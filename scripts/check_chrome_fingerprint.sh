#!/usr/bin/env bash
# Автосверка эталона Chrome-отпечатка (PLAN.md, "План дальнейших
# действий", шаг 9).
#
# Chrome меняет форму ClientHello несколько раз в год (предупреждение
# Этапа 3: "это не разовая задача, а процесс"). Профиль в
# `core/src/fingerprint/chrome_profile.rs` привязан к конкретной версии
# Chrome через utls (`HelloChrome_133` = `HelloChrome_Auto` на момент
# написания). Когда utls двигает `HelloChrome_Auto` на новую версию,
# наш профиль устаревает молча. Этот скрипт ловит такое расхождение.
#
# Что делает:
#   1. тянет u_common.go из refraction-networking/utls (только сеть —
#      raw.githubusercontent.com, ничего не собирает и не запускает);
#   2. находит, на какой профиль сейчас указывает HelloChrome_Auto;
#   3. тянет u_parrots.go и вынимает из профиля cipher suites, набор
#      расширений и signature_algorithms;
#   4. сверяет с эталоном, зашитым в этот скрипт (тем же, на который
#      опираются chrome_profile.rs и core/tests/fingerprint_chrome_full.rs),
#      и печатает расхождения.
#
# Ненулевой код возврата = эталон разошёлся, профиль пора обновлять.
# Годится для ручного запуска и для scheduled-задачи.
set -euo pipefail

RAW="https://raw.githubusercontent.com/refraction-networking/utls/master"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== сверка эталона Chrome-отпечатка с utls =="

curl -fsSL --max-time 30 "$RAW/u_common.go"  -o "$TMP/u_common.go"
curl -fsSL --max-time 30 "$RAW/u_parrots.go" -o "$TMP/u_parrots.go"

# 1. На какой профиль указывает HelloChrome_Auto.
auto="$(grep -oE 'HelloChrome_Auto[[:space:]]*=[[:space:]]*HelloChrome_[0-9A-Za-z_]+' "$TMP/u_common.go" \
        | head -n1 | sed -E 's/.*=[[:space:]]*//')"
if [[ -z "${auto:-}" ]]; then
    echo "НЕ УДАЛОСЬ найти HelloChrome_Auto в u_common.go — формат utls изменился." >&2
    exit 2
fi
echo "utls HelloChrome_Auto -> $auto"

PROFILE_IN_CODE="HelloChrome_133"
if [[ "$auto" != "$PROFILE_IN_CODE" ]]; then
    echo
    echo "!! РАСХОЖДЕНИЕ: код опирается на $PROFILE_IN_CODE, а utls уже на $auto."
    echo "   Обновить core/src/fingerprint/chrome_profile.rs под новый профиль."
    DRIFT=1
else
    echo "профиль в коде ($PROFILE_IN_CODE) совпадает с текущим HelloChrome_Auto."
    DRIFT=0
fi

# 2. Список cipher suites этого профиля: от строки `case <profile>:` до
#    следующего `case ` — вынимаем содержимое блока CipherSuites{...}.
suites="$(awk -v prof="$auto" '
    $0 ~ ("case "prof":") {inprofile=1}
    inprofile && /CipherSuites: \[\]uint16\{/ {incs=1; next}
    incs && /\},/ {incs=0; inprofile=0}
    incs {print}
' "$TMP/u_parrots.go" | grep -oE '[A-Za-z0-9_]+' | grep -vE '^$')"

if [[ -z "${suites:-}" ]]; then
    echo "НЕ УДАЛОСЬ вынуть список cipher suites профиля $auto — формат u_parrots.go изменился." >&2
    exit 2
fi

# 3. Эталон: как chrome_profile.rs описывает список Chrome — GREASE,
#    3x TLS1.3, 6x ECDHE-TLS1.2 (эти девять клиент реально предлагает),
#    затем 6 legacy TLS1.2 (RSA/CBC): клиент их не реализует и заявляет
#    только в REALITY (см. CHROME_LEGACY_SUITES в chrome_profile.rs).
#    Имена — как в utls.
read -r -d '' EXPECTED <<'EOF' || true
GREASE_PLACEHOLDER
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
EOF

echo
echo "-- cipher suites профиля $auto (сверху вниз, как в u_parrots.go) --"
diff_out="$(diff <(printf '%s\n' "$EXPECTED") <(printf '%s\n' "$suites") || true)"
if [[ -z "$diff_out" ]]; then
    echo "список cipher suites совпал с эталоном в скрипте."
else
    echo "!! СПИСОК cipher suites РАЗОШЁЛСЯ (слева — эталон, справа — utls):"
    printf '%s\n' "$diff_out"
    DRIFT=1
fi

# 4. Набор расширений и signature_algorithms. Порядок расширений Chrome
#    перемешивает на каждое соединение, поэтому сравнивается
#    отсортированный набор имён типов из utls.
block="$(awk -v prof="$auto" '
    $0 ~ ("case "prof":") {inprofile=1; next}
    inprofile && /^[[:space:]]*case Hello/ {exit}
    inprofile {print}
' "$TMP/u_parrots.go")"
exts="$(grep -oE '&[A-Za-z0-9]+\{|BoringGREASEECH\(\)' <<<"$block" \
        | sed -E 's/^&//; s/\{$//' | grep -E 'Extension|ECH' | sort)"
EXPECTED_EXTS="ALPNExtension
ApplicationSettingsExtensionNew
BoringGREASEECH()
ExtendedMasterSecretExtension
KeyShareExtension
PSKKeyExchangeModesExtension
RenegotiationInfoExtension
SCTExtension
SNIExtension
SessionTicketExtension
SignatureAlgorithmsExtension
StatusRequestExtension
SupportedCurvesExtension
SupportedPointsExtension
SupportedVersionsExtension
UtlsCompressCertExtension
UtlsGREASEExtension
UtlsGREASEExtension"
echo
echo "-- расширения профиля $auto --"
diff_out="$(diff <(sort <<<"$EXPECTED_EXTS") <(printf '%s\n' "$exts") || true)"
if [[ -z "$diff_out" ]]; then
    echo "набор расширений совпал с эталоном."
else
    echo "!! НАБОР РАСШИРЕНИЙ РАЗОШЁЛСЯ (слева — эталон, справа — utls):"
    printf '%s\n' "$diff_out"
    DRIFT=1
fi

sigalgs="$(awk '/SignatureAlgorithmsExtension\{/{f=1; next} f && /\}\},/{exit} f' <<<"$block" \
           | grep -oE '[A-Za-z0-9]+' | grep -vE '^(SupportedSignatureAlgorithms|SignatureScheme)$')"
EXPECTED_SIG="ECDSAWithP256AndSHA256
PSSWithSHA256
PKCS1WithSHA256
ECDSAWithP384AndSHA384
PSSWithSHA384
PKCS1WithSHA384
PSSWithSHA512
PKCS1WithSHA512"
echo
echo "-- signature_algorithms профиля $auto --"
diff_out="$(diff <(printf '%s\n' "$EXPECTED_SIG") <(printf '%s\n' "$sigalgs") || true)"
if [[ -z "$diff_out" ]]; then
    echo "signature_algorithms совпали с эталоном."
else
    echo "!! signature_algorithms РАЗОШЛИСЬ (слева — эталон, справа — utls):"
    printf '%s\n' "$diff_out"
    DRIFT=1
fi

echo
if [[ "$DRIFT" -ne 0 ]]; then
    echo "ИТОГ: эталон устарел — обновить chrome_profile.rs и этот скрипт."
    exit 1
fi
echo "ИТОГ: расхождений нет."
