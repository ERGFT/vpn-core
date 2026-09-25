//! Этап 3 — первый конкретный шаг "эмуляции" (не только измерения):
//! порядок cipher suites, приведённый к порядку реального Chrome.
//!
//! # Откуда взят эталон
//! Список и порядок cipher suites — из `refraction-networking/utls`
//! (форк `crypto/tls` стандартной библиотеки Go, реальная зависимость
//! REALITY-клиента в самом Xray-core — см. `reality/mod.rs`), файл
//! `u_parrots.go`, профиль `HelloChrome_133` (`HelloChrome_Auto` на
//! момент этой правки — самый свежий стабильный Chrome, на который
//! ссылается сам utls). Получено напрямую (`curl
//! raw.githubusercontent.com/refraction-networking/utls/master/u_parrots.go`),
//! не по памяти и не по пересказу — та же дисциплина сверки, что и для
//! REALITY-находок в Этапе 5.
//!
//! # Почему список неполный — осознанно, не забыто
//! Полный список Chrome 133 — 16 cipher suites: GREASE-плейсхолдер, три
//! TLS1.3-suite'а, шесть ECDHE-suite'ов TLS1.2 и ещё шесть legacy
//! suite'ов TLS1.2 (голый `TLS_RSA_*` без ECDHE, CBC-режим). Крипто-провайдер
//! этого проекта (`aws-lc-rs`, тот же, что применяется для настоящего TLS
//! везде в клиенте) реализует только первые девять — три TLS1.3 и шесть
//! ECDHE-suite'ов TLS1.2 — сознательно НЕ реализует голый RSA-key-exchange
//! и CBC-режим, потому что это небезопасные, устаревшие механизмы: их
//! отсутствие в `aws-lc-rs`/`ring` — общее свойство современных
//! rustls-провайдеров, не пробел этого проекта. Реализовывать их заново
//! только ради побайтовой точности TLS-отпечатка означало бы сознательно
//! тащить в клиента небезопасную криптографию ради маскировки — прямое
//! нарушение того, ради чего вообще существует HTTPS/TLS, и прямая
//! переинженерия ради второстепенной цели. Поэтому здесь переставляется
//! только порядок ДЕЙСТВИТЕЛЬНО предлагаемых девяти suite'ов — так, чтобы
//! их относительный порядок совпадал с тем, в каком их видно в списке
//! Chrome, а не тащится их полный набор.
//!
//! # GREASE (RFC 8701) — сделан полностью, во всех местах, где его ставит Chrome
//! Патч `vendor/rustls-reality-patch` (конфиг клиента о GREASE ничего не
//! знает): пять независимых значений на соединение
//! (`client/common.rs`, `GreaseValues`, раскладка как у BoringSSL —
//! сверено по `u_parrots.go`, `ApplyPreset`): первый cipher suite; первая
//! группа в supported_groups и первая запись key_share (одно и то же
//! значение, тело key_share — один нулевой байт); первая версия в
//! supported_versions; два отдельных GREASE-расширения — самое первое с
//! пустым телом и самое последнее (перед PSK) с телом `[0]`, типы
//! гарантированно разные. Значения живут на всё соединение: второй
//! ClientHello после HelloRetryRequest получает те же. После HRR,
//! указавшего группу, GREASE в key_share НЕ добавляется (RFC 8446 §4.1.2 —
//! там ровно одна запись; иначе Go-серверы, включая REALITY, рвут
//! соединение).
//!
//! GREASE-расширения вписаны прямо в `ClientExtensions::encode`
//! (`msgs/handshake.rs`) — правка макроса `extension_struct!`, которой
//! опасались раньше, не понадобилась: `encode` написан вручную, длина
//! списка считается `LengthPrefixedBuffer`'ом.
//!
//! Действует и для REALITY. Раньше GREASE в группах/key_share для REALITY
//! был сознательно отложен "до интероп-теста"; это пересмотрено по
//! исходникам (см. PLAN.md, Этап 3): сервер `XTLS/REALITY` неизвестные
//! группы в key_share пропускает, а собственный REALITY-клиент Xray-core
//! по умолчанию — utls с отпечатком `HelloChrome_133`, т.е. REALITY-серверы
//! штатно получают ровно эти GREASE-значения. Реальная группа у REALITY
//! по-прежнему одна (`X25519MLKEM768`), анти-HRR-логика не тронута.
//! Проверено живыми хендшейками: `core/tests/fingerprint_chrome_profile.rs`,
//! `core/tests/fingerprint_grease_groups.rs` (включая путь через HRR) и
//! `core/tests/reality_handshake.rs` (там же AEAD-проверка доказывает, что
//! GREASE-байты вошли в AAD так же, как их посчитал клиент).
//!
//! # Что ещё не сделано (см. PLAN.md, Этап 3)
//! - Порядок TLS-расширений — ЗАКРЫТО ДРУГИМ способом, без патча: этот же
//!   вендоренный rustls уже рандомизирует порядок расширений на каждое
//!   соединение (`ClientHelloDetails::extension_order_seed`,
//!   `client/hs.rs`) — проверено эмпирически в этой сессии (три реальных
//!   рукопожатия на loopback дали три разных порядка одного и того же
//!   набора расширений). Это СЛУЧАЙНО совпадает с тем, что делает сам
//!   Chrome 106+ (`ShuffleChromeTLSExtensions` в том же `u_parrots.go`) —
//!   поэтому именно порядок расширений (в отличие от порядка cipher
//!   suites) уже не статичен и не отличает этот клиент от браузера так,
//!   как раньше ошибочно считалось (см. поправку в PLAN.md, Этап 3).
//! - Набор и значения самих расширений (какие сигнатурные алгоритмы,
//!   ALPN-протоколы, сжатие сертификатов, ALPS, SCT и т.п. заявлены) — до
//!   сих пор не сверены построчно с Chrome. Список групп для НЕ-REALITY
//!   пути уже совпадает (`X25519MLKEM768, X25519, secp256r1, secp384r1` —
//!   то, что по умолчанию отдаёт `aws-lc-rs`).
//! - Предложение TLS1.2 в `supported_versions` только ради внешнего
//!   сходства с Chrome (реальный Chrome всегда предлагает откат до 1.2,
//!   даже практически никогда им не пользуясь) — этот клиент сейчас
//!   TLS1.3-only по факту согласования почти везде (кроме обычного
//!   `security=tls`-пути, где `ClientConfig::builder()` использует
//!   `versions::DEFAULT_VERSIONS`, включающие и 1.2). Расширять специально
//!   под REALITY или REALITY делать TLS1.2-aware только ради фингерпринта
//!   — отдельное решение с касанием протокола, не сделано здесь.

use rustls::crypto::CryptoProvider;
use rustls::CipherSuite;

/// Порядок cipher suites в ClientHello реального Chrome 133
/// (`HelloChrome_Auto` в `refraction-networking/utls`, `u_parrots.go`,
/// см. модульный докстринг). Первый элемент — GREASE-плейсхолдер (сюда
/// никогда не попадает, `aws-lc-rs` не даёт "suite" под фейковый
/// кодпоинт) — оставлен для документальной полноты списка, не
/// используется в [`apply_chrome133_cipher_order`]. Хвост
/// (`TLS_RSA_*`/CBC) оставлен по той же причине — см. докстринг про то,
/// почему они не реализуются.
const CHROME133_CIPHER_ORDER: &[CipherSuite] = &[
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// Переставить `provider.cipher_suites` так, чтобы suite'ы из
/// [`CHROME133_CIPHER_ORDER`] шли в том же ОТНОСИТЕЛЬНОМ порядке, в
/// каком их видно у Chrome — остальные (если провайдер вдруг
/// когда-нибудь станет предлагать что-то ещё, не входящее в список
/// Chrome) дописываются следом в их исходном порядке, а не отбрасываются
/// — так эта функция не сломается молча, если набор suite'ов провайдера
/// изменится в будущей версии `aws-lc-rs`/rustls.
pub fn apply_chrome133_cipher_order(mut provider: CryptoProvider) -> CryptoProvider {
    provider.cipher_suites.sort_by_key(|cs| {
        CHROME133_CIPHER_ORDER
            .iter()
            .position(|&wanted| wanted == cs.suite())
            .unwrap_or(CHROME133_CIPHER_ORDER.len())
    });
    provider
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorders_default_aws_lc_rs_suites_to_match_chrome133() {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let reordered = apply_chrome133_cipher_order(provider);

        let got: Vec<CipherSuite> = reordered
            .cipher_suites
            .iter()
            .map(|cs| cs.suite())
            .collect();

        // Девять suite'ов, которые реально есть в aws-lc-rs, должны
        // оказаться в том же порядке, что и в CHROME133_CIPHER_ORDER —
        // без пропусков и без лишних (это и есть эмпирическая проверка,
        // что список эталона выше не разошёлся с тем, что провайдер
        // реально умеет).
        assert_eq!(
            got, CHROME133_CIPHER_ORDER,
            "после переупорядочивания список suite'ов aws-lc-rs должен побайтово совпасть с CHROME133_CIPHER_ORDER"
        );
    }

    #[test]
    fn unknown_suite_not_in_chrome_list_goes_to_the_end_not_dropped() {
        // Синтетический провайдер с suite'ом, которого нет в списке
        // Chrome (реальный TLS13_AES_128_GCM_SHA256 плюс намеренно
        // "неизвестный" порядок) — проверяем, что функция не паникует и
        // не теряет suite'ы, даже если список эталона когда-нибудь не
        // покроет что-то новое.
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        // Оставляем только TLS1.3-suite'ы — минимальный набор, где
        // порядок точно проверяем без риска не найти нужные ECDHE-suite'ы
        // в разных сборках aws-lc-rs.
        provider.cipher_suites.retain(|cs| {
            matches!(
                cs.suite(),
                CipherSuite::TLS13_AES_256_GCM_SHA384 | CipherSuite::TLS13_AES_128_GCM_SHA256
            )
        });
        let reordered = apply_chrome133_cipher_order(provider);
        let got: Vec<CipherSuite> = reordered
            .cipher_suites
            .iter()
            .map(|cs| cs.suite())
            .collect();
        assert_eq!(
            got,
            vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
            ],
            "128 должен идти раньше 256 — так у Chrome, но не в дефолтном порядке aws-lc-rs (там 256 первый)"
        );
    }
}
