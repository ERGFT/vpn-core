//! Крипто-примитивы клиентской части REALITY. См. предупреждения и
//! ссылки на первоисточники в `reality/mod.rs` — здесь только код.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::error::{Error, Result};

type HmacSha512 = Hmac<Sha512>;

/// Максимальная длина ShortId в открытом виде (до шифрования) — 8 байт.
/// В ссылке `sid=` кодируется hex-строкой до 16 символов (Xray-core),
/// более короткие значения дополняются нулями справа при сборке
/// plaintext-блока (см. [`RealityAuth::compute`]).
pub const SHORT_ID_LEN: usize = 8;
/// Полная длина поля TLS SessionId, которое использует REALITY.
pub const SESSION_ID_LEN: usize = 32;
/// Длина plaintext-блока перед AEAD: version(3)+reserved(1)+timestamp(4)+short_id(8).
const PLAINTEXT_LEN: usize = 16;

/// Результат подготовки клиентской аутентификации REALITY.
///
/// `session_id` — готовое содержимое поля SessionId для вставки в
/// ClientHello (см. `reality/mod.rs` — куда именно его вставить,
/// текущий код не решает, это открытый архитектурный вопрос).
/// `auth_key` нужен отдельно и позже — им проверяется HMAC-подпись
/// сертификата сервера в [`verify_ed25519_hmac`]/`verifier.rs`.
#[derive(Debug)]
pub struct RealityAuth {
    pub client_public: [u8; 32],
    pub auth_key: [u8; 32],
    pub session_id: [u8; SESSION_ID_LEN],
}

impl RealityAuth {
    /// Собрать SessionId и вывести AuthKey.
    ///
    /// # Параметры
    /// - `server_public` — статический X25519-ключ сервера (`pbk=` в
    ///   ссылке, см. `VlessConfig::reality_params`).
    /// - `short_id` — до [`SHORT_ID_LEN`] байт (`sid=`); короче —
    ///   дополняется нулями справа, как в открытом plaintext-блоке
    ///   Xray-core.
    /// - `client_hello_random` — 32 байта поля `random`, которое
    ///   реально уйдёт в ClientHello: bytes[..20] — HKDF-соль,
    ///   bytes[20..32] — nonce AES-GCM (сверено по исходникам — см.
    ///   `reality/mod.rs`).
    /// - `client_hello_raw_with_placeholder` — байты ВСЕГО
    ///   ClientHello-сообщения (handshake header + body) ровно в том
    ///   виде, в котором они уйдут на сервер, но с ещё-не-зашифрованным
    ///   содержимым SessionId на месте (т.е. до подстановки результата
    ///   этой функции) — это AAD; сервер увидит те же байты (с уже
    ///   переписанным SessionId) и сможет посчитать тот же AAD только
    ///   если сначала расшифрует поле, что и есть суть аутентификации.
    ///
    /// Возвращает эфемерный публичный ключ клиента (кладётся в TLS
    /// key_share для X25519 — обычный путь TLS 1.3, ничего
    /// REALITY-специфичного), сам SessionId и производный AuthKey.
    pub fn compute(
        server_public: &[u8; 32],
        short_id: &[u8],
        client_hello_random: &[u8; 32],
        client_hello_raw_with_placeholder: &[u8],
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<Self> {
        if short_id.len() > SHORT_ID_LEN {
            return Err(Error::Protocol(format!(
                "REALITY short_id длиннее {SHORT_ID_LEN} байт: {}",
                short_id.len()
            )));
        }

        let ephemeral = EphemeralSecret::random_from_rng(rng);
        let client_public = X25519PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(&X25519PublicKey::from(*server_public));

        let auth_key = derive_auth_key(shared.as_bytes(), client_hello_random)?;
        let plaintext = build_plaintext(short_id);

        let session_id = seal_session_id(
            &auth_key,
            client_hello_random,
            &plaintext,
            client_hello_raw_with_placeholder,
        )?;

        Ok(RealityAuth {
            client_public: client_public.to_bytes(),
            auth_key,
            session_id,
        })
    }
}

/// Версия, которую этот клиент объявляет в байтах `[0..3]`
/// plaintext-блока SessionId — три байта `[major, minor, patch]`,
/// байт-в-байт как `core.Version_x/y/z` в самом Xray-core (см. их
/// `core/core.go`). Раньше здесь стояли нули: решение было осознанным
/// ("не участник экосистемы версий Xray-core"), но проверка
/// `minClientVer`/`maxClientVer` на сервере — не гипотеза и не слух,
/// а реально существующий, активный код: см. `XTLS/reality`, `tls.go`,
/// вокруг `Value(hs.c.ClientVer[:]...) >= Value(config.MinClientVer...)`
/// (сверено напрямую по исходнику сессии этого этапа). При несовпадении
/// сервер НЕ шлёт alert — он просто не помечает соединение как REALITY
/// (`hs.c.conn` остаётся не равен `conn`) и прозрачно проксирует байты
/// на сайт прикрытия, то есть для нашего клиента это выглядит как
/// провал хендшейка без диагностики. Проверка по-прежнему опциональна
/// (`config.MinClientVer == nil` — пропускается, а это нулевое значение
/// Go для `[]byte`, то есть поведение по умолчанию, если админ явно не
/// задал `minClientVer`/`maxClientVer`) — но раз код реален и цена
/// правки — три байта, нет причин держать явно недостоверное значение.
///
/// Число НЕ синхронизировано автоматически с апстримом (никакого
/// подключения к сети Xray-core на этапе сборки — negentropy было бы
/// избыточной инженерией ради околонулевой пользы) и будет стареть по
/// мере выхода новых версий Xray-core; это сознательный компромисс, а
/// не забытая работа — см. пояснение в PLAN.md, Этап 5. Значение взято
/// по актуальной на момент этой правки ветке `main` Xray-core (`26.9.9`)
/// и означает не совместимость по функциям, а просто правдоподобное
/// число вместо `0.0.0`, которое сервер, требовательный к
/// `minClientVer`, отверг бы почти наверняка.
const CLIENT_VERSION: [u8; 3] = [26, 9, 9];

/// AuthKey = HKDF-SHA256(salt=random[..20], ikm=shared_secret,
/// info="REALITY")[..32]. Вынесено отдельной функцией, чтобы тесты
/// могли пересчитать её независимо от [`RealityAuth::compute`].
/// Собрать 16-байтный plaintext-блок (версия(3)+reserved(1)+timestamp(4)+
/// short_id(8, дополняется нулями справа) перед AEAD-печатью. Вынесено
/// отдельно, чтобы `RealityAuth::compute` (используется в тестах/спайке)
/// и `hook.rs` (используется в реальном рукопожатии через
/// `rustls::client::RealityClientHook`) не расходились в этой логике —
/// один источник истины. `short_id` длиннее [`SHORT_ID_LEN`] обрезается
/// до этой длины вызывающим кодом (см. `compute()` и `hook.rs`).
pub(crate) fn build_plaintext(short_id: &[u8]) -> [u8; PLAINTEXT_LEN] {
    let mut plaintext = [0u8; PLAINTEXT_LEN];
    // Байты [0..3] — версия ядра, которую видит проверка minClientVer/
    // maxClientVer на сервере (см. док-комментарий CLIENT_VERSION выше).
    // Байт [3] — reserved, оставляем нулём (Xray-core делает то же самое).
    plaintext[0..3].copy_from_slice(&CLIENT_VERSION);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    plaintext[4..8].copy_from_slice(&now.to_be_bytes());
    let n = short_id.len().min(SHORT_ID_LEN);
    plaintext[8..8 + n].copy_from_slice(&short_id[..n]);
    plaintext
}

pub(crate) fn derive_auth_key(
    shared_secret: &[u8],
    client_hello_random: &[u8; 32],
) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&client_hello_random[..20]), shared_secret);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .map_err(|_| Error::Protocol("HKDF expand для AuthKey не удался".into()))?;
    Ok(auth_key)
}

/// AES-256-GCM(key=auth_key).Seal(nonce=random[20..32], plaintext,
/// aad=client_hello_raw) — 16 байт plaintext + 16-байтный тег GCM дают
/// ровно [`SESSION_ID_LEN`] байт результата, заполняя всё поле целиком
/// (никакой части ShortId "в открытом виде" на проводе не остаётся —
/// это резолвит неоднозначность между источниками, которая была на
/// этапе исследования: plaintext-блок с ShortId — 16 байт, а не 24).
pub(crate) fn seal_session_id(
    auth_key: &[u8; 32],
    client_hello_random: &[u8; 32],
    plaintext: &[u8; PLAINTEXT_LEN],
    aad: &[u8],
) -> Result<[u8; SESSION_ID_LEN]> {
    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|_| Error::Protocol("некорректная длина AuthKey для AES-256-GCM".into()))?;
    let nonce = Nonce::from_slice(&client_hello_random[20..32]);
    let sealed = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Protocol("AES-256-GCM seal для REALITY SessionId не удался".into()))?;

    if sealed.len() != SESSION_ID_LEN {
        return Err(Error::Protocol(format!(
            "неожиданная длина зашифрованного SessionId: {} (ожидалось {SESSION_ID_LEN})",
            sealed.len()
        )));
    }
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&sealed);
    Ok(session_id)
}

/// Обратная операция — расшифровать SessionId обратно в plaintext-блок
/// (версия/timestamp/short_id). Клиенту эта функция не нужна в бою (её
/// делает сервер), но она нужна тестам: собрать `session_id` через
/// `compute()`, а расшифровать — независимым путём, не переиспользуя
/// внутренний код `compute()`, иначе тест лишь подтвердит, что функция
/// не падает, а не что она шифрует то, что нужно.
#[cfg(test)]
fn open_session_id(
    auth_key: &[u8; 32],
    client_hello_random: &[u8; 32],
    session_id: &[u8; SESSION_ID_LEN],
    aad: &[u8],
) -> Result<[u8; PLAINTEXT_LEN]> {
    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|_| Error::Protocol("некорректная длина AuthKey для AES-256-GCM".into()))?;
    let nonce = Nonce::from_slice(&client_hello_random[20..32]);
    let opened = cipher
        .decrypt(
            nonce,
            Payload {
                msg: session_id,
                aad,
            },
        )
        .map_err(|_| Error::Protocol("AES-256-GCM open для REALITY SessionId не удался".into()))?;
    let mut plaintext = [0u8; PLAINTEXT_LEN];
    plaintext.copy_from_slice(&opened);
    Ok(plaintext)
}

/// Проверка серверного сертификата в модели доверия REALITY: вместо
/// цепочки X.509 сверяем HMAC-SHA512(AuthKey, peer_ed25519_pubkey) ==
/// подпись сертификата. См. `verifier.rs`, где это используется в
/// реализации `rustls::client::danger::ServerCertVerifier`.
pub fn verify_ed25519_hmac(auth_key: &[u8; 32], peer_pubkey: &[u8], signature: &[u8]) -> bool {
    let mut mac = match <HmacSha512 as Mac>::new_from_slice(auth_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(peer_pubkey);
    mac.verify_slice(signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 §6.1 — официальный тестовый вектор X25519 (Alice/Bob).
    /// Перепроверен самостоятельно через Python `cryptography` перед
    /// тем, как попасть сюда (значения из RFC при первом чтении
    /// выглядели длиннее ожидаемых 32 байт — оказалось, это не ошибка
    /// транскрипции, а верная длина; подтверждено вычислением: сначала
    /// self-consistency, alice_priv -> alice_pub и bob_priv -> bob_pub,
    /// затем shared_a == shared_b == K).
    #[test]
    fn x25519_matches_rfc7748_vector() {
        let alice_priv: [u8; 32] =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let alice_pub_expected =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let bob_priv: [u8; 32] =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_pub_expected =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap();
        let k_expected =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap();

        // x25519-dalek's StaticSecret не даёт "чистый" X25519(k, u) —
        // оборачивает в свою модель ключей, что и нужно: те же клэмпинг
        // и base-point umul, что описывает сам RFC 7748.
        let alice_static = x25519_dalek::StaticSecret::from(alice_priv);
        let bob_static = x25519_dalek::StaticSecret::from(bob_priv);
        let alice_pub = x25519_dalek::PublicKey::from(&alice_static);
        let bob_pub = x25519_dalek::PublicKey::from(&bob_static);

        assert_eq!(
            alice_pub.as_bytes().as_slice(),
            alice_pub_expected.as_slice()
        );
        assert_eq!(bob_pub.as_bytes().as_slice(), bob_pub_expected.as_slice());

        let shared_a = alice_static.diffie_hellman(&bob_pub);
        let shared_b = bob_static.diffie_hellman(&alice_pub);
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
        assert_eq!(shared_a.as_bytes().as_slice(), k_expected.as_slice());
    }

    #[test]
    fn seal_open_roundtrip_recovers_plaintext_fields() {
        let server_public = [7u8; 32];
        let short_id = [0xaa, 0xbb, 0xcc, 0xdd];
        let client_hello_random = [0x11u8; 32];
        // Синтетический "ClientHello" — для теста важно только то, что
        // Seal/Open используют один и тот же AAD, не его реальная
        // TLS-структура.
        let fake_client_hello = b"\x01\x00\x00\x2a fake-client-hello-bytes-aad";

        let mut rng = rand::rngs::OsRng;
        let server_static = x25519_dalek::StaticSecret::random_from_rng(rng);
        let server_public_key = x25519_dalek::PublicKey::from(&server_static);

        let auth = RealityAuth::compute(
            server_public_key.as_bytes(),
            &short_id,
            &client_hello_random,
            fake_client_hello,
            &mut rng,
        )
        .unwrap();
        let _ = server_public; // не используется напрямую — сервер сгенерирован рядом

        // Сервер: получив client_public (в реальном ClientHello — в
        // key_share) и зная свой server_static, выводит тот же
        // shared/AuthKey независимо от клиентского RealityAuth::compute.
        let server_shared =
            server_static.diffie_hellman(&x25519_dalek::PublicKey::from(auth.client_public));
        let server_auth_key =
            derive_auth_key(server_shared.as_bytes(), &client_hello_random).unwrap();
        assert_eq!(
            server_auth_key, auth.auth_key,
            "AuthKey должен совпасть на обеих сторонах ECDH"
        );

        let opened = open_session_id(
            &server_auth_key,
            &client_hello_random,
            &auth.session_id,
            fake_client_hello,
        )
        .unwrap();

        let recovered_ts = u32::from_be_bytes(opened[4..8].try_into().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        // Сравнение с допуском в пару секунд, а не точное равенство —
        // `compute()` и эта проверка читают системные часы в разные
        // моменты теста, отличие на 1 секунду на границе не баг.
        assert!(
            now.saturating_sub(recovered_ts) <= 2,
            "восстановленный timestamp должен быть примерно текущим unix-временем, получено {recovered_ts}, сейчас {now}"
        );
        assert_eq!(
            &opened[8..12],
            &short_id,
            "восстановленный short_id должен совпасть с исходным"
        );
        assert_eq!(
            &opened[12..16],
            &[0, 0, 0, 0],
            "хвост short_id-поля должен быть нулевым паддингом"
        );
    }

    #[test]
    fn seal_open_fails_with_wrong_aad() {
        let mut rng = rand::rngs::OsRng;
        let server_static = x25519_dalek::StaticSecret::random_from_rng(rng);
        let server_public_key = x25519_dalek::PublicKey::from(&server_static);
        let client_hello_random = [0x22u8; 32];
        let real_aad = b"correct-aad-bytes";
        let wrong_aad = b"tampered-aad-bytes";

        let auth = RealityAuth::compute(
            server_public_key.as_bytes(),
            &[],
            &client_hello_random,
            real_aad,
            &mut rng,
        )
        .unwrap();

        let server_shared =
            server_static.diffie_hellman(&x25519_dalek::PublicKey::from(auth.client_public));
        let server_auth_key =
            derive_auth_key(server_shared.as_bytes(), &client_hello_random).unwrap();

        let result = open_session_id(
            &server_auth_key,
            &client_hello_random,
            &auth.session_id,
            wrong_aad,
        );
        assert!(
            result.is_err(),
            "AEAD должен отвергать SessionId при несовпадении AAD (защита от подмены остального ClientHello)"
        );
    }

    #[test]
    fn hmac_verify_accepts_correct_and_rejects_wrong_key_or_signature() {
        let auth_key = [3u8; 32];
        let wrong_key = [4u8; 32];
        let peer_pubkey = [9u8; 32];

        let mut mac = <HmacSha512 as Mac>::new_from_slice(&auth_key).unwrap();
        mac.update(&peer_pubkey);
        let correct_signature = mac.finalize().into_bytes();

        assert!(verify_ed25519_hmac(
            &auth_key,
            &peer_pubkey,
            &correct_signature
        ));
        assert!(!verify_ed25519_hmac(
            &wrong_key,
            &peer_pubkey,
            &correct_signature
        ));

        let mut tampered_signature = correct_signature.to_vec();
        tampered_signature[0] ^= 0xff;
        assert!(!verify_ed25519_hmac(
            &auth_key,
            &peer_pubkey,
            &tampered_signature
        ));

        assert!(!verify_ed25519_hmac(&auth_key, &peer_pubkey, &[]));
    }

    #[test]
    fn build_plaintext_declares_nonzero_client_version() {
        // Регрессия против находки minClientVer/maxClientVer (см.
        // док-комментарий CLIENT_VERSION): раньше здесь стояли нули, что
        // реальный, активный код сервера в XTLS/reality (`tls.go`)
        // трактовал бы как версию `0.0.0` и мог отвергнуть при явно
        // заданном `minClientVer`. Байты [3] (reserved) по-прежнему
        // нулевые — так делает и сам Xray-core.
        let plaintext = build_plaintext(&[1, 2, 3, 4]);
        assert_eq!(
            &plaintext[0..3],
            &CLIENT_VERSION,
            "версия в SessionId должна быть той, что объявлена в CLIENT_VERSION, не нулевой"
        );
        assert_eq!(plaintext[3], 0, "байт reserved должен оставаться нулевым");
    }

    #[test]
    fn compute_rejects_short_id_longer_than_8_bytes() {
        let mut rng = rand::rngs::OsRng;
        let too_long = [0u8; SHORT_ID_LEN + 1];
        let err =
            RealityAuth::compute(&[1u8; 32], &too_long, &[0u8; 32], b"aad", &mut rng).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }
}
