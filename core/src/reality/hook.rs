// SPDX-License-Identifier: GPL-3.0-or-later
//! Реализация `rustls::client::RealityClientHook` — то самое место, где
//! REALITY реально подключается к настоящему TLS-рукопожатию, а не
//! только проверен в отрыве от него.
//!
//! # Почему не старый `reality_session_id_spike.rs`
//! Первая проверка (Этап 5, спайк через `ClientSessionStore` с фейковой
//! TLS1.2-сессией) доказала, что патченный rustls МОЖЕТ доставить
//! произвольный SessionId на провод — но оказалась архитектурно не тем
//! механизмом для полного REALITY: `ClientSessionStore::tls12_session()`
//! вызывается ДО того, как rustls генерирует `ClientHello.random`
//! (сверено построчно по `client/hs.rs`: `ClientSessionValue::retrieve`
//! в начале `ClientHelloInput::new()`, `random: Random::new(...)` —
//! позже, в конце той же функции), а AuthKey и nonce AES-GCM зависят
//! именно от `random`. Плюс аутентификация REALITY требует переиспользовать
//! ОДИН И ТОТ ЖЕ эфемерный X25519-секрет дважды: для ECDH с
//! REALITY-сервером (AuthKey) и позже для настоящего TLS1.3 ECDH с
//! сервером, чьё имя стоит в SNI — `ClientSessionStore` вообще не
//! участвует в выборе ключей.
//!
//! Поэтому реальный путь — новый, точечный хук в самом
//! `vendor/rustls-reality-patch` (`client::RealityClientHook`,
//! `ClientConfig::reality`), который патчит `emit_client_hello_for_retry`
//! напрямую: подменяет key_share на наш и, уже зная настоящий
//! `ClientHello.random`, на месте шифрует SessionId с AAD = байты САМОГО
//! этого ClientHello (см. `client/hs.rs` в патче за подробным
//! построчным обоснованием и сверкой с `reality.go` из Xray-core).
//! Старый спайк-тест оставлен как есть (проходит, полезен как
//! независимое доказательство первого шага), но в бою не используется.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use ml_kem::kem::{Decapsulate, Kem, KeyExport};
use ml_kem::{DecapsulationKey768, MlKem768};
use rustls::client::RealityClientHook;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::auth::{
    build_plaintext, derive_auth_key, seal_session_id as aead_seal_session_id, SHORT_ID_LEN,
};

/// FIPS 203, ML-KEM-768: размер encapsulation key (публичный ключ,
/// уходит в наш key_share) и ciphertext (приходит в key_share сервера).
/// Не берём константы из самого крейта `ml_kem` напрямую в сигнатурах
/// (`ml_kem::EncapsulationKeySize768`/`CiphertextSize768` — это
/// type-level числа `typenum`, а не `usize`) — здесь достаточно простых
/// констант для проверки длины входящих байт с провода. Сверено вручную
/// против `crypto/mlkem` из стандартной библиотеки Go (см. PLAN.md,
/// Этап 5) и рантайм-проверкой в собственном пробном крейте перед тем,
/// как попасть сюда.
const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// Полный key_share сервера для группы X25519MLKEM768: ciphertext(1088)
/// + X25519-ключ сервера(32).
const HYBRID_SERVER_SHARE_LEN: usize = MLKEM768_CIPHERTEXT_LEN + 32;

/// Одно REALITY-рукопожатие = один `RealityHook`. Эфемерный X25519-ключ
/// генерируется в [`RealityHook::new`] и живёт ровно до конца этого
/// TLS-соединения (пересоздавать на каждый `connect()`, никогда не
/// переиспользовать между соединениями — иначе теряется свойство "разные
/// соединения выглядят как разные случайные ClientHello").
pub struct RealityHook {
    /// `StaticSecret`, а не `EphemeralSecret` — намеренно: тот же скаляр
    /// используется ДВАЖДЫ (`shared_secret` ниже — ECDH с
    /// REALITY-сервером для AuthKey, и позже `complete_real_ecdh` — ECDH
    /// с настоящим сервером из ServerHello). `EphemeralSecret` в
    /// x25519-dalek специально не даёт этого сделать (consuming API) —
    /// здесь это не защита от бага, а именно то, что нужно протоколу.
    ephemeral: StaticSecret,
    client_public: [u8; 32],
    /// ECDH(ephemeral, server_public) — сырой (без HKDF) общий секрет с
    /// REALITY-сервером. HKDF (соль = `client_hello_random[..20]`)
    /// считается позже, в `seal_session_id`, когда random уже известен.
    ///
    /// `Zeroizing<..>`, не голый массив: без него значение просто
    /// освобождается вместе с остальной памятью `RealityHook`, оставляя
    /// сырые байты секрета в уже несвободной памяти процесса до
    /// следующей перезаписи этой страницы — тихий риск того же рода,
    /// от которого предостерегает PLAN.md (Этап 2: "крипто-ошибки не
    /// прощают"). `x25519-dalek` с feature `zeroize` уже делает это для
    /// `ephemeral`/`SharedSecret` сам — здесь то же самое для поля,
    /// которое мы храним как обычный `[u8; 32]`.
    shared_secret: Zeroizing<[u8; 32]>,
    short_id: Vec<u8>,
    /// AuthKey — известен только после `seal_session_id` (нужен
    /// `client_hello_random`, который приходит вместе с этим вызовом).
    /// `RealityCertVerifier::from_hook` читает его позже, при проверке
    /// сертификата сервера — TLS-рукопожатие гарантирует, что ClientHello
    /// (и значит `seal_session_id`) уходит раньше, чем приходит
    /// Certificate от сервера, так что к моменту чтения он уже есть.
    /// Тоже `Zeroizing<..>` — см. `shared_secret` за обоснованием.
    auth_key: OnceLock<Zeroizing<[u8; 32]>>,
    /// ML-KEM-768 decapsulation key этого рукопожатия — нужен позже, в
    /// `complete_real_ecdh`, чтобы раскрыть ML-KEM-часть key_share
    /// сервера. `zeroize`-feature `ml_kem` даёт этому типу
    /// `ZeroizeOnDrop` сам (см. Cargo.toml) — как и `ephemeral` выше,
    /// никакого ручного кода здесь не нужно.
    mlkem_decap: DecapsulationKey768,
    /// Кэш гибридного key_share (ML-KEM768 encapsulation key || X25519
    /// публичный ключ, 1216 байт) — считается один раз в [`RealityHook::new`],
    /// чтобы `client_hybrid_key_share()` не пересчитывал его на каждый
    /// вызов (rustls-патч всё равно кэширует у себя, но так проще
    /// рассуждать о том, где именно лежит единственная копия).
    hybrid_key_share: Vec<u8>,
    /// Отправленный ClientHello целиком (Handshake-сообщение с
    /// заголовком, уже с запечатанным SessionId) и полученный ServerHello
    /// — нужны только для проверки подписи ML-DSA-65 (`pqv=`): сервер
    /// подписывает HMAC(AuthKey; ключ сертификата || ClientHello ||
    /// ServerHello), как `VerifyPeerCertificate` в Xray-core.
    client_hello_raw: OnceLock<Vec<u8>>,
    server_hello_raw: OnceLock<Vec<u8>>,
    /// Сервер прошёл проверку REALITY (HMAC сертификата и, если задан
    /// `pqv=`, ML-DSA-65). Ставит только `RealityCertVerifier`; пока
    /// флаг не стоит, по соединению нельзя отправлять ничего, кроме
    /// «браузерных» запросов (см. `transport::tcp_tls`).
    verified: AtomicBool,
    /// `pbk=` оказался точкой малого порядка: общий секрет X25519 — нули,
    /// AuthKey вычислим кем угодно. Такой хук не пройдёт проверку никогда.
    degenerate: bool,
}

impl fmt::Debug for RealityHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Намеренно не печатаем ни `ephemeral`, ни `shared_secret` — это
        // ключевой материал, не отладочная информация.
        f.debug_struct("RealityHook")
            .field("client_public", &hex::encode(self.client_public))
            .finish_non_exhaustive()
    }
}

impl RealityHook {
    /// `server_public` — статический X25519-ключ REALITY-сервера (`pbk=`
    /// в ссылке). `short_id` — до [`SHORT_ID_LEN`] байт (`sid=`); длиннее
    /// — молча обрезается до этой длины (симметрично с
    /// `RealityAuth::compute`, которая вместо этого возвращает ошибку;
    /// здесь ошибка неуместна, так как хук конструируется один раз при
    /// сборке конфига, а не на каждое рукопожатие — валидацию длины
    /// `short_id` стоит делать раньше, при разборе ссылки, а не здесь).
    pub fn new(
        server_public: &[u8; 32],
        short_id: &[u8],
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Self {
        let ephemeral = StaticSecret::random_from_rng(rng);
        let client_public = X25519PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(&X25519PublicKey::from(*server_public));

        // ML-KEM-768: своя пара ключей, никак не пересекается с
        // X25519-скаляром выше — REALITY-аутентификация (AuthKey, ниже
        // по файлу) как была, так и остаётся чистым X25519 ECDH с
        // REALITY-сервером. Гибрид нужен только для НАСТОЯЩЕГО
        // TLS1.3-обмена ключами, который видит сам сервер (см. doc-
        // комментарий `RealityClientHook` в rustls-патче и PLAN.md,
        // Этап 5). `generate_keypair()` — с feature "getrandom" крейта
        // `ml_kem`, берёт случайность из ОС напрямую, не через `rng`
        // выше: `ml_kem` требует rand_core 0.10, а `rng` здесь —
        // rand_core 0.6 (через `rand` 0.8) — версии несовместимы на
        // уровне трейтов, см. обоснование в корневом Cargo.toml.
        let (mlkem_decap, mlkem_encap) = MlKem768::generate_keypair();
        let mut hybrid_key_share = Vec::with_capacity(MLKEM768_ENCAPSULATION_KEY_LEN + 32);
        hybrid_key_share.extend_from_slice(mlkem_encap.to_bytes().as_slice());
        hybrid_key_share.extend_from_slice(&client_public.to_bytes());
        debug_assert_eq!(hybrid_key_share.len(), MLKEM768_ENCAPSULATION_KEY_LEN + 32);

        Self {
            ephemeral,
            client_public: client_public.to_bytes(),
            shared_secret: Zeroizing::new(*shared.as_bytes()),
            short_id: short_id[..short_id.len().min(SHORT_ID_LEN)].to_vec(),
            auth_key: OnceLock::new(),
            mlkem_decap,
            hybrid_key_share,
            client_hello_raw: OnceLock::new(),
            server_hello_raw: OnceLock::new(),
            verified: AtomicBool::new(false),
            degenerate: !shared.was_contributory(),
        }
    }

    /// Ключ сервера `pbk=` вырожденный (точка малого порядка X25519) —
    /// с ним REALITY-аутентификация ничего не доказывает.
    pub fn is_degenerate(&self) -> bool {
        self.degenerate
    }

    /// Отметить, что сервер прошёл проверку REALITY.
    pub fn mark_verified(&self) {
        self.verified.store(true, Ordering::SeqCst);
    }

    /// Прошёл ли сервер проверку REALITY в этом рукопожатии.
    pub fn is_verified(&self) -> bool {
        self.verified.load(Ordering::SeqCst)
    }

    /// AuthKey этого рукопожатия — `None` до тех пор, пока ClientHello ещё
    /// не отправлен (`seal_session_id` не вызывался). Нужен
    /// [`crate::reality::RealityCertVerifier::from_hook`], чтобы проверить
    /// подпись сертификата сервера тем же ключом, что защищает SessionId.
    /// Возвращает копию (`[u8; 32]` — обычный, не `Zeroizing`): вызывающая
    /// сторона (`RealityCertVerifier`) использует его сразу же и коротко
    /// живущей локальной переменной, разумный компромисс, не пытаемся
    /// протащить `Zeroizing` через весь стек вызовов ради одного чтения.
    pub fn auth_key(&self) -> Option<[u8; 32]> {
        self.auth_key.get().map(|k| **k)
    }

    /// Отправленный ClientHello (см. поле `client_hello_raw`).
    pub fn client_hello_raw(&self) -> Option<&[u8]> {
        self.client_hello_raw.get().map(Vec::as_slice)
    }

    /// Полученный ServerHello (см. поле `server_hello_raw`).
    pub fn server_hello_raw(&self) -> Option<&[u8]> {
        self.server_hello_raw.get().map(Vec::as_slice)
    }
}

/// Смещение SessionId в Handshake-сообщении ClientHello: тип(1) +
/// длина(3) + версия(2) + random(32) + длина SessionId(1) — то самое
/// `hello.Raw[39:]` из `reality.go`.
const SESSION_ID_OFFSET: usize = 39;

impl RealityClientHook for RealityHook {
    fn client_hybrid_key_share(&self) -> Vec<u8> {
        self.hybrid_key_share.clone()
    }

    fn seal_session_id(&self, client_hello_random: &[u8; 32], aad: &[u8]) -> [u8; 32] {
        // derive_auth_key/seal_session_id по построению не могут
        // провалиться на наших фиксированных длинах (32-байтный
        // auth_key, 16-байтный plaintext) — см. их же документацию в
        // auth.rs; `expect` тут — это утверждение об инварианте, а не
        // "не думал про обработку ошибок". Сам трейт-метод объявлен без
        // Result: это вызывается из середины сборки ClientHello в
        // rustls, где заворачивать в Result было бы правкой сигнатуры
        // ради ветки, которая никогда не сработает.
        let auth_key = Zeroizing::new(
            derive_auth_key(&*self.shared_secret, client_hello_random)
                .expect("HKDF-SHA256 с 32-байтным выводом не может провалиться"),
        );
        // Игнорируем повторную установку: rustls вызывает этот метод
        // ровно один раз на исходный ClientHello (см. `retryreq.is_none()`
        // в патче), но даже если бы вызвал дважды — значение одно и то
        // же для одного и того же хука.
        let _ = self.auth_key.set(Zeroizing::new(*auth_key));
        let plaintext = build_plaintext(&self.short_id);
        let sealed = aead_seal_session_id(&auth_key, client_hello_random, &plaintext, aad)
            .expect("AES-256-GCM seal 16 байт корректным 32-байтным ключом не может провалиться");
        // Итоговый ClientHello = AAD с запечатанным SessionId на своём месте.
        if aad.len() >= SESSION_ID_OFFSET + 32 {
            let mut raw = aad.to_vec();
            raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].copy_from_slice(&sealed);
            let _ = self.client_hello_raw.set(raw);
        }
        sealed
    }

    fn complete_x25519(&self, peer_key_share: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        // Сайт-приманка без ML-KEM выбрал голый X25519: обычный ECDH тем
        // же эфемерным ключом, что и X25519-часть гибридной доли.
        let peer: [u8; 32] = peer_key_share.try_into().map_err(|_| {
            rustls::Error::General(format!(
                "REALITY: X25519-ключ сервера должен быть 32 байта, получено {}",
                peer_key_share.len()
            ))
        })?;
        let shared = self.ephemeral.diffie_hellman(&X25519PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(rustls::Error::General(
                "REALITY: вырожденный X25519-ключ сервера".into(),
            ));
        }
        Ok(shared.as_bytes().to_vec())
    }

    fn server_hello_received(&self, raw: &[u8]) {
        let _ = self.server_hello_raw.set(raw.to_vec());
    }

    fn complete_real_ecdh(&self, peer_key_share: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        // Полный key_share сервера для X25519MLKEM768: ML-KEM768
        // ciphertext(1088) || X25519-ключ сервера(32) = 1120 байт. Тот же
        // порядок, что и у нас в `hybrid_key_share` (ML-KEM первым) — по
        // `draft-ietf-tls-ecdhe-mlkem-02` §4.1 он одинаков для клиента и
        // сервера при этой группе (в отличие от SecP256r1MLKEM768, где
        // порядок обратный — но мы её не используем).
        if peer_key_share.len() != HYBRID_SERVER_SHARE_LEN {
            return Err(rustls::Error::General(format!(
                "REALITY: ожидался key_share сервера длиной {HYBRID_SERVER_SHARE_LEN} байт \
                 (ML-KEM768 ciphertext + X25519), получено {} байт",
                peer_key_share.len()
            )));
        }
        let (mlkem_ct_bytes, server_x25519_bytes) =
            peer_key_share.split_at(MLKEM768_CIPHERTEXT_LEN);

        let mlkem_ct = ml_kem::ml_kem_768::Ciphertext::try_from(mlkem_ct_bytes).map_err(|_| {
            rustls::Error::General(
                "REALITY: некорректный формат ML-KEM768 ciphertext сервера".into(),
            )
        })?;
        // `decapsulate()` возвращает `ml_kem::SharedKey` — обёртку
        // крейта `hybrid-array` вокруг `[u8; 32]`, не гарантированно
        // стирающую себя при Drop (`ml_kem`'s feature "zeroize" стирает
        // `DecapsulationKey`, но не обязательно транзитивно этот тип —
        // не полагаемся на это неявно). Сразу копируем в свой
        // `Zeroizing<[u8; 32]>`, как и везде в этом файле с секретами,
        // которые храним сами.
        let mlkem_shared: Zeroizing<[u8; 32]> = Zeroizing::new(
            self.mlkem_decap
                .decapsulate(&mlkem_ct)
                .as_slice()
                .try_into()
                .expect("ML-KEM-768 shared key всегда 32 байта (FIPS 203)"),
        );

        let server_x25519: [u8; 32] = server_x25519_bytes.try_into().map_err(|_| {
            rustls::Error::General("REALITY: некорректная длина X25519-ключа сервера".into())
        })?;
        let ecdh_shared = self
            .ephemeral
            .diffie_hellman(&X25519PublicKey::from(server_x25519));
        if !ecdh_shared.was_contributory() {
            return Err(rustls::Error::General(
                "REALITY: вырожденный X25519-ключ сервера в гибридной доле".into(),
            ));
        }

        // Порядок комбинирования — mlkem || ecdh — байт-в-байт как в
        // `crypto/tls` стандартной библиотеки Go (`hybridKeyExchange.
        // clientSharedSecret`, ветка X25519MLKEM768, см. PLAN.md, Этап 5)
        // — используется тем же кодом, что и настоящие Xray-core-серверы
        // (собственной реализации гибрида в них нет, это TLS-стек ниже
        // REALITY, тот же для всех). Итог — 64 байта на вход остального
        // TLS1.3 key schedule, вместо прежних 32 (чистый X25519 ECDH).
        let mut combined = Vec::with_capacity(32 + 32);
        combined.extend_from_slice(mlkem_shared.as_slice());
        combined.extend_from_slice(ecdh_shared.as_bytes());
        Ok(combined)
    }
}
