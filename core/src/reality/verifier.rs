//! `rustls::client::danger::ServerCertVerifier` для модели доверия
//! REALITY. См. предупреждения и первоисточники в `reality/mod.rs`.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

use super::auth::verify_ed25519_hmac;
use super::hook::RealityHook;
use crate::error::Error as CoreError;

/// Откуда `RealityCertVerifier` берёт AuthKey. `Fixed` — для тестов и для
/// вызывающего кода, который уже знает готовый ключ. `Hook` — реальный
/// путь через `transport/`: `RealityHook` вычисляет AuthKey не раньше,
/// чем отправит ClientHello (нужен `client_hello_random`), а
/// `verify_server_cert` вызывается позже — к тому моменту значение уже
/// есть (гарантирует порядок сообщений TLS-рукопожатия).
enum AuthKeySource {
    Fixed([u8; 32]),
    Hook(Arc<RealityHook>),
}

impl AuthKeySource {
    fn get(&self) -> Result<[u8; 32], TlsError> {
        match self {
            Self::Fixed(key) => Ok(*key),
            Self::Hook(hook) => hook.auth_key().ok_or_else(|| {
                TlsError::General(
                    "REALITY: AuthKey ещё не вычислен — verify_server_cert вызван раньше \
                     отправки ClientHello, это внутренняя ошибка порядка вызовов, не ответ сервера"
                        .into(),
                )
            }),
        }
    }
}

/// Заменяет проверку цепочки X.509 (корни/срок действия/имя хоста) на
/// HMAC-SHA512(AuthKey, ed25519_pubkey_сертификата) == подпись
/// сертификата — так, как это делает `VerifyPeerCertificate` в
/// Xray-core (см. `reality/mod.rs`). Подписи самого TLS-рукопожатия
/// (Certificate/CertificateVerify) по-прежнему проверяются по-настоящему
/// через `rustls::crypto::verify_tls1{2,3}_signature` — заменён только
/// источник доверия к ключу, не криптография рукопожатия целиком.
pub struct RealityCertVerifier {
    auth_key: AuthKeySource,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for RealityCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityCertVerifier").finish_non_exhaustive()
    }
}

impl RealityCertVerifier {
    /// `auth_key` — уже выведенный `RealityAuth::auth_key` этого
    /// соединения. НЕ переиспользовать между соединениями: ключ завязан
    /// на конкретный `client_hello_random` этого рукопожатия.
    ///
    /// Требует, чтобы `rustls`-crypto-провайдер уже был установлен
    /// (`crate::transport::tcp_tls::ensure_crypto_provider()`), иначе
    /// возвращает ошибку, а не паникует.
    pub fn new(auth_key: [u8; 32]) -> Result<Self, CoreError> {
        Self::with_source(AuthKeySource::Fixed(auth_key))
    }

    /// Реальный путь (`transport/`, `security=reality`): AuthKey ещё
    /// неизвестен в момент сборки `ClientConfig` (нужен
    /// `client_hello_random`, который появляется только внутри
    /// рукопожатия) — поэтому verifier не берёт готовое значение, а
    /// читает его позже из того же `RealityHook`, что вычисляет его в
    /// `seal_session_id`. `hook` должен быть ТЕМ ЖЕ `Arc`, что передан в
    /// `ClientConfig::reality` этого соединения.
    pub fn from_hook(hook: Arc<RealityHook>) -> Result<Self, CoreError> {
        Self::with_source(AuthKeySource::Hook(hook))
    }

    fn with_source(auth_key: AuthKeySource) -> Result<Self, CoreError> {
        let provider = CryptoProvider::get_default().cloned().ok_or_else(|| {
            CoreError::Protocol(
                "rustls CryptoProvider не установлен — вызвать ensure_crypto_provider() до RealityCertVerifier::new".into(),
            )
        })?;
        Ok(Self { auth_key, provider })
    }
}

impl ServerCertVerifier for RealityCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|e| {
            TlsError::General(format!("REALITY: не удалось разобрать сертификат сервера: {e}"))
        })?;

        // Ed25519 SPKI (RFC 8410) — «сырой» 32-байтный публичный ключ
        // прямо в BIT STRING, без дополнительной ASN.1-обёртки внутри.
        let spki = cert.public_key().subject_public_key.data.as_ref();
        if spki.len() != 32 {
            return Err(TlsError::General(format!(
                "REALITY: ожидался Ed25519-ключ (32 байта) в сертификате сервера, получено {} байт",
                spki.len()
            )));
        }

        let signature = cert.signature_value.data.as_ref();
        let auth_key = self.auth_key.get()?;

        if !verify_ed25519_hmac(&auth_key, spki, signature) {
            return Err(TlsError::General(
                "REALITY: HMAC-SHA512(AuthKey, pubkey сертификата) не совпал с подписью — сервер не прошёл REALITY-аутентификацию (чужой AuthKey или это не REALITY-сервер)".into(),
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    fn install_crypto_provider_for_test() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// Строит самоподписанный Ed25519-сертификат через `rcgen`, а затем
    /// ВРУЧНУЮ переписывает поле подписи в DER на HMAC-значение — то
    /// есть воспроизводит именно то, что делает REALITY-сервер
    /// (обычная x509-подпись игнорируется целиком, реальный смысл несёт
    /// только HMAC). Это единственный практичный способ протестировать
    /// `verify_server_cert` без живого REALITY-сервера.
    fn build_cert_with_hmac_signature(auth_key: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec!["reality.invalid".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().to_vec();

        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let pubkey_bytes: [u8; 32] = parsed
            .public_key()
            .subject_public_key
            .data
            .as_ref()
            .try_into()
            .expect("rcgen Ed25519 SPKI должен быть 32 байта");

        let sig_offset = find_subslice(&der, parsed.signature_value.data.as_ref())
            .expect("подпись должна присутствовать в DER как непрерывный срез");
        let sig_len = parsed.signature_value.data.as_ref().len();

        let mut mac = Hmac::<Sha512>::new_from_slice(auth_key).unwrap();
        mac.update(&pubkey_bytes);
        let hmac_sig = mac.finalize().into_bytes();

        let mut patched = der.clone();
        // rcgen подписывает Ed25519 (64-байтная подпись) — HMAC-SHA512
        // тоже даёт ровно 64 байта, длина поля в DER не меняется, можно
        // переписать байты на месте, не трогая остальную ASN.1-структуру.
        assert_eq!(sig_len, hmac_sig.len(), "длина Ed25519-подписи должна совпасть с длиной HMAC-SHA512, иначе патч сломает DER");
        patched[sig_offset..sig_offset + sig_len].copy_from_slice(&hmac_sig);

        (patched, pubkey_bytes)
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn accepts_certificate_with_valid_hmac_signature() {
        install_crypto_provider_for_test();
        let auth_key = [5u8; 32];
        let (der, _pubkey) = build_cert_with_hmac_signature(&auth_key);

        let verifier = RealityCertVerifier::new(auth_key).unwrap();
        let cert = CertificateDer::from(der);
        let server_name = ServerName::try_from("reality.invalid").unwrap();
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok(), "сертификат с верным HMAC должен быть принят: {result:?}");
    }

    #[test]
    fn rejects_certificate_with_wrong_auth_key() {
        install_crypto_provider_for_test();
        let auth_key = [5u8; 32];
        let wrong_key = [6u8; 32];
        let (der, _pubkey) = build_cert_with_hmac_signature(&auth_key);

        let verifier = RealityCertVerifier::new(wrong_key).unwrap();
        let cert = CertificateDer::from(der);
        let server_name = ServerName::try_from("reality.invalid").unwrap();
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_err(), "сертификат с HMAC под чужим ключом должен быть отвергнут");
    }

    #[test]
    fn rejects_ordinary_ca_signed_style_certificate() {
        // Обычный сертификат, подписанный самим собой по-настоящему
        // (без патча на HMAC) — не должен пройти, потому что его
        // "подпись" почти наверняка не совпадёт с HMAC ни для какого
        // ключа (вероятность коллизии пренебрежимо мала).
        install_crypto_provider_for_test();
        use rcgen::{CertificateParams, KeyPair};
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec!["reality.invalid".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().to_vec();

        let verifier = RealityCertVerifier::new([9u8; 32]).unwrap();
        let cert_der = CertificateDer::from(der);
        let server_name = ServerName::try_from("reality.invalid").unwrap();
        let result = verifier.verify_server_cert(&cert_der, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_err(), "настоящая Ed25519-подпись не должна случайно совпасть с HMAC");
    }
}
