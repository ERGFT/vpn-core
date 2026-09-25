use alloc::boxed::Box;
use alloc::vec::Vec;

use super::ResolvesClientCert;
use crate::log::{debug, trace};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{CertificateChain, DistinguishedName, ProtocolName, ServerExtensions};
use crate::sync::Arc;
use crate::{compress, sign, CipherSuite, SignatureScheme};

#[derive(Debug)]
pub(super) struct ServerCertDetails<'a> {
    pub(super) cert_chain: CertificateChain<'a>,
    pub(super) ocsp_response: Vec<u8>,
}

impl<'a> ServerCertDetails<'a> {
    pub(super) fn new(cert_chain: CertificateChain<'a>, ocsp_response: Vec<u8>) -> Self {
        Self {
            cert_chain,
            ocsp_response,
        }
    }

    pub(super) fn into_owned(self) -> ServerCertDetails<'static> {
        let Self {
            cert_chain,
            ocsp_response,
        } = self;
        ServerCertDetails {
            cert_chain: cert_chain.into_owned(),
            ocsp_response,
        }
    }
}

pub(super) struct ClientHelloDetails {
    pub(super) alpn_protocols: Vec<ProtocolName>,
    pub(super) sent_extensions: Vec<ExtensionType>,
    pub(super) extension_order_seed: u16,
    // reality-core (Этап 3): GREASE-значения (RFC 8701) этого соединения.
    // Генерируются ровно один раз в `ClientHelloInput::new`, по той же
    // причине, что и `extension_order_seed` строкой выше:
    // HelloRetryRequest — это второй ClientHello ТОГО ЖЕ соединения, и
    // GREASE-значения там должны быть те же, что и в первом (в
    // BoringSSL/uTLS они тоже живут на соединении — `greaseSeed` в
    // `u_conn.go`, — а не генерируются заново на каждый hello).
    pub(super) grease: GreaseValues,
    pub(super) offered_cert_compression: bool,
    pub(super) offered_cipher_suites: Vec<CipherSuite>,
}

/// reality-core (Этап 3): по одному GREASE-значению на каждое место в
/// ClientHello, где его ставит Chrome (раскладка — как у BoringSSL,
/// `ssl_grease_index_t`; сверено по `u_parrots.go` utls, профиль
/// `HelloChrome_133`): cipher suite, группа (одна и та же в
/// supported_groups и key_share), два пустых расширения (первое и
/// последнее в списке) и версия в supported_versions. Разные места —
/// независимые значения, а не одно на всё.
#[derive(Clone, Copy, Debug)]
pub(super) struct GreaseValues {
    pub(super) cipher: u16,
    pub(super) group: u16,
    pub(super) extension1: u16,
    pub(super) extension2: u16,
    pub(super) version: u16,
}

impl GreaseValues {
    pub(super) fn generate(
        secure_random: &dyn crate::crypto::SecureRandom,
    ) -> Result<Self, crate::rand::GetRandomFailed> {
        let next = || crate::rand::random_u16(secure_random).map(grease_value);
        let cipher = next()?;
        let group = next()?;
        let extension1 = next()?;
        let mut extension2 = next()?;
        // Два GREASE-расширения с одинаковым типом — это дубликат
        // расширения, который сервер обязан отвергнуть (RFC 8446 §4.2).
        // BoringSSL в этом случае делает `^= 0x1010` — результат остаётся
        // GREASE-формы (0x?A?A), но гарантированно отличается.
        if extension2 == extension1 {
            extension2 ^= 0x1010;
        }
        let version = next()?;
        Ok(Self {
            cipher,
            group,
            extension1,
            extension2,
            version,
        })
    }
}

/// Случайные 16 бит → одно из 16 GREASE-значений вида `0x?A?A`
/// (RFC 8701 §2: 0x0A0A, 0x1A1A, …, 0xFAFA).
fn grease_value(raw: u16) -> u16 {
    let nibble = raw & 0x0f;
    (nibble << 12) | 0x0a00 | (nibble << 4) | 0x0a
}

impl ClientHelloDetails {
    pub(super) fn new(
        alpn_protocols: Vec<ProtocolName>,
        extension_order_seed: u16,
        grease: GreaseValues,
    ) -> Self {
        Self {
            alpn_protocols,
            sent_extensions: Vec::new(),
            extension_order_seed,
            grease,
            offered_cert_compression: false,
            offered_cipher_suites: Vec::new(),
        }
    }

    pub(super) fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &ServerExtensions<'_>,
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        let mut extensions = received_exts.collect_used();
        extensions.extend(
            received_exts
                .unknown_extensions
                .iter()
                .map(|ext| ExtensionType::from(*ext)),
        );
        for ext_type in extensions {
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {ext_type:?}");
                return true;
            }
        }

        false
    }
}

pub(super) enum ClientAuthDetails {
    /// Send an empty `Certificate` and no `CertificateVerify`.
    Empty { auth_context_tls13: Option<Vec<u8>> },
    /// Send a non-empty `Certificate` and a `CertificateVerify`.
    Verify {
        certkey: Arc<sign::CertifiedKey>,
        signer: Box<dyn sign::Signer>,
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    },
}

impl ClientAuthDetails {
    pub(super) fn resolve(
        resolver: &dyn ResolvesClientCert,
        canames: Option<&[DistinguishedName]>,
        sigschemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    ) -> Self {
        let acceptable_issuers = canames
            .unwrap_or_default()
            .iter()
            .map(|p| p.as_ref())
            .collect::<Vec<&[u8]>>();

        if let Some(certkey) = resolver.resolve(&acceptable_issuers, sigschemes) {
            if let Some(signer) = certkey.key.choose_scheme(sigschemes) {
                debug!("Attempting client auth");
                return Self::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                    compressor,
                };
            }
        }

        debug!("Client auth requested but no cert/sigscheme available");
        Self::Empty { auth_context_tls13 }
    }
}
