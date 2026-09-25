use thiserror::Error;

/// Единая ошибка для всего ядра. Каждый вариант соответствует месту,
/// где реально может провалиться протокольный код — не "общая" ошибка.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid VLESS URI: {0}")]
    InvalidUri(String),

    #[error("unsupported address type: {0}")]
    UnsupportedAddressType(u8),

    #[error("unsupported SOCKS5 version: {0}")]
    UnsupportedSocksVersion(u8),

    #[error("unsupported SOCKS5 command: {0}")]
    UnsupportedSocksCommand(u8),

    #[error("SOCKS5 protocol error: {0}")]
    Socks5(String),

    #[error("VLESS protocol error: {0}")]
    Protocol(String),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("invalid DNS name: {0}")]
    InvalidDnsName(#[from] rustls_pki_types::InvalidDnsNameError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid UUID: {0}")]
    Uuid(#[from] uuid::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
