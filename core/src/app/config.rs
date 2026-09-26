//! Файл настроек (TOML).
//!
//! ```toml
//! [[inbounds]]
//! type = "socks"
//! listen = "127.0.0.1:1080"
//! # auth_file = "auth.txt"          # логин:пароль в первой строке
//! # allow_ip = ["192.168.1.23"]
//!
//! [[outbounds]]
//! tag = "proxy"
//! type = "vless"
//! link_file = "server.txt"          # или link = "vless://…"
//!
//! [[outbounds]]
//! tag = "direct"
//! type = "direct"
//!
//! [route]
//! final = "proxy"                   # выход по умолчанию
//! ```
//!
//! Относительные пути — от папки файла настроек. Секреты (ссылку, пароль)
//! лучше держать в отдельных файлах: сам файл настроек тогда можно
//! показывать и хранить без опаски.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::access::IpNet;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub route: RouteConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InboundKind {
    Socks,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundConfig {
    #[serde(rename = "type")]
    pub kind: InboundKind,
    pub tag: Option<String>,
    pub listen: SocketAddr,
    /// `логин:пароль` прямо в файле (лучше — `auth_file`).
    pub auth: Option<String>,
    pub auth_file: Option<PathBuf>,
    #[serde(default)]
    pub allow_ip: Vec<IpNet>,
    pub max_conns: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundKind {
    Vless,
    Direct,
    Block,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundConfig {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: OutboundKind,
    /// vless: ссылка прямо в файле (лучше — `link_file`).
    pub link: Option<String>,
    pub link_file: Option<PathBuf>,
    /// vless: свои корневые сертификаты для `security=tls`.
    pub ca_file: Option<PathBuf>,
    /// vless: UDP через XUDP (по умолчанию) или поток на назначение.
    #[serde(default = "yes")]
    pub xudp: bool,
    /// vless: разрешить `security=none` (без шифрования).
    #[serde(default)]
    pub allow_insecure: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Выход по умолчанию; не задан — первый из `outbounds`.
    #[serde(rename = "final")]
    pub final_: Option<String>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| Error::Config(e.to_string()))
    }

    /// Прочитать файл настроек; относительные пути внутри него
    /// становятся путями от его папки.
    pub fn load(path: &Path) -> Result<Self> {
        warn_if_readable_by_others(path);
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("не удалось прочитать {}: {e}", path.display())))?;
        let mut cfg = Self::parse(&text)?;
        let base = path.parent().unwrap_or(Path::new("."));
        let fix = |p: &mut Option<PathBuf>| {
            if let Some(v) = p {
                if v.is_relative() {
                    *v = base.join(&*v);
                }
            }
        };
        for i in &mut cfg.inbounds {
            fix(&mut i.auth_file);
        }
        for o in &mut cfg.outbounds {
            fix(&mut o.link_file);
            fix(&mut o.ca_file);
        }
        Ok(cfg)
    }
}

/// На Unix: файл с секретами не должен читаться другими пользователями.
pub fn warn_if_readable_by_others(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                tracing::warn!(
                    file = %path.display(),
                    "файл с секретом доступен другим пользователям; выполните chmod 600"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Прочитать секрет (ссылку или логин:пароль) из файла: первая непустая
/// строка без пробелов по краям.
pub fn read_secret_file(path: &Path) -> Result<String> {
    warn_if_readable_by_others(path);
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("не удалось прочитать {}: {e}", path.display())))?;
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::Config(format!("файл {} пуст", path.display())))
}

/// PEM-файл с корневыми сертификатами.
pub fn load_ca(path: &Path) -> Result<rustls::RootCertStore> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    let mut roots = rustls::RootCertStore::empty();
    let iter = CertificateDer::pem_file_iter(path)
        .map_err(|e| Error::Config(format!("не удалось прочитать {}: {e}", path.display())))?;
    for cert in iter {
        let cert =
            cert.map_err(|e| Error::Config(format!("битый сертификат в {}: {e}", path.display())))?;
        roots.add(cert).map_err(|e| {
            Error::Config(format!(
                "сертификат из {} не подходит как корневой: {e}",
                path.display()
            ))
        })?;
    }
    if roots.is_empty() {
        return Err(Error::Config(format!(
            "в {} нет ни одного сертификата",
            path.display()
        )));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_and_rejects_typos() {
        let c = Config::parse(
            r#"
[[inbounds]]
type = "socks"
listen = "127.0.0.1:1080"
allow_ip = ["192.168.1.0/24"]

[[outbounds]]
tag = "proxy"
type = "vless"
link = "vless://u@h:1"
xudp = false

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"
"#,
        )
        .unwrap();
        assert_eq!(c.inbounds[0].kind, InboundKind::Socks);
        assert_eq!(c.inbounds[0].allow_ip.len(), 1);
        assert_eq!(c.outbounds.len(), 2);
        assert!(!c.outbounds[0].xudp);
        assert!(c.outbounds[1].xudp, "xudp по умолчанию включён");
        assert_eq!(c.route.final_.as_deref(), Some("direct"));

        // Опечатка в имени поля — ошибка, а не молчаливое «не задано».
        let e = Config::parse("[[outbounds]]\ntag='a'\ntype='direct'\nxudpp=true\n").unwrap_err();
        assert!(e.to_string().contains("xudpp"), "{e}");
        assert!(
            Config::parse("[[inbounds]]\ntype='carrier-pigeon'\nlisten='127.0.0.1:1'\n").is_err()
        );
        assert!(Config::parse(
            "[[inbounds]]\ntype='socks'\nlisten='127.0.0.1:1'\nallow_ip=['x']\n"
        )
        .is_err());

        // Пример из репозитория разбирается.
        let ex = Config::parse(include_str!("../../../examples/client.toml")).unwrap();
        assert_eq!(ex.outbounds.len(), 3);
        assert_eq!(ex.route.final_.as_deref(), Some("proxy"));
    }
}
