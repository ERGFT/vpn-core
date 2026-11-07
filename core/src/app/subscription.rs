// SPDX-License-Identifier: GPL-3.0-or-later
//! Подписки: адрес, по которому панель (3x-ui, Marzban, Remnawave и
//! подобные) отдаёт список серверов.
//!
//! Форматы: список ссылок в base64 (основной у панелей), обычный текст со
//! ссылками, JSON sing-box и YAML Clash. Поддерживаемые VLESS/Trojan
//! создаются; Hysteria 2 URI распознаются, но пропускаются до готовности
//! outbound. Серверы других протоколов пропускаются с подсчётом.
//!
//! Безопасность:
//! - адрес подписки — секрет того же уровня, что UUID (в нём токен):
//!   лучше `url_file`; в журнал пишется только имя сервера панели;
//! - только https с проверкой сертификата (иначе список серверов — а
//!   значит, и куда пойдёт весь трафик — может подменить любой по пути);
//! - серверы с `security=none` пропускаются, если подписке это явно не
//!   разрешено (`allow_insecure`), — те же правила, что для ссылки;
//! - последний рабочий список хранится на диске (`cache_file`) —
//!   клиент стартует, даже если панель недоступна; файл содержит UUID,
//!   на Unix права 600.

use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use serde::Deserialize;

use super::group::Group;
use super::http_client;
use super::outbound::Outbound;
use crate::error::{Error, Result};

/// Потолок на ответ панели.
const MAX_BODY: usize = 4 * 1024 * 1024;
/// Потолок на число серверов в одной подписке: иначе панель на 4 МиБ
/// создаёт десятки тысяч выходов с TLS-конфигами и съедает память.
const MAX_SERVERS: usize = 4096;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionConfig {
    pub tag: String,
    /// Адрес прямо в файле настроек (лучше — `url_file`).
    pub url: Option<String>,
    pub url_file: Option<PathBuf>,
    /// Как часто обновлять, секунд (по умолчанию 12 часов).
    pub update_interval: Option<u64>,
    /// Через какой выход загружать (по умолчанию — через группу, в
    /// которую входит подписка, а при первом запуске без сохранённого
    /// списка — напрямую).
    pub detour: Option<String>,
    /// Где хранить последний рабочий список (по умолчанию рядом с файлом
    /// настроек: `<tag>.subscription`).
    pub cache_file: Option<PathBuf>,
    /// Разрешить серверы с `security=none`.
    #[serde(default)]
    pub allow_insecure: bool,
    /// Брать только серверы, чьё имя подходит под выражение.
    pub include: Option<String>,
    /// Не брать серверы, чьё имя подходит под выражение.
    pub exclude: Option<String>,
    /// User-Agent запроса (от него панели зависит формат ответа).
    pub user_agent: Option<String>,
    /// UDP через XUDP (как у ссылки в выходе vless).
    #[serde(default = "yes")]
    pub xudp: bool,
    /// Свои корневые сертификаты панели (самоподписанный сертификат).
    pub ca_file: Option<PathBuf>,
    /// Mux.Cool для серверов подписки (кроме серверов с Vision).
    pub mux: Option<u16>,
    /// Дробление ClientHello к серверам подписки.
    pub fragment: Option<crate::transport::fragment::FragmentConfig>,
}

/// Адрес подписки — секрет (в нём токен панели).
impl std::fmt::Debug for SubscriptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionConfig")
            .field("tag", &self.tag)
            .field("url", &crate::redact::opt(&self.url))
            .field("url_file", &self.url_file)
            .field("update_interval", &self.update_interval)
            .field("detour", &self.detour)
            .field("cache_file", &self.cache_file)
            .field("allow_insecure", &self.allow_insecure)
            .field("include", &self.include)
            .field("exclude", &self.exclude)
            .field("user_agent", &self.user_agent)
            .field("xudp", &self.xudp)
            .field("ca_file", &self.ca_file)
            .field("mux", &self.mux)
            .field("fragment", &self.fragment)
            .finish()
    }
}

fn yes() -> bool {
    true
}

pub(crate) mod formats;
use formats::parse_typed;
pub use formats::{parse, Parsed};

/// Готовый к работе сервер подписки.
pub type BuiltServer = Arc<dyn Outbound>;

/// Настройки, общие для всех серверов подписки.
#[derive(Debug, Clone)]
pub struct ServerOpts {
    pub xudp: bool,
    pub allow_insecure: bool,
    pub mux: Option<u16>,
    pub fragment: Option<Arc<crate::transport::fragment::Fragment>>,
}

/// Собирает выходы из ссылок подписки (tag, ссылка; проверки — как у
/// выхода vless).
pub type ServerFactory = dyn Fn(&str, &str, ServerOpts) -> Result<BuiltServer> + Send + Sync;

pub struct Subscription {
    pub cfg: SubscriptionConfig,
    url: String,
    include: Option<regex::Regex>,
    exclude: Option<regex::Regex>,
    groups: Vec<Weak<Group>>,
    detour: Option<Arc<dyn Outbound>>,
    /// Напрямую — для самой первой загрузки.
    direct: Arc<dyn Outbound>,
    factory: Arc<ServerFactory>,
    roots: Option<rustls::RootCertStore>,
    fragment: Option<Arc<crate::transport::fragment::Fragment>>,
    events: super::events::Bus,
    /// Текущие серверы и когда список применён (мс Unix) — для API.
    current: std::sync::Mutex<(Vec<Arc<dyn Outbound>>, u64)>,
}

impl Subscription {
    pub fn new(
        cfg: SubscriptionConfig,
        url: String,
        groups: Vec<Weak<Group>>,
        detour: Option<Arc<dyn Outbound>>,
        direct: Arc<dyn Outbound>,
        factory: Arc<ServerFactory>,
        events: super::events::Bus,
    ) -> Result<Self> {
        let rx = |r: &Option<String>, what: &str| -> Result<Option<regex::Regex>> {
            r.as_deref()
                .map(|s| {
                    regex::Regex::new(s)
                        .map_err(|e| Error::Config(format!("подписка {}: {what}: {e}", cfg.tag)))
                })
                .transpose()
        };
        let include = rx(&cfg.include, "include")?;
        let exclude = rx(&cfg.exclude, "exclude")?;
        let u = http_client::Url::parse(&url)
            .map_err(|e| Error::Config(format!("подписка {}: {e}", cfg.tag)))?;
        if !u.https {
            return Err(Error::Config(format!(
                "подписка {}: адрес должен быть https — иначе список серверов могут подменить",
                cfg.tag
            )));
        }
        let roots = cfg
            .ca_file
            .as_deref()
            .map(super::config::load_ca)
            .transpose()?;
        let fragment = cfg
            .fragment
            .as_ref()
            .map(|f| f.build().map(Arc::new))
            .transpose()
            .map_err(|e| Error::Config(format!("подписка {}: {e}", cfg.tag)))?;
        Ok(Subscription {
            fragment,
            roots,
            cfg,
            url,
            include,
            exclude,
            groups,
            detour,
            direct,
            factory,
            events,
            current: std::sync::Mutex::new((Vec::new(), 0)),
        })
    }

    fn host(&self) -> String {
        http_client::Url::parse(&self.url)
            .map(|u| u.host)
            .unwrap_or_default()
    }

    /// Разобрать и применить ответ панели. Возвращает число серверов.
    pub fn apply(&self, body: &[u8]) -> Result<usize> {
        let parsed = parse_typed(body)?;
        if parsed.servers.len() > MAX_SERVERS {
            return Err(Error::Config(format!(
                "подписка {}: серверов больше {MAX_SERVERS} — такой список не применяется",
                self.cfg.tag
            )));
        }
        let mut built = Vec::new();
        let mut insecure = 0;
        let mut broken = parsed.invalid;
        for server in &parsed.servers {
            let name = &server.name;
            let link = &server.link;
            if self.include.as_ref().is_some_and(|r| !r.is_match(name))
                || self.exclude.as_ref().is_some_and(|r| r.is_match(name))
            {
                continue;
            }
            let tag = format!("{}/{name}", self.cfg.tag);
            let opts = ServerOpts {
                xudp: self.cfg.xudp,
                allow_insecure: self.cfg.allow_insecure,
                mux: self.cfg.mux,
                fragment: self.fragment.clone(),
            };
            match (self.factory)(&tag, link, opts) {
                Ok(o) => built.push(o),
                Err(e) if e.to_string().contains("security=none") => insecure += 1,
                Err(e) => {
                    tracing::debug!(
                        server = ?name,
                        protocol = server.protocol.as_str(),
                        error = %e,
                        "подписка: сервер пропущен"
                    );
                    broken += 1;
                }
            }
        }
        if insecure > 0 {
            tracing::warn!(
                subscription = %self.cfg.tag,
                count = insecure,
                "подписка: серверы без шифрования (security=none) пропущены; разрешить — \"allow_insecure\": true"
            );
        }
        if broken > 0 {
            tracing::warn!(subscription = %self.cfg.tag, count = broken, "подписка: серверы с неподходящими ссылками пропущены");
        }
        for (scheme, n) in &parsed.skipped {
            tracing::info!(subscription = %self.cfg.tag, protocol = %scheme, count = n, "подписка: протокол не поддерживается — пропущено");
        }
        if built.is_empty() {
            return Err(Error::Config(format!(
                "подписка {}: ни одного подходящего сервера",
                self.cfg.tag
            )));
        }
        let n = built.len();
        for g in self.groups.iter().filter_map(Weak::upgrade) {
            g.set_dynamic(&self.cfg.tag, built.clone());
        }
        *self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (built, super::stats::now_ms());
        Ok(n)
    }

    /// Серверы подписки и время, когда список применён (мс Unix; 0 — ещё
    /// не было).
    pub fn servers(&self) -> (Vec<Arc<dyn Outbound>>, u64) {
        self.current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Прочитать сохранённый список (при запуске).
    pub fn load_cache(&self) -> Option<usize> {
        let f = self.cfg.cache_file.as_ref()?;
        let body = std::fs::read(f).ok()?;
        match self.apply(&body) {
            Ok(n) => {
                tracing::info!(subscription = %self.cfg.tag, servers = n, "подписка: сохранённый список загружен");
                Some(n)
            }
            Err(e) => {
                tracing::warn!(subscription = %self.cfg.tag, error = %e, "подписка: сохранённый список не подошёл");
                None
            }
        }
    }

    fn save_cache(&self, body: &[u8]) {
        let Some(f) = &self.cfg.cache_file else {
            return;
        };
        // Права 0600 — сразу при создании: в списке UUID и адреса серверов.
        let r = crate::fsutil::write_atomic(f, body, 0o600);
        if let Err(e) = r {
            tracing::warn!(subscription = %self.cfg.tag, error = %e, "подписка: список не сохранён");
        }
    }

    /// Через какие выходы пробовать загрузку.
    fn routes(&self, first_time: bool) -> Vec<Arc<dyn Outbound>> {
        if let Some(d) = &self.detour {
            return vec![d.clone()];
        }
        let mut v: Vec<Arc<dyn Outbound>> = self
            .groups
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|g| !g.members().is_empty())
            .map(|g| g as Arc<dyn Outbound>)
            .take(1)
            .collect();
        if first_time || v.is_empty() {
            v.push(self.direct.clone());
        }
        v
    }

    /// Загрузить и применить; `first_time` — сохранённого списка нет.
    pub async fn update(&self, first_time: bool) -> Result<usize> {
        let r = self.fetch_apply(first_time).await;
        self.events
            .emit(|| super::events::Event::SubscriptionUpdate {
                subscription: self.cfg.tag.clone(),
                servers: r.as_ref().ok().copied(),
                error: r.as_ref().err().map(|e| e.to_string()),
            });
        r
    }

    async fn fetch_apply(&self, first_time: bool) -> Result<usize> {
        let ua = self
            .cfg
            .user_agent
            .clone()
            .unwrap_or_else(|| "v2rayN/7.10.0".into());
        let mut last = None;
        for via in self.routes(first_time) {
            let r = http_client::get(
                via.as_ref(),
                &self.url,
                &[("User-Agent", &ua), ("Accept", "*/*")],
                MAX_BODY,
                FETCH_TIMEOUT,
                true,
                self.roots.as_ref(),
            )
            .await;
            match r {
                Ok(resp) if resp.status == 200 => {
                    if let Some(info) = resp.header("subscription-userinfo") {
                        tracing::info!(subscription = %self.cfg.tag, info, "подписка: трафик и срок");
                    }
                    let n = self.apply(&resp.body)?;
                    self.save_cache(&resp.body);
                    tracing::info!(
                        subscription = %self.cfg.tag,
                        panel = %self.host(),
                        via = via.tag(),
                        servers = n,
                        "подписка обновлена"
                    );
                    return Ok(n);
                }
                Ok(resp) => {
                    last = Some(Error::Protocol(format!(
                        "подписка {}: панель ответила {}",
                        self.cfg.tag, resp.status
                    )))
                }
                Err(e) if e.to_string().contains("CaUsedAsEndEntity") => {
                    last = Some(Error::Protocol(format!(
                        "подписка {}: сертификат панели — сертификат центра (CA:TRUE), а не \
                         сервера; выпустите сертификат сервера с basicConstraints=CA:FALSE",
                        self.cfg.tag
                    )))
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| Error::Protocol("подписка: некуда отправить запрос".into())))
    }

    /// Есть ли сохранённый список моложе интервала обновления.
    fn cache_fresh(&self) -> bool {
        self.cfg
            .cache_file
            .as_ref()
            .and_then(|f| std::fs::metadata(f).ok())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < self.interval())
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(self.cfg.update_interval.unwrap_or(12 * 3600).max(60))
    }

    /// Обновлять по расписанию. `loaded` — список уже есть (из сохранённого
    /// или загружен при запуске); первое обновление — сразу, если списка
    /// нет или он старше интервала.
    pub async fn run(self: Arc<Self>, loaded: bool) -> Result<()> {
        let interval = self.interval();
        let mut first = !loaded;
        let mut wait = if loaded && self.cache_fresh() {
            interval.mul_f64(rand::random::<f64>() * 0.2 + 0.9)
        } else {
            Duration::from_secs(1)
        };
        loop {
            tokio::time::sleep(wait).await;
            match self.update(first).await {
                Ok(_) => {
                    first = false;
                    wait = interval.mul_f64(rand::random::<f64>() * 0.2 + 0.9);
                }
                Err(e) => {
                    tracing::warn!(subscription = %self.cfg.tag, error = %e, "подписка: обновить не удалось");
                    // Повтор раньше: через минуту, пока списка нет, иначе
                    // через 5 минут (но не реже интервала).
                    wait = if first {
                        Duration::from_secs(60)
                    } else {
                        Duration::from_secs(300).min(interval)
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const L1: &str = "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=reality&sni=x.com&pbk=AAAA&sid=01&type=tcp#Germany%20%F0%9F%87%A9%F0%9F%87%AA";
    const L2: &str = "vless://22222222-2222-2222-2222-222222222222@b.example:8443?security=tls&type=ws&path=%2Fws#Finland";

    #[test]
    fn base64_and_plain_lists() {
        let plain = format!("{L1}\n{L2}\nvmess://eyJ2IjoyfQ==\ntrojan://p@c:443#T\n\n");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&plain);
        for body in [
            plain.clone(),
            b64.clone(),
            format!("{}\n", &b64[..b64.len()]),
        ] {
            let p = parse(body.as_bytes()).unwrap();
            assert_eq!(p.servers.len(), 3, "{body}");
            assert_eq!(p.servers[0].0, "Germany 🇩🇪");
            assert_eq!(p.servers[1].0, "Finland");
            assert_eq!(p.servers[2], ("T".into(), "trojan://p@c:443#T".into()));
            assert_eq!(p.skipped["vmess"], 1);
        }
        // Без имени — host:port; одинаковые имена — с номером.
        let p = parse(format!("vless://u@h.example:1?type=tcp\n{L2}\n{L2}").as_bytes()).unwrap();
        assert_eq!(p.servers[0].0, "h.example:1");
        assert_eq!(p.servers[2].0, "Finland (2)");
        assert!(parse(b"<html>blocked</html>").is_err());
    }

    #[test]
    fn singbox_json() {
        let j = r#"{"outbounds":[
          {"type":"vless","tag":"NL reality","server":"nl.example","server_port":443,
           "uuid":"33333333-3333-3333-3333-333333333333","flow":"xtls-rprx-vision",
           "tls":{"enabled":true,"server_name":"www.site.com","utls":{"enabled":true,"fingerprint":"chrome"},
                  "reality":{"enabled":true,"public_key":"PBK","short_id":"ab"}}},
          {"type":"vless","tag":"ws","server":"w.example","server_port":80,"uuid":"u",
           "transport":{"type":"ws","path":"/p","headers":{"Host":"h.example"}}},
          {"type":"trojan","tag":"TJ","server":"tj.example","server_port":443,"password":"pw",
           "tls":{"enabled":true,"server_name":"tj.example"},"transport":{"type":"ws","path":"/t"}},
          {"type":"shadowsocks","tag":"ss"},
          {"type":"direct","tag":"direct"}]}"#;
        let p = parse(j.as_bytes()).unwrap();
        assert_eq!(p.servers.len(), 3);
        let t = crate::trojan::TrojanConfig::parse(&p.servers[2].1).unwrap();
        assert_eq!(t.password, "pw");
        assert_eq!(t.transport.network, crate::vless::NetworkType::Ws);
        let link = &p.servers[0].1;
        for part in [
            "@nl.example:443?",
            "security=reality",
            "sni=www.site.com",
            "pbk=PBK",
            "sid=ab",
            "flow=xtls-rprx-vision",
            "type=tcp",
            "#NL%20reality",
        ] {
            assert!(link.contains(part), "{link} ~ {part}");
        }
        let v = crate::vless::VlessConfig::parse(link).unwrap();
        assert_eq!(v.host, "nl.example");
        assert!(p.servers[1].1.contains("path=%2Fp") && p.servers[1].1.contains("host=h.example"));
        assert_eq!(p.skipped["shadowsocks"], 1);
    }

    #[test]
    fn out_of_range_port_is_not_truncated() {
        let y = r#"
proxies:
  - {name: big, type: vless, server: a.example, port: 70000, uuid: 44444444-4444-4444-4444-444444444444, tls: true}
  - {name: ok, type: vless, server: b.example, port: "8443", uuid: 44444444-4444-4444-4444-444444444444, tls: true}
"#;
        let p = parse(y.as_bytes()).unwrap();
        assert_eq!(p.invalid, 1);
        assert_eq!(p.servers.len(), 1);
        assert!(
            p.servers[0].1.contains("@b.example:8443?"),
            "{}",
            p.servers[0].1
        );
        let j = r#"{"outbounds": [
            {"type": "vless", "tag": "z", "server": "c.example", "server_port": 0,
             "uuid": "44444444-4444-4444-4444-444444444444"}]}"#;
        let p = parse(j.as_bytes()).unwrap();
        assert_eq!((p.invalid, p.servers.len()), (1, 0));
    }

    #[test]
    fn control_characters_are_removed_from_names() {
        let list = "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls#Good%0AFAKE%20LOG\n";
        let p = parse(list.as_bytes()).unwrap();
        assert_eq!(p.servers[0].0, "GoodFAKE LOG");
    }

    #[test]
    fn clash_yaml() {
        let y = r#"
port: 7890
proxies:
  - name: "JP"
    type: vless
    server: jp.example
    port: 443
    uuid: 44444444-4444-4444-4444-444444444444
    network: grpc
    tls: true
    servername: jp.example
    grpc-opts:
      grpc-service-name: svc
  - name: R
    type: vless
    server: r.example
    port: "8443"
    uuid: 55555555-5555-5555-5555-555555555555
    flow: xtls-rprx-vision
    tls: true
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: KEY
      short-id: "01"
  - name: T
    type: trojan
    server: t
    port: 1
    password: "pa ss"
"#;
        let p = parse(y.as_bytes()).unwrap();
        assert_eq!(p.servers.len(), 3);
        assert!(p.servers[0].1.contains("type=grpc") && p.servers[0].1.contains("serviceName=svc"));
        assert!(p.servers[1].1.contains(":8443?") && p.servers[1].1.contains("security=reality"));
        let t = crate::trojan::TrojanConfig::parse(&p.servers[2].1).unwrap();
        assert_eq!(
            (t.password.as_str(), t.transport.host.as_str()),
            ("pa ss", "t")
        );
        assert_eq!(t.transport.security, crate::vless::Security::Tls);
    }
}
