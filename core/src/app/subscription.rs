//! Подписки: адрес, по которому панель (3x-ui, Marzban, Remnawave и
//! подобные) отдаёт список серверов.
//!
//! Форматы: список ссылок в base64 (основной у панелей), обычный текст со
//! ссылками, JSON sing-box и YAML Clash (из них берутся только VLESS).
//! Серверы других протоколов пропускаются — в журнале сколько и каких.
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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use base64::Engine;
use serde::Deserialize;

use super::group::Group;
use super::http_client;
use super::outbound::Outbound;
use crate::error::{Error, Result};

/// Потолок на ответ панели.
const MAX_BODY: usize = 4 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Deserialize)]
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
}

fn yes() -> bool {
    true
}

/// Что нашлось в ответе панели.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Имя сервера и vless://-ссылка.
    pub servers: Vec<(String, String)>,
    /// Пропущенные протоколы: схема → сколько.
    pub skipped: HashMap<String, usize>,
}

fn pct_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_string())
}

fn decode_base64(text: &str) -> Option<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(b) = engine.decode(&compact) {
            if let Ok(s) = String::from_utf8(b) {
                return Some(s);
            }
        }
    }
    None
}

fn parse_lines(text: &str, out: &mut Parsed) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((scheme, rest)) = line.split_once("://") else {
            continue;
        };
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "vless" {
            *out.skipped.entry(scheme).or_default() += 1;
            continue;
        }
        let name = match rest.split_once('#') {
            Some((_, frag)) if !frag.is_empty() => pct_decode(frag),
            _ => rest
                .split(['?', '#'])
                .next()
                .and_then(|a| a.rsplit_once('@'))
                .map(|(_, hp)| hp.to_string())
                .unwrap_or_else(|| "server".into()),
        };
        out.servers.push((name, line.to_string()));
    }
}

/// Собрать vless://-ссылку из полей.
struct LinkBuilder {
    uuid: String,
    host: String,
    port: u16,
    params: Vec<(&'static str, String)>,
    name: String,
}

impl LinkBuilder {
    fn param(&mut self, k: &'static str, v: impl Into<String>) {
        let v = v.into();
        if !v.is_empty() {
            self.params.push((k, v));
        }
    }

    fn build(self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host
        };
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("encryption", "none");
        for (k, v) in &self.params {
            q.append_pair(k, v);
        }
        let name: String =
            url::form_urlencoded::byte_serialize(self.name.as_bytes()).collect::<String>();
        format!(
            "vless://{}@{}:{}?{}#{}",
            self.uuid,
            host,
            self.port,
            q.finish(),
            name.replace('+', "%20")
        )
    }
}

fn js<'a>(v: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    Some(cur)
}

fn js_str(v: &serde_json::Value, path: &[&str]) -> String {
    js(v, path)
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string()
}

/// JSON sing-box: `outbounds` с `type = "vless"`.
fn parse_singbox(text: &str, out: &mut Parsed) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| Error::Config(format!("подписка: JSON sing-box: {e}")))?;
    let list = v
        .get("outbounds")
        .and_then(|o| o.as_array())
        .cloned()
        .unwrap_or_default();
    for o in list {
        let ty = js_str(&o, &["type"]);
        match ty.as_str() {
            "vless" => {}
            // Служебные выходы sing-box — не серверы.
            "direct" | "block" | "dns" | "selector" | "urltest" | "" => continue,
            other => {
                *out.skipped.entry(other.to_string()).or_default() += 1;
                continue;
            }
        }
        let mut b = LinkBuilder {
            uuid: js_str(&o, &["uuid"]),
            host: js_str(&o, &["server"]),
            port: js(&o, &["server_port"])
                .and_then(|p| p.as_u64())
                .unwrap_or(443) as u16,
            params: Vec::new(),
            name: js_str(&o, &["tag"]),
        };
        b.param("flow", js_str(&o, &["flow"]));
        let tls = js(&o, &["tls", "enabled"]).and_then(|x| x.as_bool()) == Some(true);
        let reality =
            js(&o, &["tls", "reality", "enabled"]).and_then(|x| x.as_bool()) == Some(true);
        b.param(
            "security",
            if reality {
                "reality"
            } else if tls {
                "tls"
            } else {
                "none"
            },
        );
        b.param("sni", js_str(&o, &["tls", "server_name"]));
        b.param("fp", js_str(&o, &["tls", "utls", "fingerprint"]));
        b.param("pbk", js_str(&o, &["tls", "reality", "public_key"]));
        b.param("sid", js_str(&o, &["tls", "reality", "short_id"]));
        if let Some(alpn) = js(&o, &["tls", "alpn"]).and_then(|a| a.as_array()) {
            let a: Vec<&str> = alpn.iter().filter_map(|x| x.as_str()).collect();
            b.param("alpn", a.join(","));
        }
        let transport = js_str(&o, &["transport", "type"]);
        match transport.as_str() {
            "" => b.param("type", "tcp"),
            "ws" | "httpupgrade" => {
                b.param("type", transport.as_str());
                b.param("path", js_str(&o, &["transport", "path"]));
                let host = js_str(&o, &["transport", "headers", "Host"]);
                let host = if host.is_empty() {
                    js_str(&o, &["transport", "host"])
                } else {
                    host
                };
                b.param("host", host);
            }
            "grpc" => {
                b.param("type", "grpc");
                b.param("serviceName", js_str(&o, &["transport", "service_name"]));
            }
            other => {
                *out.skipped.entry(format!("vless+{other}")).or_default() += 1;
                continue;
            }
        }
        if b.name.is_empty() {
            b.name = format!("{}:{}", b.host, b.port);
        }
        let name = b.name.clone();
        out.servers.push((name, b.build()));
    }
    Ok(())
}

/// YAML Clash: `proxies` с `type: vless`.
fn parse_clash(text: &str, out: &mut Parsed) -> Result<()> {
    let v: serde_json::Value = yaml_serde::from_str(text)
        .map_err(|e| Error::Config(format!("подписка: YAML Clash: {e}")))?;
    let list = v
        .get("proxies")
        .and_then(|o| o.as_array())
        .cloned()
        .unwrap_or_default();
    for p in list {
        let ty = js_str(&p, &["type"]);
        if ty != "vless" {
            *out.skipped.entry(ty).or_default() += 1;
            continue;
        }
        let port = js(&p, &["port"])
            .and_then(|x| {
                x.as_u64()
                    .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(443) as u16;
        let mut b = LinkBuilder {
            uuid: js_str(&p, &["uuid"]),
            host: js_str(&p, &["server"]),
            port,
            params: Vec::new(),
            name: js_str(&p, &["name"]),
        };
        b.param("flow", js_str(&p, &["flow"]));
        let tls = js(&p, &["tls"]).and_then(|x| x.as_bool()) == Some(true);
        let reality = js(&p, &["reality-opts"]).is_some();
        b.param(
            "security",
            if reality {
                "reality"
            } else if tls {
                "tls"
            } else {
                "none"
            },
        );
        b.param("sni", js_str(&p, &["servername"]));
        b.param("fp", js_str(&p, &["client-fingerprint"]));
        b.param("pbk", js_str(&p, &["reality-opts", "public-key"]));
        b.param("sid", js_str(&p, &["reality-opts", "short-id"]));
        let network = js_str(&p, &["network"]);
        match network.as_str() {
            "" | "tcp" => b.param("type", "tcp"),
            "ws" => {
                b.param("type", "ws");
                b.param("path", js_str(&p, &["ws-opts", "path"]));
                b.param("host", js_str(&p, &["ws-opts", "headers", "Host"]));
            }
            "grpc" => {
                b.param("type", "grpc");
                b.param(
                    "serviceName",
                    js_str(&p, &["grpc-opts", "grpc-service-name"]),
                );
            }
            other => {
                *out.skipped.entry(format!("vless+{other}")).or_default() += 1;
                continue;
            }
        }
        if b.name.is_empty() {
            b.name = format!("{}:{}", b.host, b.port);
        }
        let name = b.name.clone();
        out.servers.push((name, b.build()));
    }
    Ok(())
}

/// Разобрать ответ панели в любом из форматов.
pub fn parse(body: &[u8]) -> Result<Parsed> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim().trim_start_matches('\u{feff}');
    let mut out = Parsed::default();
    if text.starts_with('{') {
        parse_singbox(text, &mut out)?;
    } else if text.contains("proxies:") {
        parse_clash(text, &mut out)?;
    } else if text.contains("://") {
        parse_lines(text, &mut out);
    } else if let Some(decoded) = decode_base64(text) {
        parse_lines(&decoded, &mut out);
    } else {
        return Err(Error::Config(
            "подписка: ответ не похож ни на список ссылок, ни на base64, ни на JSON/YAML".into(),
        ));
    }
    // Одинаковые имена — с номером, чтобы tag серверов были разными.
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (name, _) in &mut out.servers {
        let n = seen.entry(name.clone()).or_default();
        *n += 1;
        if *n > 1 {
            *name = format!("{name} ({n})");
        }
    }
    Ok(out)
}

/// Готовый к работе сервер подписки.
pub type BuiltServer = Arc<dyn Outbound>;

/// Настройки, общие для всех серверов подписки.
#[derive(Debug, Clone, Copy)]
pub struct ServerOpts {
    pub xudp: bool,
    pub allow_insecure: bool,
    pub mux: Option<u16>,
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
}

impl Subscription {
    pub fn new(
        cfg: SubscriptionConfig,
        url: String,
        groups: Vec<Weak<Group>>,
        detour: Option<Arc<dyn Outbound>>,
        direct: Arc<dyn Outbound>,
        factory: Arc<ServerFactory>,
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
        Ok(Subscription {
            roots,
            cfg,
            url,
            include,
            exclude,
            groups,
            detour,
            direct,
            factory,
        })
    }

    fn host(&self) -> String {
        http_client::Url::parse(&self.url)
            .map(|u| u.host)
            .unwrap_or_default()
    }

    /// Разобрать и применить ответ панели. Возвращает число серверов.
    pub fn apply(&self, body: &[u8]) -> Result<usize> {
        let parsed = parse(body)?;
        let mut built = Vec::new();
        let mut insecure = 0;
        let mut broken = 0;
        for (name, link) in &parsed.servers {
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
            };
            match (self.factory)(&tag, link, opts) {
                Ok(o) => built.push(o),
                Err(e) if e.to_string().contains("security=none") => insecure += 1,
                Err(e) => {
                    tracing::debug!(server = %name, error = %e, "подписка: сервер пропущен");
                    broken += 1;
                }
            }
        }
        if insecure > 0 {
            tracing::warn!(
                subscription = %self.cfg.tag,
                count = insecure,
                "подписка: серверы без шифрования (security=none) пропущены; разрешить — allow_insecure = true"
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
        Ok(n)
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
        let tmp = f.with_extension("tmp");
        let r = (|| -> std::io::Result<()> {
            std::fs::write(&tmp, body)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::rename(&tmp, f)
        })();
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
            assert_eq!(p.servers.len(), 2, "{body}");
            assert_eq!(p.servers[0].0, "Germany 🇩🇪");
            assert_eq!(p.servers[1].0, "Finland");
            assert_eq!(p.skipped["vmess"], 1);
            assert_eq!(p.skipped["trojan"], 1);
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
          {"type":"shadowsocks","tag":"ss"},
          {"type":"direct","tag":"direct"}]}"#;
        let p = parse(j.as_bytes()).unwrap();
        assert_eq!(p.servers.len(), 2);
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
"#;
        let p = parse(y.as_bytes()).unwrap();
        assert_eq!(p.servers.len(), 2);
        assert!(p.servers[0].1.contains("type=grpc") && p.servers[0].1.contains("serviceName=svc"));
        assert!(p.servers[1].1.contains(":8443?") && p.servers[1].1.contains("security=reality"));
        assert_eq!(p.skipped["trojan"], 1);
    }
}
