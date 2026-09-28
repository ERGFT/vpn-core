// SPDX-License-Identifier: GPL-3.0-or-later
//! Ссылка `vless://`/`trojan://` из отдельных полей: так выходы из
//! настроек sing-box и Xray и серверы подписок проходят тот же разбор и
//! те же проверки, что и ссылка из командной строки.

/// Собрать ссылку `vless://` или `trojan://` из полей.
pub struct LinkBuilder {
    /// `vless` или `trojan`.
    pub scheme: &'static str,
    /// UUID (vless) или пароль (trojan).
    pub uuid: String,
    pub host: String,
    pub port: u16,
    pub params: Vec<(&'static str, String)>,
    pub name: String,
}

impl LinkBuilder {
    pub fn param(&mut self, k: &'static str, v: impl Into<String>) {
        let v = v.into();
        if !v.is_empty() {
            self.params.push((k, v));
        }
    }

    pub fn build(self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host
        };
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        if self.scheme == "vless" {
            q.append_pair("encryption", "none");
        }
        for (k, v) in &self.params {
            q.append_pair(k, v);
        }
        let name: String =
            url::form_urlencoded::byte_serialize(self.name.as_bytes()).collect::<String>();
        let user: String = url::form_urlencoded::byte_serialize(self.uuid.as_bytes()).collect();
        format!(
            "{}://{}@{}:{}?{}#{}",
            self.scheme,
            user.replace('+', "%20"),
            host,
            self.port,
            q.finish(),
            name.replace('+', "%20")
        )
    }
}
