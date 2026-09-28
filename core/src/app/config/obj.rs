// SPDX-License-Identifier: GPL-3.0-or-later
//! Разбор JSON-настроек (sing-box, Xray) с проверкой каждого ключа.
//!
//! [`Obj`] выдаёт поля объекта по имени и помнит, какие взяты. В конце
//! [`Obj::finish`] сообщает об оставшихся: опечатка или возможность,
//! которой в этом ядре нет, — ошибка с путём до ключа
//! (`outbounds[1].tls.ech`), а не молча выброшенная настройка.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// JSON с комментариями `//` и `/* */` и запятыми перед `]`/`}` (так
/// пишут настройки sing-box и Xray) → обычный JSON.
pub fn strip_jsonc(text: &str) -> String {
    let b = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_str = true;
                out.push(c);
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    if b[i] == b'\n' {
                        out.push(b'\n');
                    }
                    i += 1;
                }
                i += 2;
            }
            b',' => {
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if !matches!(b.get(j), Some(b']') | Some(b'}')) {
                    out.push(c);
                }
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Объект настроек: поля по имени, с учётом взятых.
pub struct Obj<'a> {
    path: String,
    map: &'a Map<String, Value>,
    used: RefCell<BTreeSet<&'a str>>,
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "true/false",
        Value::Number(_) => "число",
        Value::String(_) => "строка",
        Value::Array(_) => "список",
        Value::Object(_) => "объект",
    }
}

impl<'a> Obj<'a> {
    pub fn new(path: impl Into<String>, v: &'a Value) -> Result<Self> {
        let path = path.into();
        match v {
            Value::Object(map) => Ok(Obj {
                path,
                map,
                used: RefCell::new(BTreeSet::new()),
            }),
            other => Err(Error::Config(format!(
                "{}: ожидался объект, а не {}",
                if path.is_empty() {
                    "настройки"
                } else {
                    &path
                },
                kind(other)
            ))),
        }
    }

    /// Путь до ключа внутри этого объекта.
    pub fn at(&self, key: &str) -> String {
        if self.path.is_empty() {
            key.to_string()
        } else {
            format!("{}.{key}", self.path)
        }
    }

    pub fn err(&self, key: &str, msg: impl std::fmt::Display) -> Error {
        Error::Config(format!("{}: {msg}", self.at(key)))
    }

    /// Значение ключа (null считается отсутствующим).
    pub fn get(&self, key: &str) -> Option<&'a Value> {
        let (k, v) = self.map.get_key_value(key)?;
        self.used.borrow_mut().insert(k.as_str());
        (!v.is_null()).then_some(v)
    }

    pub fn has(&self, key: &str) -> bool {
        self.map.get(key).is_some_and(|v| !v.is_null())
    }

    /// Пометить ключи взятыми, ничего с ними не делая: они есть в формате,
    /// но на работу этого ядра не влияют (журнал, оформление и т.п.).
    pub fn ignore(&self, keys: &[&str]) {
        for k in keys {
            let _ = self.get(k);
        }
    }

    /// Ключ есть в формате, но это ядро его не умеет: ошибка, если задан
    /// и не равен «пустому» значению.
    pub fn unsupported(&self, key: &str, what: &str) -> Result<()> {
        match self.get(key) {
            None | Some(Value::Bool(false)) => Ok(()),
            Some(Value::Array(a)) if a.is_empty() => Ok(()),
            Some(Value::Object(o)) if o.is_empty() => Ok(()),
            Some(Value::String(s)) if s.is_empty() => Ok(()),
            Some(_) => Err(self.err(key, format!("не поддерживается ({what})"))),
        }
    }

    pub fn str(&self, key: &str) -> Result<Option<String>> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(v) => Err(self.err(key, format!("ожидалась строка, а не {}", kind(v)))),
        }
    }

    pub fn req_str(&self, key: &str) -> Result<String> {
        self.str(key)?
            .filter(|s| !s.is_empty())
            .ok_or_else(|| self.err(key, "не задано"))
    }

    pub fn bool(&self, key: &str) -> Result<Option<bool>> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(v) => Err(self.err(key, format!("ожидалось true/false, а не {}", kind(v)))),
        }
    }

    pub fn u64(&self, key: &str) -> Result<Option<u64>> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Number(n)) => n
                .as_u64()
                .map(Some)
                .ok_or_else(|| self.err(key, "ожидалось целое неотрицательное число")),
            // Xray местами пишет числа строкой ("port": "443").
            Some(Value::String(s)) => s
                .trim()
                .parse()
                .map(Some)
                .map_err(|_| self.err(key, format!("ожидалось число, а не \"{s}\""))),
            Some(v) => Err(self.err(key, format!("ожидалось число, а не {}", kind(v)))),
        }
    }

    pub fn u16(&self, key: &str) -> Result<Option<u16>> {
        match self.u64(key)? {
            None => Ok(None),
            Some(n) => u16::try_from(n)
                .map(Some)
                .map_err(|_| self.err(key, format!("{n} — больше 65535"))),
        }
    }

    /// Строка или список строк (`"a"` и `["a"]` — одно и то же, как в
    /// sing-box и Xray).
    pub fn strs(&self, key: &str) -> Result<Vec<String>> {
        match self.get(key) {
            None => Ok(Vec::new()),
            Some(Value::String(s)) => Ok(vec![s.clone()]),
            Some(Value::Array(a)) => a
                .iter()
                .enumerate()
                .map(|(i, v)| match v {
                    Value::String(s) => Ok(s.clone()),
                    // Порты и т.п. числами.
                    Value::Number(n) => Ok(n.to_string()),
                    v => Err(Error::Config(format!(
                        "{}[{i}]: ожидалась строка, а не {}",
                        self.at(key),
                        kind(v)
                    ))),
                })
                .collect(),
            Some(Value::Number(n)) => Ok(vec![n.to_string()]),
            Some(v) => Err(self.err(key, format!("ожидался список строк, а не {}", kind(v)))),
        }
    }

    /// Ключи объекта, которых нет в `known`, — вероятные опечатки
    /// (для сообщения об ошибке, пока разбор не дошёл до [`Obj::finish`]).
    pub fn unknown_among(&self, known: &[&str]) -> Vec<String> {
        self.map
            .keys()
            .filter(|k| !known.contains(&k.as_str()) && !k.starts_with("//"))
            .cloned()
            .collect()
    }

    pub fn obj(&self, key: &str) -> Result<Option<Obj<'a>>> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => Obj::new(self.at(key), v).map(Some),
        }
    }

    /// Список объектов.
    pub fn objs(&self, key: &str) -> Result<Vec<Obj<'a>>> {
        match self.get(key) {
            None => Ok(Vec::new()),
            Some(Value::Array(a)) => a
                .iter()
                .enumerate()
                .map(|(i, v)| Obj::new(format!("{}[{i}]", self.at(key)), v))
                .collect(),
            Some(v) => Err(self.err(key, format!("ожидался список, а не {}", kind(v)))),
        }
    }

    /// Все ключи взяты? Иначе — ошибка с первыми неизвестными.
    pub fn finish(self) -> Result<()> {
        let used = self.used.into_inner();
        let rest: Vec<&str> = self
            .map
            .keys()
            .map(String::as_str)
            .filter(|k| !used.contains(k) && !k.starts_with("//") && *k != "$schema")
            .collect();
        if rest.is_empty() {
            return Ok(());
        }
        let where_ = if self.path.is_empty() {
            "в корне настроек".to_string()
        } else {
            format!("в {}", self.path)
        };
        Err(Error::Config(format!(
            "{where_} неизвестные или неподдерживаемые ключи: {}",
            rest.join(", ")
        )))
    }
}

/// Длительность в стиле Go (`30s`, `3m`, `1h30m`, `500ms`) или число
/// секунд.
pub fn duration(o: &Obj<'_>, key: &str) -> Result<Option<Duration>> {
    let s = match o.get(key) {
        None => return Ok(None),
        Some(Value::Number(n)) => {
            return n
                .as_u64()
                .map(|s| Some(Duration::from_secs(s)))
                .ok_or_else(|| o.err(key, "ожидалось число секунд"))
        }
        Some(Value::String(s)) => s.trim().to_string(),
        Some(v) => return Err(o.err(key, format!("ожидалась длительность, а не {}", kind(v)))),
    };
    parse_go_duration(&s).map(Some).ok_or_else(|| {
        o.err(
            key,
            format!("«{s}» — не длительность (пример: 30s, 3m, 1h)"),
        )
    })
}

pub fn parse_go_duration(s: &str) -> Option<Duration> {
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<u64>() {
        return Some(Duration::from_secs(n));
    }
    let mut total = Duration::ZERO;
    let mut rest = s;
    while !rest.is_empty() {
        let num_end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if num_end == 0 {
            return None;
        }
        let n: f64 = rest[..num_end].parse().ok()?;
        rest = &rest[num_end..];
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let secs = match &rest[..unit_end] {
            "ns" => n / 1e9,
            "us" | "µs" => n / 1e6,
            "ms" => n / 1e3,
            "s" => n,
            "m" => n * 60.0,
            "h" => n * 3600.0,
            "d" => n * 86400.0,
            _ => return None,
        };
        total += Duration::from_secs_f64(secs);
        rest = &rest[unit_end..];
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonc_comments_and_trailing_commas() {
        let t = r#"{
            // комментарий
            "a": "http://x//y", /* блок
            комментарий */ "b": [1, 2,],
            "в": "строка с \" и // внутри",
        }"#;
        let v: Value = serde_json::from_str(&strip_jsonc(t)).unwrap();
        assert_eq!(v["a"], "http://x//y");
        assert_eq!(v["b"], serde_json::json!([1, 2]));
        assert_eq!(v["в"], "строка с \" и // внутри");
    }

    #[test]
    fn unknown_keys_are_reported_with_path() {
        let v: Value = serde_json::json!({"a": 1, "typo": 2});
        let o = Obj::new("outbounds[0]", &v).unwrap();
        assert_eq!(o.u64("a").unwrap(), Some(1));
        let e = o.finish().unwrap_err().to_string();
        assert!(e.contains("outbounds[0]") && e.contains("typo"), "{e}");
    }

    #[test]
    fn go_durations() {
        assert_eq!(parse_go_duration("3m"), Some(Duration::from_secs(180)));
        assert_eq!(parse_go_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_go_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_go_duration("45"), Some(Duration::from_secs(45)));
        assert_eq!(parse_go_duration("3x"), None);
    }
}
