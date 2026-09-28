// SPDX-License-Identifier: GPL-3.0-or-later
//! «Шум» перед UDP (`noises` у Xray, `freedom`): перед первой датаграммой
//! к новому адресу выход `direct` шлёт туда несколько пакетов-пустышек.
//! DPI, который узнаёт протокол (QUIC, WireGuard, игры) по первому
//! пакету потока, видит сначала мусор.
//!
//! Виды: `rand` (случайные байты, длина — `packet = "от-до"`), `str`
//! (строка как есть), `base64`, `hex`. `delay` — пауза после пакета, мс.
//! `apply_to` — `ip` (по умолчанию), `ipv4`, `ipv6`. К порту 53 (DNS) шум
//! не шлётся — как у Xray. По умолчанию выключено.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;
use rand::RngCore;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::transport::fragment::{parse_range, NumOrRange};
use crate::transport::xhttp::Range;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoiseConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub packet: NumOrRange,
    pub delay: Option<NumOrRange>,
    pub apply_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Data {
    Rand(Range),
    Fixed(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Apply {
    Ip,
    V4,
    V6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Noise {
    data: Data,
    delay: Range,
    apply: Apply,
}

/// Больше датаграмму шуметь незачем (и её могут отбросить по MTU).
const MAX_NOISE: usize = 1400;

impl NoiseConfig {
    pub fn build(&self) -> Result<Noise> {
        let text = || match &self.packet {
            NumOrRange::Str(s) => s.clone(),
            NumOrRange::Num(n) => n.to_string(),
        };
        let data = match self.kind.as_str() {
            "rand" => {
                let r = match &self.packet {
                    NumOrRange::Num(n) => Range { from: *n, to: *n },
                    NumOrRange::Str(s) => parse_range(s, "noises.packet")?,
                };
                if r.from == 0 || r.to as usize > MAX_NOISE {
                    return Err(Error::Config(format!(
                        "noises: длина rand — от 1 до {MAX_NOISE} байт"
                    )));
                }
                Data::Rand(r)
            }
            "str" => Data::Fixed(text().into_bytes()),
            "base64" => Data::Fixed(
                base64::engine::general_purpose::STANDARD
                    .decode(text().trim())
                    .map_err(|e| Error::Config(format!("noises: base64: {e}")))?,
            ),
            "hex" => Data::Fixed(
                hex::decode(text().trim())
                    .map_err(|e| Error::Config(format!("noises: hex: {e}")))?,
            ),
            other => {
                return Err(Error::Config(format!(
                    "noises: type = «{other}» — бывает rand, str, base64, hex"
                )))
            }
        };
        if let Data::Fixed(d) = &data {
            if d.is_empty() || d.len() > MAX_NOISE {
                return Err(Error::Config(format!(
                    "noises: пакет — от 1 до {MAX_NOISE} байт"
                )));
            }
        }
        let delay = match &self.delay {
            Some(d) => d.range("noises.delay")?,
            None => Range { from: 0, to: 0 },
        };
        if delay.to > 1000 {
            return Err(Error::Config(
                "noises.delay: больше секунды — UDP-приложения не дождутся".into(),
            ));
        }
        let apply = match self.apply_to.as_deref().unwrap_or("ip") {
            "ip" => Apply::Ip,
            "ipv4" => Apply::V4,
            "ipv6" => Apply::V6,
            other => {
                return Err(Error::Config(format!(
                    "noises: apply_to = «{other}» — бывает ip, ipv4, ipv6"
                )))
            }
        };
        Ok(Noise { data, delay, apply })
    }
}

impl Noise {
    /// Слать ли этот шум к `ip:port`.
    pub fn applies(&self, ip: IpAddr, port: u16) -> bool {
        port != 53
            && match self.apply {
                Apply::Ip => true,
                Apply::V4 => ip.is_ipv4(),
                Apply::V6 => ip.is_ipv6(),
            }
    }

    /// Пакет шума.
    pub fn packet(&self) -> Vec<u8> {
        match &self.data {
            Data::Fixed(d) => d.clone(),
            Data::Rand(r) => {
                let mut v = vec![0u8; r.rand() as usize];
                rand::thread_rng().fill_bytes(&mut v);
                v
            }
        }
    }

    /// Пауза после пакета.
    pub fn delay(&self) -> Duration {
        Duration::from_millis(self.delay.rand() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ключ='строка'` или `ключ=число` построчно → JSON-объект.
    fn kv(s: &str) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        for line in s.lines() {
            let (k, v) = line.split_once('=').unwrap();
            let v = v.trim();
            let v = match v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')) {
                Some(s) => serde_json::Value::String(s.into()),
                None => serde_json::Value::from(v.parse::<u64>().unwrap()),
            };
            m.insert(k.trim().into(), v);
        }
        serde_json::Value::Object(m)
    }

    fn n(s: &str) -> Result<Noise> {
        serde_json::from_value::<NoiseConfig>(kv(s))
            .unwrap()
            .build()
    }

    #[test]
    fn kinds_and_limits() {
        let r = n("type='rand'\npacket='10-20'\ndelay='5-10'").unwrap();
        for _ in 0..20 {
            assert!((10..=20).contains(&r.packet().len()));
            assert!((5..=10).contains(&(r.delay().as_millis() as u64)));
        }
        assert_eq!(n("type='str'\npacket='hello'").unwrap().packet(), b"hello");
        assert_eq!(
            n("type='base64'\npacket='AAEC'").unwrap().packet(),
            [0, 1, 2]
        );
        assert_eq!(n("type='hex'\npacket='ff00'").unwrap().packet(), [255, 0]);
        let v6 = n("type='str'\npacket='x'\napply_to='ipv6'").unwrap();
        assert!(!v6.applies("1.2.3.4".parse().unwrap(), 443));
        assert!(v6.applies("::1".parse().unwrap(), 443));
        assert!(
            !r.applies("1.2.3.4".parse().unwrap(), 53),
            "к DNS — без шума"
        );
        for bad in [
            "type='rand'\npacket='0-5'",
            "type='rand'\npacket='10-5000'",
            "type='zzz'\npacket='x'",
            "type='hex'\npacket='zz'",
            "type='str'\npacket='x'\ndelay=5000",
            "type='str'\npacket='x'\napply_to='mars'",
        ] {
            assert!(n(bad).is_err(), "{bad}");
        }
    }
}
