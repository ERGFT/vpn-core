// SPDX-License-Identifier: GPL-3.0-or-later
//! Sniffing QUIC: домен из TLS ClientHello внутри Initial-пакетов
//! QUIC v1 (RFC 9000/9001) и v2 (RFC 9369) — для HTTP/3, который браузеры
//! шлют по UDP.
//!
//! Ключи Initial-пакетов выводятся из Destination Connection ID, который
//! клиент пишет открытым текстом (так устроен QUIC: эти ключи — не
//! секрет, они лишь защищают от случайных изменений в сети). Снимаем
//! защиту заголовка, расшифровываем AES-128-GCM, собираем CRYPTO-кадры по
//! смещениям и разбираем ClientHello тем же разбором, что для TCP.
//!
//! Chrome с ML-KEM кладёт ClientHello в два пакета и перемешивает
//! CRYPTO-кадры внутри пакета («chaos protection»), поэтому кусочки
//! собираются по смещению из нескольких датаграмм. Ничего не меняется:
//! датаграммы уходят дальше как есть.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes_gcm::aes::Aes128;
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::sniff::{parse_client_hello, Sniff};

const V1: u32 = 1;
const V2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
/// Больше CRYPTO-данных не собираем (ClientHello с ML-KEM — ~2 КиБ).
const MAX_CRYPTO: u64 = 16 * 1024;
/// Больше датаграмм не ждём: ClientHello обычно в одной-двух.
pub const MAX_DATAGRAMS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn expand_label(prk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    prk.expand(&info, out)
        .expect("длина вывода HKDF в пределах");
}

/// Ключи клиентских Initial-пакетов.
pub fn client_initial_keys(version: u32, dcid: &[u8]) -> Option<InitialKeys> {
    let (salt, prefix) = match version {
        V1 => (&SALT_V1, "quic"),
        V2 => (&SALT_V2, "quicv2"),
        _ => return None,
    };
    let (_, initial) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    let mut client = [0u8; 32];
    expand_label(&initial, "client in", &mut client);
    let c = Hkdf::<Sha256>::from_prk(&client).ok()?;
    let mut k = InitialKeys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    expand_label(&c, &format!("{prefix} key"), &mut k.key);
    expand_label(&c, &format!("{prefix} iv"), &mut k.iv);
    expand_label(&c, &format!("{prefix} hp"), &mut k.hp);
    Some(k)
}

fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let first = *b.get(*i)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(*i..*i + len)?;
    let mut v = u64::from(first & 0x3f);
    for &x in &bytes[1..] {
        v = (v << 8) | u64::from(x);
    }
    *i += len;
    Some(v)
}

/// Разбор одной датаграммы.
enum Packet {
    /// Не QUIC Initial поддерживаемой версии.
    NotQuic,
    /// Кусочки CRYPTO (смещение, данные).
    Crypto(Vec<(u64, Vec<u8>)>),
}

/// Собирает ClientHello из Initial-пакетов одного потока.
#[derive(Default)]
pub struct QuicSniffer {
    dcid: Option<(u32, Vec<u8>)>,
    keys: Option<InitialKeys>,
    frags: BTreeMap<u64, Vec<u8>>,
    datagrams: usize,
}

impl QuicSniffer {
    /// Первая датаграмма похожа на QUIC Initial (дешёвая проверка, без
    /// расшифровки).
    pub fn looks_like_initial(d: &[u8]) -> bool {
        d.len() >= 1200 - 64
            && d[0] & 0xc0 == 0xc0
            && match u32::from_be_bytes([d[1], d[2], d[3], d[4]]) {
                V1 => (d[0] >> 4) & 3 == 0,
                V2 => (d[0] >> 4) & 3 == 1,
                _ => false,
            }
    }

    /// Добавить датаграмму от клиента.
    pub fn push(&mut self, d: &[u8]) -> Sniff {
        self.datagrams += 1;
        let frags = match self.parse_datagram(d) {
            Packet::NotQuic => {
                // Первая не QUIC — значит, не QUIC; следующие (0-RTT и т.п.)
                // просто не дают ничего нового.
                return if self.dcid.is_none() {
                    Sniff::No
                } else {
                    self.more()
                };
            }
            Packet::Crypto(f) => f,
        };
        for (off, data) in frags {
            match off.checked_add(data.len() as u64) {
                Some(end) if end <= MAX_CRYPTO => {}
                _ => return Sniff::No,
            }
            let slot = self.frags.entry(off).or_default();
            if data.len() > slot.len() {
                *slot = data;
            }
        }
        match self.assembled() {
            Some(r) => r,
            None => self.more(),
        }
    }

    fn more(&self) -> Sniff {
        if self.datagrams >= MAX_DATAGRAMS {
            Sniff::No
        } else {
            Sniff::NeedMore
        }
    }

    /// Непрерывные данные с нуля → ClientHello, если он уже целиком.
    fn assembled(&self) -> Option<Sniff> {
        let mut buf: Vec<u8> = Vec::new();
        for (&off, data) in &self.frags {
            let off = off as usize;
            if off > buf.len() {
                break;
            }
            let end = off + data.len();
            if end > buf.len() {
                buf.extend_from_slice(&data[buf.len() - off..]);
            }
        }
        if buf.len() < 4 {
            return None;
        }
        if buf[0] != 1 {
            return Some(Sniff::No);
        }
        let need =
            4 + ((usize::from(buf[1]) << 16) | (usize::from(buf[2]) << 8) | usize::from(buf[3]));
        if need as u64 > MAX_CRYPTO {
            return Some(Sniff::No);
        }
        if buf.len() < need {
            return None;
        }
        Some(match parse_client_hello(&buf[..need]) {
            Some(Some(h)) => Sniff::Domain(h),
            _ => Sniff::No,
        })
    }

    fn parse_datagram(&mut self, mut d: &[u8]) -> Packet {
        let mut out = Vec::new();
        let mut any = false;
        while !d.is_empty() {
            let Some((consumed, frags)) = self.parse_packet(d) else {
                break;
            };
            if let Some(f) = frags {
                any = true;
                out.extend(f);
            }
            d = &d[consumed..];
        }
        if any {
            Packet::Crypto(out)
        } else {
            Packet::NotQuic
        }
    }

    /// Один пакет из датаграммы: сколько байт занял и CRYPTO-кусочки,
    /// если это расшифрованный Initial. `None` — дальше разбирать нечего.
    #[allow(clippy::type_complexity)]
    fn parse_packet(&mut self, p: &[u8]) -> Option<(usize, Option<Vec<(u64, Vec<u8>)>>)> {
        let b0 = *p.first()?;
        if b0 & 0x80 == 0 {
            return None; // короткий заголовок — Initial-пакетов дальше нет
        }
        let version = u32::from_be_bytes(p.get(1..5)?.try_into().ok()?);
        let initial_type = match version {
            V1 => 0,
            V2 => 1,
            _ => return None,
        };
        let ty = (b0 >> 4) & 3;
        let retry_type = if version == V1 { 3 } else { 0 };
        if ty == retry_type {
            return None;
        }
        let mut i = 5;
        let dcid_len = usize::from(*p.get(i)?);
        if dcid_len > 20 {
            return None;
        }
        let dcid = p.get(i + 1..i + 1 + dcid_len)?;
        i += 1 + dcid_len;
        let scid_len = usize::from(*p.get(i)?);
        if scid_len > 20 {
            return None;
        }
        i += 1 + scid_len;
        if ty == initial_type {
            let token = varint(p, &mut i)? as usize;
            i = i.checked_add(token)?;
        }
        let length = varint(p, &mut i)? as usize;
        let pn_offset = i;
        let end = pn_offset.checked_add(length)?;
        if end > p.len() || length < 4 + 16 + 1 {
            return None;
        }
        if ty != initial_type {
            return Some((end, None));
        }
        let fresh;
        let keys = match (&self.dcid, &self.keys) {
            (None, _) => {
                fresh = client_initial_keys(version, dcid)?;
                &fresh
            }
            (Some((v, id)), Some(k)) if *v == version && id == dcid => k,
            // Другой поток — не наш.
            _ => return Some((end, None)),
        };
        let got = decrypt(keys, &p[..end], pn_offset).and_then(|pl| frames(&pl));
        // Поток запоминается по первому пакету, который расшифровался.
        if got.is_some() && self.dcid.is_none() {
            self.keys = client_initial_keys(version, dcid);
            self.dcid = Some((version, dcid.to_vec()));
        }
        Some((end, got))
    }
}

/// Прочитать первые датаграммы UDP-потока (`r` отдаёт по датаграмме за
/// чтение) и, если это QUIC, найти домен. Прочитанное — в `pending`, его
/// нужно отправить дальше. Следующих датаграмм ждём не дольше
/// [`super::sniff::SNIFF_TIMEOUT`] в сумме; не QUIC — сразу `None`.
pub async fn read_and_sniff<R: AsyncRead + Unpin>(
    r: &mut R,
    pending: &mut Vec<Vec<u8>>,
) -> std::io::Result<Option<String>> {
    let mut buf = vec![0u8; 65535];
    let n = r.read(&mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    pending.push(buf[..n].to_vec());
    if !QuicSniffer::looks_like_initial(&buf[..n]) {
        return Ok(None);
    }
    let mut s = QuicSniffer::default();
    let mut verdict = s.push(&buf[..n]);
    let deadline = tokio::time::Instant::now() + super::sniff::SNIFF_TIMEOUT;
    loop {
        match verdict {
            Sniff::Domain(d) => return Ok(Some(d)),
            Sniff::No => return Ok(None),
            Sniff::NeedMore => {}
        }
        match tokio::time::timeout_at(deadline, r.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => return Ok(None),
            Ok(Ok(n)) => {
                pending.push(buf[..n].to_vec());
                verdict = s.push(&buf[..n]);
            }
            Ok(Err(e)) => return Err(e),
        }
    }
}

/// Снять защиту заголовка и расшифровать; вернуть открытые кадры.
fn decrypt(k: &InitialKeys, p: &[u8], pn_offset: usize) -> Option<Vec<u8>> {
    let sample = p.get(pn_offset + 4..pn_offset + 20)?;
    let mut mask = GenericArray::clone_from_slice(sample);
    Aes128::new(GenericArray::from_slice(&k.hp)).encrypt_block(&mut mask);
    let mut header = p[..pn_offset + 4].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(header[0] & 3) + 1;
    header.truncate(pn_offset + pn_len);
    let mut pn = 0u64;
    for j in 0..pn_len {
        header[pn_offset + j] ^= mask[1 + j];
        pn = (pn << 8) | u64::from(header[pn_offset + j]);
    }
    let mut nonce = k.iv;
    for (j, b) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + j] ^= b;
    }
    Aes128Gcm::new(GenericArray::from_slice(&k.key))
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &p[pn_offset + pn_len..],
                aad: &header,
            },
        )
        .ok()
}

/// CRYPTO-кадры из открытого Initial-пакета. Другие кадры, допустимые в
/// Initial, пропускаются; недопустимый — пакет не разбирается.
fn frames(pl: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < pl.len() {
        match varint(pl, &mut i)? {
            0x00 | 0x01 => {} // PADDING, PING
            t @ (0x02 | 0x03) => {
                // ACK: largest, delay, число диапазонов, первый, пары.
                varint(pl, &mut i)?;
                varint(pl, &mut i)?;
                let n = varint(pl, &mut i)?;
                varint(pl, &mut i)?;
                if n > pl.len() as u64 {
                    return None;
                }
                for _ in 0..n * 2 {
                    varint(pl, &mut i)?;
                }
                if t == 0x03 {
                    for _ in 0..3 {
                        varint(pl, &mut i)?;
                    }
                }
            }
            0x06 => {
                let off = varint(pl, &mut i)?;
                let len = varint(pl, &mut i)? as usize;
                let data = pl.get(i..i.checked_add(len)?)?;
                i += len;
                out.push((off, data.to_vec()));
            }
            0x1c => return Some(out), // CONNECTION_CLOSE
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        hex::decode(s).unwrap()
    }

    #[test]
    fn initial_keys_match_rfc_vectors() {
        let dcid = unhex("8394c8f03e515708");
        // RFC 9001, приложение A.1.
        let k = client_initial_keys(V1, &dcid).unwrap();
        assert_eq!(k.key.to_vec(), unhex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv.to_vec(), unhex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(k.hp.to_vec(), unhex("9f50449e04a0e810283a1e9933adedd2"));
        // RFC 9369, приложение A.1 (QUIC v2).
        let k = client_initial_keys(V2, &dcid).unwrap();
        assert_eq!(k.key.to_vec(), unhex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(k.iv.to_vec(), unhex("91f73e2351d8fa91660e909f"));
        assert!(client_initial_keys(0xff00_001d, &dcid).is_none());
    }

    /// Защищённый Initial-пакет клиента из RFC 9001, приложение A.2
    /// (ClientHello для example.com).
    const RFC9001_CLIENT_INITIAL: &str = include_str!("testdata/rfc9001_client_initial.hex");

    #[test]
    fn rfc9001_client_initial() {
        let pkt = unhex(RFC9001_CLIENT_INITIAL);
        assert_eq!(pkt.len(), 1200);
        assert!(QuicSniffer::looks_like_initial(&pkt));
        let mut s = QuicSniffer::default();
        assert_eq!(s.push(&pkt), Sniff::Domain("example.com".into()));

        // Повреждённый пакет не расшифровывается — «не QUIC».
        let mut bad = pkt.clone();
        bad[600] ^= 1;
        assert_eq!(QuicSniffer::default().push(&bad), Sniff::No);
        // Не QUIC вовсе.
        assert_eq!(QuicSniffer::default().push(b"\x16\x03\x01hello"), Sniff::No);
        assert!(!QuicSniffer::looks_like_initial(b"\x00\x01"));
    }

    /// Собрать Initial-пакет v1 из открытых кадров (обратная операция
    /// к разбору — для проверки сборки ClientHello из нескольких пакетов).
    fn protect(dcid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
        let k = client_initial_keys(V1, dcid).unwrap();
        let mut payload = frames.to_vec();
        if payload.len() < 1100 {
            payload.resize(1100, 0); // PADDING до ~1200 байт
        }
        let mut hdr = vec![0xc3];
        hdr.extend_from_slice(&V1.to_be_bytes());
        hdr.push(dcid.len() as u8);
        hdr.extend_from_slice(dcid);
        hdr.push(0); // SCID
        hdr.push(0); // токен
        let len = (4 + payload.len() + 16) as u16 | 0x4000;
        hdr.extend_from_slice(&len.to_be_bytes());
        let pn_offset = hdr.len();
        hdr.extend_from_slice(&pn.to_be_bytes());
        let mut nonce = k.iv;
        for (j, b) in u64::from(pn).to_be_bytes().iter().enumerate() {
            nonce[4 + j] ^= b;
        }
        let ct = Aes128Gcm::new(GenericArray::from_slice(&k.key))
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: &hdr,
                },
            )
            .unwrap();
        let mut pkt = hdr;
        pkt.extend_from_slice(&ct);
        let mut mask = GenericArray::clone_from_slice(&pkt[pn_offset + 4..pn_offset + 20]);
        Aes128::new(GenericArray::from_slice(&k.hp)).encrypt_block(&mut mask);
        pkt[0] ^= mask[0] & 0x0f;
        for j in 0..4 {
            pkt[pn_offset + j] ^= mask[1 + j];
        }
        pkt
    }

    fn crypto(off: u64, data: &[u8]) -> Vec<u8> {
        let mut f = vec![
            0x06,
            0x80 | (off >> 24) as u8,
            (off >> 16) as u8,
            (off >> 8) as u8,
            off as u8,
        ];
        f.extend_from_slice(&[0x40 | (data.len() >> 8) as u8, data.len() as u8]);
        f.extend_from_slice(data);
        f
    }

    fn client_hello(host: &str, pad: usize) -> Vec<u8> {
        let rec = crate::app::sniff::tests::client_hello(host);
        // Без TLS-записи; раздуть расширением padding, как ML-KEM у Chrome.
        let mut hs = rec[5..].to_vec();
        let body_len = hs.len() - 4 + 4 + pad;
        let ext_at = 4 + 2 + 32 + 1 + 2 + 2 + 2;
        let ext_len = u16::from_be_bytes([hs[ext_at], hs[ext_at + 1]]) as usize + 4 + pad;
        hs[ext_at..ext_at + 2].copy_from_slice(&(ext_len as u16).to_be_bytes());
        hs.extend_from_slice(&[0x00, 0x15]);
        hs.extend_from_slice(&(pad as u16).to_be_bytes());
        hs.extend(std::iter::repeat_n(0, pad));
        hs[1..4].copy_from_slice(&(body_len as u32).to_be_bytes()[1..]);
        hs
    }

    #[test]
    fn two_packets_shuffled_frames() {
        let dcid = [7u8; 8];
        let ch = client_hello("www.youtube.com", 1500);
        assert!(ch.len() > 1500);
        // Первый пакет: кусочки вразброс с PING и PADDING между ними.
        let mut f1 = Vec::new();
        f1.extend(crypto(600, &ch[600..900]));
        f1.push(0x01);
        f1.extend(crypto(0, &ch[..300]));
        f1.extend([0, 0, 0]);
        f1.extend(crypto(300, &ch[300..600]));
        // Второй — остальное, с перекрытием.
        let f2 = crypto(850, &ch[850..]);
        let p1 = protect(&dcid, 0, &f1);
        let p2 = protect(&dcid, 1, &f2);
        let mut s = QuicSniffer::default();
        assert_eq!(s.push(&p1), Sniff::NeedMore);
        assert_eq!(s.push(&p2), Sniff::Domain("www.youtube.com".into()));

        // Порядок пакетов не важен.
        let mut s = QuicSniffer::default();
        assert_eq!(s.push(&p2), Sniff::NeedMore);
        assert_eq!(s.push(&p1), Sniff::Domain("www.youtube.com".into()));

        // Два пакета в одной датаграмме (coalesced).
        let mut both = p1.clone();
        both.extend_from_slice(&p2);
        assert_eq!(
            QuicSniffer::default().push(&both),
            Sniff::Domain("www.youtube.com".into())
        );

        // Недостающий кусок: сдаёмся после MAX_DATAGRAMS.
        let mut s = QuicSniffer::default();
        let mut last = Sniff::NeedMore;
        for _ in 0..MAX_DATAGRAMS {
            last = s.push(&p2);
        }
        assert_eq!(last, Sniff::No);

        // Смещение за пределом — отказ, а не выделение памяти.
        let far = protect(&dcid, 2, &crypto(MAX_CRYPTO, b"x"));
        assert_eq!(QuicSniffer::default().push(&far), Sniff::No);
    }

    #[tokio::test]
    async fn reads_flow_and_keeps_datagrams() {
        let dcid = [9u8; 8];
        let ch = client_hello("a.example", 1500);
        let p1 = protect(&dcid, 0, &crypto(0, &ch[..800]));
        let p2 = protect(&dcid, 1, &crypto(800, &ch[800..]));
        // Датаграммы по одной за чтение, как у потока ipstack.
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let mut pending = Vec::new();
        let (p1c, p2c) = (p1.clone(), p2.clone());
        let w = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            b.write_all(&p1c).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            b.write_all(&p2c).await.unwrap();
            b
        });
        let d = read_and_sniff(&mut a, &mut pending).await.unwrap();
        assert_eq!(d.as_deref(), Some("a.example"));
        assert_eq!(pending, vec![p1, p2]);
        drop(w.await.unwrap());

        // Не QUIC: одна датаграмма, без ожидания.
        let (mut a, mut b) = tokio::io::duplex(1024);
        tokio::io::AsyncWriteExt::write_all(&mut b, b"dns?")
            .await
            .unwrap();
        let mut pending = Vec::new();
        let t = std::time::Instant::now();
        assert_eq!(read_and_sniff(&mut a, &mut pending).await.unwrap(), None);
        assert!(t.elapsed() < std::time::Duration::from_millis(100));
        assert_eq!(pending, vec![b"dns?".to_vec()]);

        // Половина ClientHello и тишина — таймаут, датаграмма сохранена.
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let p1 = protect(&dcid, 0, &crypto(0, &ch[..800]));
        tokio::io::AsyncWriteExt::write_all(&mut b, &p1)
            .await
            .unwrap();
        let mut pending = Vec::new();
        assert_eq!(read_and_sniff(&mut a, &mut pending).await.unwrap(), None);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn garbage_never_panics() {
        let pkt = unhex(RFC9001_CLIENT_INITIAL);
        let mut seed = 0x1234_5678u32;
        for n in 0..3000 {
            let mut v = pkt.clone();
            for _ in 0..(n % 7 + 1) {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let at = seed as usize % v.len();
                v[at] = (seed >> 8) as u8;
            }
            v.truncate(seed as usize % (v.len() + 1));
            let _ = QuicSniffer::default().push(&v);
        }
        for n in 0..64 {
            let _ = varint(&vec![0xff; n], &mut 0);
            let _ = frames(&vec![0x02; n]);
            let _ = frames(&vec![0x06; n]);
        }
    }
}

#[cfg(test)]
mod chrome_tests {
    use super::*;

    /// Настоящие первые датаграммы Chromium 140 (headless, ML-KEM в
    /// ClientHello, chaos protection) к www.example.test — сняты
    /// скриптом scripts/capture_chrome_quic.sh.
    const CHROME: &str = include_str!("testdata/chromium140_quic_initial.hex");

    #[test]
    fn real_chromium_initial() {
        let dgrams: Vec<Vec<u8>> = CHROME
            .lines()
            .map(|l| hex::decode(l.trim()).unwrap())
            .collect();
        assert!(QuicSniffer::looks_like_initial(&dgrams[0]));
        let mut s = QuicSniffer::default();
        let mut got = None;
        for (i, d) in dgrams.iter().enumerate() {
            match s.push(d) {
                Sniff::Domain(h) => {
                    got = Some((i + 1, h));
                    break;
                }
                Sniff::NeedMore => {}
                Sniff::No => panic!("датаграмма {}: не разобрано", i + 1),
            }
        }
        let (n, host) = got.expect("домен не найден");
        eprintln!("Chromium: домен найден после {n} датаграмм");
        assert_eq!(host, "www.example.test");
    }
}
