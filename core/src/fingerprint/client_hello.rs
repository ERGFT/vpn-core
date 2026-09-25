//! Разбор сырых байт TLS ClientHello — то, что реально ушло в сеть, а не
//! то, что мы думаем, что отправили. Отдельно от rustls: сама rustls эти
//! байты нам не отдаёт (см. `PLAN.md`, Этап 3), поэтому мы их перехватываем
//! на уровне сокета (`capture.rs`) и разбираем здесь заново, вручную.
//!
//! Минимально необходимый парсер для JA3/JA4 — не полноценный TLS-стек:
//! не проверяет крипто, не валидирует сертификаты, просто читает поля.
//! Всё чтение — через `Cursor` с проверкой границ: на входе — недоверенные
//! байты с провода, паниковать на выходе за границы буфера нельзя.

use crate::error::{Error, Result};

const HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const CLIENT_HELLO_MSG_TYPE: u8 = 0x01;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const GROUP_X25519: u16 = 0x001d;
/// Гибридная постквантовая группа X25519MLKEM768 (см. PLAN.md, Этап 5) —
/// REALITY теперь всегда шлёт именно её, не голый X25519. Формат
/// key_share клиента для неё: `ML-KEM768 encapsulation key(1184) ||
/// X25519(32)` = 1216 байт (`draft-ietf-tls-ecdhe-mlkem-02` §4.1,
/// ML-KEM-часть первая для этой конкретной группы).
const GROUP_X25519MLKEM768: u16 = 0x11ec;
const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// `legacy_version` из тела ClientHello (не путать с реальной
    /// согласованной версией при TLS 1.3 — там она в расширении).
    pub legacy_version: u16,
    /// Значения из расширения `supported_versions` (0x002b), если оно
    /// было. Пусто, если расширения не было (типичный до-TLS1.3 клиент).
    pub supported_versions: Vec<u16>,
    /// Cipher suites в исходном порядке, как отправил клиент (включая
    /// GREASE — фильтрация GREASE делается уже в ja3/ja4, не здесь).
    pub cipher_suites: Vec<u16>,
    /// Типы расширений в исходном порядке (включая GREASE).
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub alpn: Vec<String>,
    /// Из расширения signature_algorithms (0x000d), в исходном порядке.
    pub signature_algorithms: Vec<u16>,
    pub sni: Option<String>,
    /// Сырые байты поля `legacy_session_id` (0-32 байта). Не входит в
    /// JA3/JA4 (оба фингерпринта его игнорируют), но нужен отдельно —
    /// Этап 5, спайк по REALITY: единственный способ убедиться, что
    /// байты, которые мы просим `rustls` отправить как SessionId, реально
    /// оказались на проводе, а не были переписаны/проигнорированы.
    pub session_id: Vec<u8>,
    /// Поле `random` (32 байта) — тоже не для JA3/JA4, а для проверки
    /// REALITY: и AuthKey, и AAD, и nonce AES-GCM зависят именно от него
    /// (см. `reality/hook.rs`), так что независимая проверка на проводе
    /// обязана видеть те же байты, что клиент реально использовал.
    pub random: [u8; 32],
    /// 32-байтный X25519-компонент из расширения `key_share` (0x0033) —
    /// либо голая группа 0x001d целиком, либо (в приоритете, если есть)
    /// последние 32 байта гибридной группы X25519MLKEM768 (0x11ec, см.
    /// [`GROUP_X25519MLKEM768`]), которую REALITY теперь отправляет
    /// всегда (см. PLAN.md, Этап 5). Нужен по той же причине, что и
    /// `random`: REALITY переиспользует этот ключ для AuthKey ECDH с
    /// REALITY-сервером, независимая проверка должна видеть тот же ключ,
    /// что ушёл на провод — ML-KEM-часть для AuthKey не нужна и здесь не
    /// хранится.
    pub key_share_x25519: Option<[u8; 32]>,
    /// Группы (`NamedGroup`) в исходном порядке из расширения `key_share`
    /// (0x0033) — включая GREASE-запись, если она есть (Этап 3). В
    /// отличие от `key_share_x25519` выше, здесь не пытаемся
    /// интерпретировать полезную нагрузку, просто список идентификаторов
    /// групп как они пришли на проводе — нужно, чтобы независимо от
    /// внутренней логики патча rustls проверить на сырых байтах, что
    /// GREASE-группа в key_share действительно совпадает с той, что
    /// заявлена в `elliptic_curves` (supported_groups), как у настоящего
    /// Chrome.
    pub key_share_groups: Vec<u16>,
    /// GREASE-расширения (RFC 8701) — тип и сырое тело, в порядке
    /// появления. У Chrome их ровно два: первое в списке с пустым телом и
    /// последнее (перед PSK, если оно есть) с телом `[0]` — нужно, чтобы
    /// проверить на проводе и тип, и тело, а не только факт наличия.
    pub grease_extensions: Vec<(u16, Vec<u8>)>,
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| Error::Protocol("ClientHello: неожиданный конец данных".into()))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }

    fn u24(&mut self) -> Result<u32> {
        let a = self.u8()? as u32;
        let b = self.u8()? as u32;
        let c = self.u8()? as u32;
        Ok((a << 16) | (b << 8) | c)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Protocol(format!(
                "ClientHello: нужно {n} байт, доступно {}",
                self.remaining()
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// Разобрать полный TLS-рекорд (начинается с байта типа контента 0x16)
/// с ClientHello внутри. Поддерживает только случай, когда весь
/// handshake-месседж уместился в один TLS-рекорд — почти всегда так и
/// есть для ClientHello (даже с десятками расширений он обычно < 16 КБ).
pub fn parse_record(bytes: &[u8]) -> Result<ClientHelloInfo> {
    let mut c = Cursor::new(bytes);
    let content_type = c.u8()?;
    if content_type != HANDSHAKE_CONTENT_TYPE {
        return Err(Error::Protocol(format!(
            "ожидался TLS-рекорд типа Handshake (0x16), получено {content_type:#04x}"
        )));
    }
    let _legacy_record_version = c.u16()?;
    let record_len = c.u16()? as usize;
    let body = c.take(record_len)?;
    parse_handshake_body(body)
}

/// Разобрать тело handshake-сообщения (начинается с байта типа 0x01 —
/// ClientHello, затем 3-байтная длина). Отдельно от [`parse_record`] —
/// удобно для тестов, которым не нужно собирать внешний TLS-рекорд.
pub fn parse_handshake_body(bytes: &[u8]) -> Result<ClientHelloInfo> {
    let mut c = Cursor::new(bytes);
    let msg_type = c.u8()?;
    if msg_type != CLIENT_HELLO_MSG_TYPE {
        return Err(Error::Protocol(format!(
            "ожидался ClientHello (0x01), получено {msg_type:#04x}"
        )));
    }
    let body_len = c.u24()? as usize;
    let body = c.take(body_len)?;
    parse_client_hello_fields(body)
}

fn parse_client_hello_fields(bytes: &[u8]) -> Result<ClientHelloInfo> {
    let mut c = Cursor::new(bytes);

    let legacy_version = c.u16()?;
    let mut info = ClientHelloInfo {
        legacy_version,
        ..Default::default()
    };
    info.random.copy_from_slice(c.take(32)?); // не нужен для JA3/JA4, нужен для REALITY (см. поле)

    let session_id_len = c.u8()? as usize;
    info.session_id = c.take(session_id_len)?.to_vec();

    let cs_len = c.u16()? as usize;
    let cs_bytes = c.take(cs_len)?;
    let mut csc = Cursor::new(cs_bytes);
    while csc.remaining() > 0 {
        info.cipher_suites.push(csc.u16()?);
    }

    let comp_len = c.u8()? as usize;
    c.take(comp_len)?;

    // Расширений может не быть вообще (ClientHello без них синтаксически
    // валиден), тогда дальше в буфере просто ничего не остаётся.
    if c.remaining() == 0 {
        return Ok(info);
    }

    let ext_total_len = c.u16()? as usize;
    let ext_bytes = c.take(ext_total_len)?;
    let mut ec = Cursor::new(ext_bytes);

    while ec.remaining() > 0 {
        let ext_type = ec.u16()?;
        let ext_len = ec.u16()? as usize;
        let data = ec.take(ext_len)?;
        info.extensions.push(ext_type);
        if is_grease(ext_type) {
            info.grease_extensions.push((ext_type, data.to_vec()));
        }

        match ext_type {
            EXT_SERVER_NAME => {
                if let Some(name) = parse_sni(data)? {
                    info.sni = Some(name);
                }
            }
            EXT_SUPPORTED_GROUPS => {
                let mut dc = Cursor::new(data);
                let list_len = dc.u16()? as usize;
                let list = dc.take(list_len)?;
                let mut lc = Cursor::new(list);
                while lc.remaining() > 0 {
                    info.elliptic_curves.push(lc.u16()?);
                }
            }
            EXT_EC_POINT_FORMATS => {
                let mut dc = Cursor::new(data);
                let list_len = dc.u8()? as usize;
                let list = dc.take(list_len)?;
                info.ec_point_formats.extend_from_slice(list);
            }
            EXT_ALPN => {
                let mut dc = Cursor::new(data);
                let list_len = dc.u16()? as usize;
                let list = dc.take(list_len)?;
                let mut lc = Cursor::new(list);
                while lc.remaining() > 0 {
                    let proto_len = lc.u8()? as usize;
                    let proto = lc.take(proto_len)?;
                    info.alpn.push(String::from_utf8_lossy(proto).into_owned());
                }
            }
            EXT_SIGNATURE_ALGORITHMS => {
                let mut dc = Cursor::new(data);
                let list_len = dc.u16()? as usize;
                let list = dc.take(list_len)?;
                let mut lc = Cursor::new(list);
                while lc.remaining() > 0 {
                    info.signature_algorithms.push(lc.u16()?);
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                // В ClientHello (в отличие от ServerHello) у этого
                // расширения впереди 1-байтная длина списка, не 2.
                let mut dc = Cursor::new(data);
                let list_len = dc.u8()? as usize;
                let list = dc.take(list_len)?;
                let mut lc = Cursor::new(list);
                while lc.remaining() > 0 {
                    info.supported_versions.push(lc.u16()?);
                }
            }
            EXT_KEY_SHARE => {
                let mut dc = Cursor::new(data);
                let list_len = dc.u16()? as usize;
                let list = dc.take(list_len)?;
                let mut lc = Cursor::new(list);
                while lc.remaining() > 0 {
                    let group = lc.u16()?;
                    let ke_len = lc.u16()? as usize;
                    let ke = lc.take(ke_len)?;
                    info.key_share_groups.push(group);
                    if group == GROUP_X25519MLKEM768 && ke.len() > MLKEM768_ENCAPSULATION_KEY_LEN {
                        // X25519 — последние 32 байта гибридного
                        // key_share (ML-KEM768 encapsulation key идёт
                        // первым для этой группы). Предпочитаем эту
                        // ветку голому X25519 ниже, если обе почему-то
                        // присутствуют — совпадает с тем, что реально
                        // использует REALITY при активном хуке.
                        if let Some(tail) = ke.get(MLKEM768_ENCAPSULATION_KEY_LEN..) {
                            if let Ok(k) = <[u8; 32]>::try_from(tail) {
                                info.key_share_x25519 = Some(k);
                            }
                        }
                    } else if group == GROUP_X25519
                        && ke.len() == 32
                        && info.key_share_x25519.is_none()
                    {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(ke);
                        info.key_share_x25519 = Some(k);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(info)
}

fn parse_sni(data: &[u8]) -> Result<Option<String>> {
    let mut c = Cursor::new(data);
    if c.remaining() == 0 {
        return Ok(None);
    }
    let list_len = c.u16()? as usize;
    let list = c.take(list_len)?;
    let mut lc = Cursor::new(list);
    while lc.remaining() > 0 {
        let name_type = lc.u8()?;
        let name_len = lc.u16()? as usize;
        let name = lc.take(name_len)?;
        if name_type == 0x00 {
            return Ok(Some(String::from_utf8_lossy(name).into_owned()));
        }
    }
    Ok(None)
}

/// GREASE-значения (RFC 8701): байты вида `0xJA` повторно, 16 штук
/// (`0x0A0A, 0x1A1A, ..., 0xFAFA`). Браузеры вставляют их в cipher
/// suites/extensions/groups/versions как "случайный шум", чтобы серверы
/// не полагались на закрытый список значений — фингерпринты обязаны их
/// игнорировать, иначе "фингерпринт" Chrome менялся бы на каждом соединении.
pub fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16be(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    /// Собрать синтетический, но синтаксически корректный ClientHello
    /// (без внешнего TLS-рекорда) с известными полями — чтобы проверить
    /// парсер независимо от реального захвата с провода.
    fn build_synthetic_client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&u16be(0x0303)); // legacy_version = TLS1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len = 0

        let ciphers: [u16; 3] = [0x1301, 0x0a0a /* GREASE */, 0xc02b];
        body.extend_from_slice(&u16be((ciphers.len() * 2) as u16));
        for c in ciphers {
            body.extend_from_slice(&u16be(c));
        }

        body.push(1); // compression methods len
        body.push(0); // "null" compression

        let mut exts = Vec::new();

        // SNI
        {
            let host = b"example.com";
            let mut sni_list = Vec::new();
            sni_list.push(0x00); // name_type = host_name
            sni_list.extend_from_slice(&u16be(host.len() as u16));
            sni_list.extend_from_slice(host);
            let mut sni_ext_data = Vec::new();
            sni_ext_data.extend_from_slice(&u16be(sni_list.len() as u16));
            sni_ext_data.extend_from_slice(&sni_list);
            exts.extend_from_slice(&u16be(0x0000));
            exts.extend_from_slice(&u16be(sni_ext_data.len() as u16));
            exts.extend_from_slice(&sni_ext_data);
        }

        // supported_groups
        {
            let groups: [u16; 2] = [0x001d, 0x0017];
            let mut data = Vec::new();
            data.extend_from_slice(&u16be((groups.len() * 2) as u16));
            for g in groups {
                data.extend_from_slice(&u16be(g));
            }
            exts.extend_from_slice(&u16be(0x000a));
            exts.extend_from_slice(&u16be(data.len() as u16));
            exts.extend_from_slice(&data);
        }

        // ALPN: "h2"
        {
            let proto = b"h2";
            let mut list = Vec::new();
            list.push(proto.len() as u8);
            list.extend_from_slice(proto);
            let mut data = Vec::new();
            data.extend_from_slice(&u16be(list.len() as u16));
            data.extend_from_slice(&list);
            exts.extend_from_slice(&u16be(0x0010));
            exts.extend_from_slice(&u16be(data.len() as u16));
            exts.extend_from_slice(&data);
        }

        // supported_versions: TLS 1.3
        {
            let versions: [u16; 1] = [0x0304];
            let mut data = Vec::new();
            data.push((versions.len() * 2) as u8);
            for v in versions {
                data.extend_from_slice(&u16be(v));
            }
            exts.extend_from_slice(&u16be(0x002b));
            exts.extend_from_slice(&u16be(data.len() as u16));
            exts.extend_from_slice(&data);
        }

        body.extend_from_slice(&u16be(exts.len() as u16));
        body.extend_from_slice(&exts);

        let mut msg = Vec::new();
        msg.push(0x01); // ClientHello
        let len = body.len() as u32;
        msg.push((len >> 16) as u8);
        msg.push((len >> 8) as u8);
        msg.push(len as u8);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn parses_synthetic_client_hello() {
        let msg = build_synthetic_client_hello();
        let info = parse_handshake_body(&msg).unwrap();

        assert_eq!(info.legacy_version, 0x0303);
        assert_eq!(info.cipher_suites, vec![0x1301, 0x0a0a, 0xc02b]);
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert_eq!(info.elliptic_curves, vec![0x001d, 0x0017]);
        assert_eq!(info.alpn, vec!["h2".to_string()]);
        assert_eq!(info.supported_versions, vec![0x0304]);
        assert!(info.extensions.contains(&0x0000));
        assert!(info.extensions.contains(&0x000a));
        assert!(info.extensions.contains(&0x0010));
        assert!(info.extensions.contains(&0x002b));
    }

    #[test]
    fn parses_full_record_wrapper() {
        let msg = build_synthetic_client_hello();
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&u16be(0x0301)); // legacy record version
        record.extend_from_slice(&u16be(msg.len() as u16));
        record.extend_from_slice(&msg);

        let info = parse_record(&record).unwrap();
        assert_eq!(info.legacy_version, 0x0303);
    }

    #[test]
    fn grease_detection() {
        for v in [
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
            0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ] {
            assert!(is_grease(v), "{v:#06x} должен быть GREASE");
        }
        for v in [0x1301u16, 0xc02b, 0x0303, 0x002b] {
            assert!(!is_grease(v), "{v:#06x} не должен быть GREASE");
        }
    }

    #[test]
    fn rejects_truncated_input() {
        let err = parse_record(&[0x16, 0x03, 0x01]).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    /// Минимальный ClientHello с ровно одним расширением — key_share, из
    /// заданных (group, key_exchange) записей. Не переиспользует
    /// `build_synthetic_client_hello` (там свой, не связанный набор
    /// расширений) — здесь важен только key_share.
    fn build_client_hello_with_key_share(entries: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&u16be(0x0303));
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session_id len
        body.extend_from_slice(&u16be(2));
        body.extend_from_slice(&u16be(0x1301));
        body.push(1);
        body.push(0);

        let mut list = Vec::new();
        for (group, ke) in entries {
            list.extend_from_slice(&u16be(*group));
            list.extend_from_slice(&u16be(ke.len() as u16));
            list.extend_from_slice(ke);
        }
        let mut ext_data = Vec::new();
        ext_data.extend_from_slice(&u16be(list.len() as u16));
        ext_data.extend_from_slice(&list);

        let mut exts = Vec::new();
        exts.extend_from_slice(&u16be(EXT_KEY_SHARE));
        exts.extend_from_slice(&u16be(ext_data.len() as u16));
        exts.extend_from_slice(&ext_data);

        body.extend_from_slice(&u16be(exts.len() as u16));
        body.extend_from_slice(&exts);

        let mut msg = Vec::new();
        msg.push(0x01);
        let len = body.len() as u32;
        msg.push((len >> 16) as u8);
        msg.push((len >> 8) as u8);
        msg.push(len as u8);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn key_share_extracts_plain_x25519() {
        let x25519 = [0x11u8; 32];
        let msg = build_client_hello_with_key_share(&[(GROUP_X25519, &x25519)]);
        let info = parse_handshake_body(&msg).unwrap();
        assert_eq!(info.key_share_x25519, Some(x25519));
    }

    #[test]
    fn key_share_extracts_x25519_tail_from_hybrid_mlkem768() {
        // REALITY теперь всегда шлёт именно эту группу (см. PLAN.md, Этап
        // 5) — ML-KEM768 encapsulation key(1184, здесь просто заполнитель)
        // + X25519(32) = 1216 байт, X25519 последним.
        let mut hybrid = vec![0xAAu8; MLKEM768_ENCAPSULATION_KEY_LEN];
        let x25519 = [0x22u8; 32];
        hybrid.extend_from_slice(&x25519);
        let msg = build_client_hello_with_key_share(&[(GROUP_X25519MLKEM768, &hybrid)]);
        let info = parse_handshake_body(&msg).unwrap();
        assert_eq!(info.key_share_x25519, Some(x25519));
    }

    #[test]
    fn key_share_prefers_hybrid_x25519_over_plain_x25519_when_both_present() {
        let plain = [0x33u8; 32];
        let mut hybrid = vec![0xBBu8; MLKEM768_ENCAPSULATION_KEY_LEN];
        let hybrid_x25519 = [0x44u8; 32];
        hybrid.extend_from_slice(&hybrid_x25519);
        // Голый X25519 идёт ПЕРВЫМ в списке — проверяем, что гибрид всё
        // равно побеждает независимо от порядка записей.
        let msg = build_client_hello_with_key_share(&[
            (GROUP_X25519, &plain),
            (GROUP_X25519MLKEM768, &hybrid),
        ]);
        let info = parse_handshake_body(&msg).unwrap();
        assert_eq!(info.key_share_x25519, Some(hybrid_x25519));
    }
}
