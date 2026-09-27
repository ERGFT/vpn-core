//! Вышестоящие DNS-серверы: обычный UDP и TCP, DNS over TLS (DoT),
//! DNS over HTTPS (DoH), DNS over QUIC (DoQ, RFC 9250), системный резолвер. Запросы к серверу идут через
//! выбранный выход (`detour`): через VLESS-сервер (`proxy`) — тогда ни
//! провайдер, ни соседи по Wi-Fi не видят, какие имена спрашиваются, —
//! или напрямую (`direct`).
//!
//! Каждый ответ проверяется: номер запроса, флаг ответа и сам вопрос
//! (имя и тип) должны совпасть — иначе ответ отбрасывается (защита от
//! подмены по UDP).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

use crate::app::outbound::{Outbound, UdpSession};
use crate::app::{Metadata, Network};
use crate::error::{Error, Result};
use crate::transport::{quic, AsyncStream};
use crate::vless::Address;

/// Метка входа в `Metadata` для запросов самого DNS-модуля: по ней выход
/// `direct` разрешает имя DNS-сервера системным резолвером, а не этим же
/// модулем (иначе — бесконечная петля).
pub const DNS_INTERNAL: &str = "dns-internal";

/// Сколько ждать ответа на одну попытку по UDP; попыток две.
const UDP_ATTEMPT: Duration = Duration::from_millis(2500);
/// Потолок на весь обмен по TCP/TLS/HTTPS (с установкой соединения).
const STREAM_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_MESSAGE: usize = 65535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Udp,
    Tcp,
    Tls,
    Https {
        path: String,
    },
    /// DNS over QUIC (RFC 9250): `quic://dns.adguard-dns.com`.
    Quic,
    Local,
    FakeIp,
}

/// Разобрать адрес сервера: `1.1.1.1`, `udp://1.1.1.1:53`,
/// `tcp://1.1.1.1`, `tls://dns.google`, `https://1.1.1.1/dns-query`,
/// `local`, `fakeip`.
pub fn parse_address(s: &str) -> Result<(Kind, Address, u16)> {
    let bad = |why: &str| Error::Config(format!("адрес DNS-сервера «{s}»: {why}"));
    let s = s.trim();
    match s {
        "local" => return Ok((Kind::Local, Address::Domain("local".into()), 0)),
        "fakeip" => return Ok((Kind::FakeIp, Address::Domain("fakeip".into()), 0)),
        _ => {}
    }
    let (scheme, rest) = match s.split_once("://") {
        Some((sc, r)) => (sc.to_ascii_lowercase(), r),
        None => ("udp".to_string(), s),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (kind, default_port) = match scheme.as_str() {
        "udp" => (Kind::Udp, 53),
        "tcp" => (Kind::Tcp, 53),
        "tls" => (Kind::Tls, 853),
        "quic" => (Kind::Quic, 853),
        "https" => (
            Kind::Https {
                path: if path.is_empty() {
                    "/dns-query".into()
                } else {
                    path.to_string()
                },
            },
            443,
        ),
        _ => return Err(bad("схема должна быть udp, tcp, tls, https или quic")),
    };
    if !path.is_empty() && !matches!(kind, Kind::Https { .. }) {
        return Err(bad("путь бывает только у https://"));
    }
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let (h, tail) = r.split_once(']').ok_or_else(|| bad("нет ']'"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| bad("неверный порт"))?,
            None if tail.is_empty() => default_port,
            None => return Err(bad("мусор после адреса")),
        };
        (h, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, p.parse().map_err(|_| bad("неверный порт"))?),
            _ => (authority, default_port),
        }
    };
    if host.is_empty() {
        return Err(bad("пустой адрес"));
    }
    let addr = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Address::Ipv4(v4),
        Ok(IpAddr::V6(v6)) => Address::Ipv6(v6),
        Err(_) => {
            if matches!(kind, Kind::Udp | Kind::Tcp) {
                return Err(bad(
                    "для udp:// и tcp:// нужен IP-адрес (имя самого DNS-сервера нечем разрешить)",
                ));
            }
            Address::Domain(host.to_ascii_lowercase())
        }
    };
    Ok((kind, addr, port))
}

/// Ответ на тот ли вопрос.
fn check_answer(query: &Message, answer: &Message) -> Result<()> {
    if answer.metadata.message_type != MessageType::Response {
        return Err(Error::Protocol("DNS: пришёл не ответ".into()));
    }
    let q = query.queries.first();
    let a = answer.queries.first();
    match (q, a) {
        (Some(q), Some(a))
            if q.query_type() == a.query_type()
                && q.name()
                    .to_ascii()
                    .eq_ignore_ascii_case(&a.name().to_ascii()) =>
        {
            Ok(())
        }
        // Некоторые серверы в ответе с ошибкой вопрос не повторяют.
        (Some(_), None) if answer.metadata.response_code != ResponseCode::NoError => Ok(()),
        _ => Err(Error::Protocol("DNS: ответ не на тот вопрос".into())),
    }
}

fn encode(msg: &Message) -> Result<Vec<u8>> {
    msg.to_vec()
        .map_err(|e| Error::Protocol(format!("DNS: не удалось собрать запрос: {e}")))
}

fn decode(b: &[u8]) -> Result<Message> {
    Message::from_vec(b).map_err(|e| Error::Protocol(format!("DNS: битый ответ: {e}")))
}

/// Общая UDP-сессия с сервером: ответы раздаются ожидающим запросам по
/// номеру.
struct UdpClient {
    session: Arc<dyn UdpSession>,
    pending: Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>,
    closed: AtomicBool,
}

async fn read_framed<S: AsyncStream + ?Sized>(s: &mut S) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_framed<S: AsyncStream + ?Sized>(s: &mut S, msg: &[u8]) -> Result<()> {
    let mut v = Vec::with_capacity(msg.len() + 2);
    v.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    v.extend_from_slice(msg);
    s.write_all(&v).await?;
    s.flush().await?;
    Ok(())
}

type TlsConn = tokio_rustls::client::TlsStream<Box<dyn AsyncStream>>;

pub struct Upstream {
    pub tag: String,
    pub kind: Kind,
    host: Address,
    port: u16,
    detour: Option<Arc<dyn Outbound>>,
    roots: Option<rustls::RootCertStore>,
    udp: tokio::sync::Mutex<Option<Arc<UdpClient>>>,
    tls_pool: Mutex<Vec<TlsConn>>,
    h2: tokio::sync::Mutex<Option<h2::client::SendRequest<Bytes>>>,
    quic: tokio::sync::Mutex<Option<(quinn::Endpoint, quinn::Connection)>>,
}

impl Upstream {
    pub fn new(
        tag: String,
        address: &str,
        detour: Option<Arc<dyn Outbound>>,
        roots: Option<rustls::RootCertStore>,
    ) -> Result<Self> {
        let (kind, host, port) = parse_address(address)?;
        let needs_detour = !matches!(kind, Kind::Local | Kind::FakeIp);
        if needs_detour && detour.is_none() {
            return Err(Error::Config(format!(
                "DNS-сервер {tag}: не задан выход (detour)"
            )));
        }
        Ok(Upstream {
            tag,
            kind,
            host,
            port,
            detour: if needs_detour { detour } else { None },
            roots,
            udp: tokio::sync::Mutex::new(None),
            tls_pool: Mutex::new(Vec::new()),
            h2: tokio::sync::Mutex::new(None),
            quic: tokio::sync::Mutex::new(None),
        })
    }

    /// Имя сервера, если он задан именем (не IP): `tls://dns.google`.
    pub fn host_name(&self) -> Option<(String, u16)> {
        match &self.host {
            Address::Domain(d) if !matches!(self.kind, Kind::Local | Kind::FakeIp) => {
                Some((d.clone(), self.port))
            }
            _ => None,
        }
    }

    pub fn is_fake(&self) -> bool {
        self.kind == Kind::FakeIp
    }

    /// Имя для TLS: домен или IP (у сертификата должен быть такой SAN).
    fn tls_name(&self) -> String {
        match &self.host {
            Address::Domain(d) => d.clone(),
            Address::Ipv4(v4) => v4.to_string(),
            Address::Ipv6(v6) => v6.to_string(),
        }
    }

    fn meta(&self, network: Network) -> Metadata {
        Metadata {
            inbound: DNS_INTERNAL.into(),
            source: SocketAddr::from(([127, 0, 0, 1], 0)),
            network,
            target: self.host.clone(),
            port: self.port,
            sniffed: None,
        }
    }

    fn detour(&self) -> &Arc<dyn Outbound> {
        self.detour.as_ref().expect("проверено при создании")
    }

    /// Отправить запрос и получить проверенный ответ (номер — как в
    /// запросе).
    pub async fn exchange(&self, query: &Message) -> Result<Message> {
        let orig_id = query.metadata.id;
        let mut q = query.clone();
        // Свой номер: у разных приложений номера могут совпасть. Для DoH —
        // 0, как советует RFC 8484 (кешируется лучше); для DoQ 0 обязателен
        // (RFC 9250, 4.2.1).
        q.metadata.id = match self.kind {
            Kind::Https { .. } | Kind::Quic => 0,
            _ => rand::random(),
        };
        let mut answer = match &self.kind {
            Kind::Udp => {
                let a = self.exchange_udp(&q).await?;
                if a.metadata.truncation {
                    // Не влез в UDP — повторить по TCP.
                    self.exchange_tcp(&q).await?
                } else {
                    a
                }
            }
            Kind::Tcp => self.exchange_tcp(&q).await?,
            Kind::Tls => self.exchange_tls(&q).await?,
            Kind::Https { path } => self.exchange_https(&q, path).await?,
            Kind::Quic => self.exchange_quic(&q).await?,
            Kind::Local => local_answer(&q).await?,
            Kind::FakeIp => return Err(Error::Protocol("fakeip — не настоящий сервер".into())),
        };
        if answer.metadata.id != q.metadata.id {
            return Err(Error::Protocol("DNS: номер ответа не совпал".into()));
        }
        check_answer(&q, &answer)?;
        answer.metadata.id = orig_id;
        Ok(answer)
    }

    async fn udp_client(&self) -> Result<Arc<UdpClient>> {
        let mut g = self.udp.lock().await;
        if let Some(c) = g.as_ref() {
            if !c.closed.load(Ordering::Relaxed) {
                return Ok(c.clone());
            }
        }
        let session = self.detour().udp(&self.meta(Network::Udp)).await?;
        let client = Arc::new(UdpClient {
            session,
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });
        let reader = client.clone();
        let (host, port) = (self.host.clone(), self.port);
        let tag = self.tag.clone();
        tokio::spawn(async move {
            while let Ok(Some((src, sport, data))) = reader.session.recv().await {
                // Ответ должен прийти с адреса сервера.
                let from_server =
                    sport == port && (matches!(host, Address::Domain(_)) || src == host);
                if !from_server || data.len() < 2 {
                    tracing::debug!(dns = %tag, "DNS: пакет не от сервера — отброшен");
                    continue;
                }
                let id = u16::from_be_bytes([data[0], data[1]]);
                if let Some(tx) = reader.pending.lock().unwrap().remove(&id) {
                    let _ = tx.send(data);
                }
            }
            reader.closed.store(true, Ordering::Relaxed);
            reader.pending.lock().unwrap().clear();
        });
        *g = Some(client.clone());
        Ok(client)
    }

    async fn exchange_udp(&self, q: &Message) -> Result<Message> {
        let bytes = encode(q)?;
        let id = q.metadata.id;
        for attempt in 0..2 {
            let client = self.udp_client().await?;
            let (tx, rx) = oneshot::channel();
            client.pending.lock().unwrap().insert(id, tx);
            if let Err(e) = client
                .session
                .send(self.host.clone(), self.port, bytes.clone())
                .await
            {
                client.closed.store(true, Ordering::Relaxed);
                client.pending.lock().unwrap().remove(&id);
                if attempt == 1 {
                    return Err(e);
                }
                continue;
            }
            match tokio::time::timeout(UDP_ATTEMPT, rx).await {
                Ok(Ok(data)) => {
                    let m = decode(&data)?;
                    if check_answer(q, &m).is_ok() {
                        return Ok(m);
                    }
                }
                Ok(Err(_)) => {} // сессия закрылась — попробуем новую
                Err(_) => {
                    client.pending.lock().unwrap().remove(&id);
                }
            }
        }
        Err(Error::Protocol(format!(
            "DNS {}: сервер не ответил по UDP",
            self.tag
        )))
    }

    async fn exchange_tcp(&self, q: &Message) -> Result<Message> {
        let bytes = encode(q)?;
        tokio::time::timeout(STREAM_TIMEOUT, async {
            let mut s = self.detour().connect(&self.meta(Network::Tcp)).await?;
            write_framed(&mut s, &bytes).await?;
            decode(&read_framed(&mut s).await?)
        })
        .await
        .map_err(|_| Error::Protocol(format!("DNS {}: сервер не ответил по TCP", self.tag)))?
    }

    async fn new_tls(&self) -> Result<TlsConn> {
        let s = self.detour().connect(&self.meta(Network::Tcp)).await?;
        crate::transport::tcp_tls::tls_over(s, &self.tls_name(), self.roots.clone(), Vec::new())
            .await
    }

    async fn exchange_tls(&self, q: &Message) -> Result<Message> {
        let bytes = encode(q)?;
        tokio::time::timeout(STREAM_TIMEOUT, async {
            // Сначала — готовое соединение из запаса; если оно уже
            // закрыто сервером, — новое.
            let pooled = self.tls_pool.lock().unwrap().pop();
            let mut last = None;
            for conn in [pooled.map(Ok), Some(Err(()))].into_iter().flatten() {
                let mut conn = match conn {
                    Ok(c) => c,
                    Err(()) => self.new_tls().await?,
                };
                let r = async {
                    write_framed(&mut conn, &bytes).await?;
                    read_framed(&mut conn).await
                }
                .await;
                match r {
                    Ok(data) => {
                        let mut pool = self.tls_pool.lock().unwrap();
                        if pool.len() < 4 {
                            pool.push(conn);
                        }
                        return decode(&data);
                    }
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| Error::Protocol("DNS: TLS".into())))
        })
        .await
        .map_err(|_| Error::Protocol(format!("DNS {}: сервер не ответил по TLS", self.tag)))?
    }

    async fn h2_sender(&self) -> Result<h2::client::SendRequest<Bytes>> {
        let mut g = self.h2.lock().await;
        if let Some(s) = g.as_ref() {
            return Ok(s.clone());
        }
        let s = self.detour().connect(&self.meta(Network::Tcp)).await?;
        let tls = crate::transport::tcp_tls::tls_over(
            s,
            &self.tls_name(),
            self.roots.clone(),
            vec![b"h2".to_vec()],
        )
        .await?;
        let (send, conn) = h2::client::handshake(tls)
            .await
            .map_err(|e| Error::Protocol(format!("DoH: h2: {e}")))?;
        let tag = self.tag.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(dns = %tag, error = %e, "DoH: соединение закрыто");
            }
        });
        *g = Some(send.clone());
        Ok(send)
    }

    async fn exchange_https(&self, q: &Message, path: &str) -> Result<Message> {
        let bytes = Bytes::from(encode(q)?);
        let authority = match (&self.host, self.port) {
            (Address::Ipv6(v6), 443) => format!("[{v6}]"),
            (Address::Ipv6(v6), p) => format!("[{v6}]:{p}"),
            (h, 443) => h.to_string(),
            (h, p) => format!("{h}:{p}"),
        };
        let uri = format!("https://{authority}{path}");
        let once = || async {
            let send = self.h2_sender().await?;
            let mut send = send
                .ready()
                .await
                .map_err(|e| Error::Protocol(format!("DoH: {e}")))?;
            let req = http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .header("content-length", bytes.len())
                .body(())
                .map_err(|e| Error::Protocol(format!("DoH: {e}")))?;
            let (resp, mut body) = send
                .send_request(req, false)
                .map_err(|e| Error::Protocol(format!("DoH: {e}")))?;
            body.send_data(bytes.clone(), true)
                .map_err(|e| Error::Protocol(format!("DoH: {e}")))?;
            let resp = resp
                .await
                .map_err(|e| Error::Protocol(format!("DoH: {e}")))?;
            if resp.status() != 200 {
                return Err(Error::Protocol(format!(
                    "DoH {}: сервер ответил {}",
                    self.tag,
                    resp.status()
                )));
            }
            let mut body = resp.into_body();
            let mut data = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|e| Error::Protocol(format!("DoH: {e}")))?;
                let _ = body.flow_control().release_capacity(chunk.len());
                data.extend_from_slice(&chunk);
                if data.len() > MAX_MESSAGE {
                    return Err(Error::Protocol("DoH: ответ слишком большой".into()));
                }
            }
            decode(&data)
        };
        tokio::time::timeout(STREAM_TIMEOUT, async {
            match once().await {
                Ok(m) => Ok(m),
                Err(e) => {
                    // Соединение могло закрыться — одна попытка с новым.
                    tracing::debug!(dns = %self.tag, error = %e, "DoH: повтор с новым соединением");
                    *self.h2.lock().await = None;
                    once().await
                }
            }
        })
        .await
        .map_err(|_| Error::Protocol(format!("DNS {}: сервер не ответил по HTTPS", self.tag)))?
    }
}

impl Upstream {
    /// Соединение DoQ: готовое или новое (через UDP-сессию выхода).
    async fn quic_conn(&self) -> Result<quinn::Connection> {
        let mut g = self.quic.lock().await;
        if let Some((_, c)) = g.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        *g = None;
        let session = self.detour().udp(&self.meta(Network::Udp)).await?;
        let (ep, peer) = quic::session_endpoint(session, self.host.clone(), self.port)?;
        let cfg = quic::client_config(self.roots.clone(), vec![b"doq".to_vec()])?;
        let what = format!("DoQ {}", self.tag);
        let conn = ep
            .connect_with(cfg, peer, &self.tls_name())
            .map_err(|e| quic::connect_error(&what, e))?
            .await
            .map_err(|e| quic::connect_error(&what, e))?;
        *g = Some((ep, conn.clone()));
        Ok(conn)
    }

    /// Один запрос — один двунаправленный поток: длина (2 байта) и
    /// сообщение в обе стороны (RFC 9250, 4.2).
    async fn exchange_quic(&self, q: &Message) -> Result<Message> {
        let bytes = encode(q)?;
        let what = format!("DoQ {}", self.tag);
        let once = || async {
            let conn = self.quic_conn().await?;
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| quic::connect_error(&what, e))?;
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            send.write_all(&framed)
                .await
                .map_err(|e| quic::connect_error(&what, e))?;
            send.finish().map_err(|e| quic::connect_error(&what, e))?;
            let mut len = [0u8; 2];
            recv.read_exact(&mut len)
                .await
                .map_err(|e| quic::connect_error(&what, e))?;
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            recv.read_exact(&mut buf)
                .await
                .map_err(|e| quic::connect_error(&what, e))?;
            decode(&buf)
        };
        tokio::time::timeout(STREAM_TIMEOUT, async {
            match once().await {
                Ok(m) => Ok(m),
                Err(e) => {
                    tracing::debug!(dns = %self.tag, error = %e, "DoQ: повтор с новым соединением");
                    if let Some((_, c)) = self.quic.lock().await.take() {
                        c.close(0u32.into(), b"");
                    }
                    once().await
                }
            }
        })
        .await
        .map_err(|_| Error::Protocol(format!("DNS {}: сервер не ответил по QUIC", self.tag)))?
    }
}

/// Ответ системного резолвера (только A и AAAA).
async fn local_answer(q: &Message) -> Result<Message> {
    let mut resp = Message::response(q.metadata.id, q.metadata.op_code);
    resp.metadata.recursion_desired = q.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.add_queries(q.queries.iter().cloned());
    let Some(question) = q.queries.first() else {
        resp.metadata.response_code = ResponseCode::FormErr;
        return Ok(resp);
    };
    let qtype = question.query_type();
    if !matches!(qtype, RecordType::A | RecordType::AAAA) {
        return Ok(resp);
    }
    let name = question.name().to_ascii();
    let host = name.trim_end_matches('.');
    match tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, 0))).await {
        Ok(Ok(addrs)) => {
            for a in addrs {
                let rdata = match (a.ip(), qtype) {
                    (IpAddr::V4(v4), RecordType::A) => RData::A(A(v4)),
                    (IpAddr::V6(v6), RecordType::AAAA) => RData::AAAA(AAAA(v6)),
                    _ => continue,
                };
                resp.add_answer(Record::from_rdata(question.name().clone(), 60, rdata));
            }
        }
        Ok(Err(_)) => resp.metadata.response_code = ResponseCode::NXDomain,
        Err(_) => resp.metadata.response_code = ResponseCode::ServFail,
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let p = |s| parse_address(s).unwrap();
        assert_eq!(
            p("1.1.1.1"),
            (Kind::Udp, Address::Ipv4("1.1.1.1".parse().unwrap()), 53)
        );
        assert_eq!(p("udp://8.8.8.8:5353").2, 5353);
        assert_eq!(
            p("tcp://[2606:4700::1111]").1,
            Address::Ipv6("2606:4700::1111".parse().unwrap())
        );
        assert_eq!(
            p("tls://dns.google"),
            (Kind::Tls, Address::Domain("dns.google".into()), 853)
        );
        assert_eq!(
            p("https://1.1.1.1"),
            (
                Kind::Https {
                    path: "/dns-query".into()
                },
                Address::Ipv4("1.1.1.1".parse().unwrap()),
                443
            )
        );
        assert_eq!(
            p("https://Dns.Example:8443/q").0,
            Kind::Https { path: "/q".into() }
        );
        assert_eq!(p("local").0, Kind::Local);
        assert_eq!(p("fakeip").0, Kind::FakeIp);
        assert_eq!(
            p("quic://dns.adguard-dns.com"),
            (
                Kind::Quic,
                Address::Domain("dns.adguard-dns.com".into()),
                853
            )
        );
        for bad in [
            "ftp://1.1.1.1",
            "quic://1.1.1.1/x",
            "udp://dns.google",
            "tls://",
            "1.1.1.1/x",
            "tcp://1.1.1.1:99999",
            "udp://[::1",
        ] {
            assert!(parse_address(bad).is_err(), "{bad}");
        }
    }
}
