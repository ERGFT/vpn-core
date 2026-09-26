//! Кодирование заголовка запроса VLESS и разбор заголовка ответа.
//!
//! Формат запроса (клиент -> сервер), все поля big-endian:
//!   1 байт   версия протокола (0x00)
//!   16 байт  UUID пользователя
//!   1 байт   длина блока доп. инструкций M (на Этапе 1 всегда 0)
//!   M байт   доп. инструкции (протобаф; не используем)
//!   1 байт   команда (0x01 TCP, 0x02 UDP, 0x03 MUX)
//!   2 байта  порт назначения
//!   1 байт   тип адреса (0x01 IPv4, 0x02 домен, 0x03 IPv6)
//!   N байт   адрес назначения
//!   ...      далее сразу полезная нагрузка (без доп. рамки)
//!
//! Формат ответа (сервер -> клиент):
//!   1 байт   версия протокола (эхо клиентской)
//!   1 байт   длина блока доп. инструкций N
//!   N байт   доп. инструкции
//!   ...      далее сразу полезная нагрузка
//!
//! Это открытый и задокументированный сообществом Xray-core протокол
//! прикладного уровня поверх обычного TLS-соединения — не эксплойт и не
//! попытка выдать трафик за что-то, чем он не является; маскировка
//! ClientHello (Этап 3) и REALITY (Этап 5) работают на уровне ниже, здесь
//! их нет.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::vless::uri::Flow;

pub const PROTOCOL_VERSION: u8 = 0x00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

impl Address {
    fn type_byte(&self) -> u8 {
        match self {
            Address::Ipv4(_) => 0x01,
            Address::Domain(_) => 0x02,
            Address::Ipv6(_) => 0x03,
        }
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.type_byte());
        match self {
            Address::Ipv4(a) => buf.put_slice(&a.octets()),
            Address::Domain(d) => {
                // Длина домена как 1 байт — домены длиннее 255 байт формат
                // не поддерживает (как и оригинальный протокол).
                buf.put_u8(d.len() as u8);
                buf.put_slice(d.as_bytes());
            }
            Address::Ipv6(a) => buf.put_slice(&a.octets()),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Ipv4(a) => write!(f, "{a}"),
            Address::Domain(d) => write!(f, "{d}"),
            Address::Ipv6(a) => write!(f, "{a}"),
        }
    }
}

/// Собрать заголовок запроса без flow. Возвращает готовый к записи в
/// сокет буфер.
pub fn encode_request(id: &Uuid, command: Command, addr: &Address, port: u16) -> BytesMut {
    encode_request_with_flow(id, command, addr, port, Flow::None)
}

/// Значение `flow`, которое уходит серверу в addons. Клиентский вариант
/// `xtls-rprx-vision-udp443` серверу отправляется как `xtls-rprx-vision`
/// (`outbound.go`: `requestAddons.Flow[:16]`).
fn wire_flow(flow: Flow) -> Option<&'static str> {
    match flow {
        Flow::None => None,
        Flow::XtlsRprxVision | Flow::XtlsRprxVisionUdp443 => Some("xtls-rprx-vision"),
    }
}

/// Собрать заголовок запроса с блоком addons. Addons — protobuf
/// `message Addons { string Flow = 1; bytes Seed = 2; }`
/// (`proxy/vless/encoding/addons.proto`); клиент заполняет только Flow,
/// как и Xray-core. Без flow — нулевая длина блока.
pub fn encode_request_with_flow(
    id: &Uuid,
    command: Command,
    addr: &Address,
    port: u16,
    flow: Flow,
) -> BytesMut {
    let mut buf = BytesMut::with_capacity(48 + addr.encoded_len_hint());
    buf.put_u8(PROTOCOL_VERSION);
    buf.put_slice(id.as_bytes());
    match wire_flow(flow) {
        Some(f) => {
            // tag 1, wire type 2 (length-delimited) = 0x0A; длина строки
            // короче 128 — один байт varint.
            let addons_len = 2 + f.len();
            buf.put_u8(addons_len as u8);
            buf.put_u8(0x0A);
            buf.put_u8(f.len() as u8);
            buf.put_slice(f.as_bytes());
        }
        None => buf.put_u8(0),
    }
    buf.put_u8(command as u8);
    // При команде Mux (XUDP) адрес не передаётся — сервер подставляет
    // `v1.mux.cool` сам (`proxy/vless/encoding/encoding.go`).
    if command != Command::Mux {
        buf.put_u16(port);
        addr.encode(&mut buf);
    }
    buf
}

impl Address {
    fn encoded_len_hint(&self) -> usize {
        match self {
            Address::Ipv4(_) => 5,
            Address::Domain(d) => 2 + d.len(),
            Address::Ipv6(_) => 17,
        }
    }
}

/// Разобрать заголовок ответа сервера из первых байт потока.
///
/// Возвращает версию протокола. Вызывающий код обязан прочитать ровно
/// `2 + N` байт заранее (версия + длина + доп. инструкции) — эта функция
/// сама сокет не читает, чтобы остаться testable без ввода-вывода.
pub struct ResponseHeader {
    pub version: u8,
}

/// Сколько ещё байт нужно дочитать после первых двух (версия, длина N),
/// чтобы заголовок ответа был разобран полностью.
pub fn response_addons_len(second_byte: u8) -> usize {
    second_byte as usize
}

pub fn parse_response_prefix(first_two: &[u8]) -> Result<(ResponseHeader, usize)> {
    if first_two.len() != 2 {
        return Err(Error::Protocol(
            "нужно ровно 2 байта для префикса ответа".into(),
        ));
    }
    let version = first_two[0];
    let addons_len = response_addons_len(first_two[1]);
    Ok((ResponseHeader { version }, addons_len))
}

/// Открыть VLESS-сессию поверх уже установленного (обычно TLS) потока:
/// отправить заголовок запроса и СРАЗУ вернуть поток, не дожидаясь
/// заголовка ответа — его снимет [`VlessStream`] при первом чтении.
///
/// Почему не ждём ответ (раньше ждали — это был дедлок): сервер Xray-core
/// (`proxy/vless/inbound/inbound.go`) пишет заголовок ответа в
/// буферизованный писатель с `SetFlushNext()` — то есть отправляет его
/// только вместе с ПЕРВЫМИ данными от цели. Для протоколов, где первым
/// говорит клиент (HTTPS, HTTP — почти всё), цель молчит, пока клиент
/// ничего не прислал, а клиент, ждущий заголовок ответа, ничего не шлёт.
/// Наши собственные тестовые серверы отвечали заголовком сразу, поэтому
/// тесты этого не видели. Клиент Xray тоже не ждёт ответа перед
/// отправкой данных.
///
/// Транспортно-независимо: TCP+TLS, WS, gRPC и тесты на
/// `tokio::io::duplex` используют одну и ту же функцию.
pub async fn vless_connect<S>(
    mut stream: S,
    id: &Uuid,
    command: Command,
    target: &Address,
    target_port: u16,
) -> Result<VlessStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = encode_request(id, command, target, target_port);
    stream.write_all(&req).await?;
    stream.flush().await?;
    Ok(VlessStream::new(stream))
}

/// Поток VLESS-сессии: запись идёт как есть, а заголовок ответа сервера
/// (`версия, N, N байт addons`) снимается и проверяется лениво — при
/// первом чтении, когда сервер его действительно пришлёт.
pub struct VlessStream<S> {
    inner: S,
    response: ResponseState,
}

#[derive(Debug, Clone, Copy)]
enum ResponseState {
    /// Ждём 2 байта: версия и длина addons. `got` — сколько уже прочитано.
    Prefix {
        buf: [u8; 2],
        got: usize,
    },
    /// Осталось отбросить столько байт addons.
    Addons {
        remaining: usize,
    },
    Done,
}

impl<S> std::fmt::Debug for VlessStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessStream")
            .field("response", &self.response)
            .finish_non_exhaustive()
    }
}

impl<S> VlessStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            response: ResponseState::Prefix {
                buf: [0; 2],
                got: 0,
            },
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Заголовок ответа уже полностью прочитан и снят.
    pub fn response_received(&self) -> bool {
        matches!(self.response, ResponseState::Done)
    }
}

fn eof_in_response_header() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "VLESS: соединение закрыто до получения заголовка ответа",
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            match &mut this.response {
                ResponseState::Done => {
                    return std::pin::Pin::new(&mut this.inner).poll_read(cx, out);
                }
                ResponseState::Prefix { buf, got } => {
                    let mut rb = tokio::io::ReadBuf::new(&mut buf[*got..]);
                    match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(eof_in_response_header()));
                            }
                            *got += n;
                            if *got == 2 {
                                let (hdr, addons) = parse_response_prefix(&buf[..])
                                    .map_err(std::io::Error::other)?;
                                if hdr.version != PROTOCOL_VERSION {
                                    return Poll::Ready(Err(std::io::Error::other(format!(
                                        "VLESS: неожиданная версия в ответе сервера: {}",
                                        hdr.version
                                    ))));
                                }
                                this.response = if addons == 0 {
                                    ResponseState::Done
                                } else {
                                    ResponseState::Addons { remaining: addons }
                                };
                            }
                        }
                    }
                }
                ResponseState::Addons { remaining } => {
                    let mut scratch = [0u8; 64];
                    let want = (*remaining).min(scratch.len());
                    let mut rb = tokio::io::ReadBuf::new(&mut scratch[..want]);
                    match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(eof_in_response_header()));
                            }
                            *remaining -= n;
                            if *remaining == 0 {
                                this.response = ResponseState::Done;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ipv4_request() {
        let id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let buf = encode_request(
            &id,
            Command::Tcp,
            &Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            443,
        );
        assert_eq!(buf[0], PROTOCOL_VERSION);
        assert_eq!(&buf[1..17], id.as_bytes());
        assert_eq!(buf[17], 0); // addons len
        assert_eq!(buf[18], Command::Tcp as u8);
        assert_eq!(&buf[19..21], &443u16.to_be_bytes());
        assert_eq!(buf[21], 0x01); // addr type ipv4
        assert_eq!(&buf[22..26], &[1, 2, 3, 4]);
    }

    /// Addons с flow байт-в-байт как у Xray-core: protobuf-кодирование
    /// `Addons{Flow: "xtls-rprx-vision"}` — `0a 10` + строка.
    #[test]
    fn encodes_vision_addons() {
        let id = Uuid::nil();
        let buf = encode_request_with_flow(
            &id,
            Command::Tcp,
            &Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            443,
            Flow::XtlsRprxVisionUdp443,
        );
        assert_eq!(buf[17], 18, "длина addons");
        assert_eq!(&buf[18..20], &[0x0A, 0x10]);
        assert_eq!(&buf[20..36], b"xtls-rprx-vision");
        assert_eq!(buf[36], Command::Tcp as u8);
    }

    #[test]
    fn encodes_domain_request() {
        let id = Uuid::nil();
        let buf = encode_request(
            &id,
            Command::Tcp,
            &Address::Domain("example.com".to_string()),
            80,
        );
        let addr_start = 1 + 16 + 1 + 1 + 2;
        assert_eq!(buf[addr_start], 0x02); // domain
        assert_eq!(buf[addr_start + 1], 11); // len("example.com")
        assert_eq!(&buf[addr_start + 2..addr_start + 2 + 11], b"example.com");
    }

    /// Сервер, ведущий себя как Xray-core (`SetFlushNext`): заголовок
    /// ответа уходит только вместе с первыми данными от цели, а цель
    /// (как любой HTTPS-сервер) молчит, пока клиент ничего не прислал.
    /// Старый `vless_handshake` здесь висел навсегда.
    #[tokio::test]
    async fn does_not_wait_for_response_header_before_sending_payload() {
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(4096);
        let id = Uuid::nil();
        let target = Address::Domain("example.com".into());

        let server_task = tokio::spawn(async move {
            // Заголовок запроса: 1+16+1+1+2+1+1+11 = 34 байта.
            let mut req = [0u8; 34];
            server.read_exact(&mut req).await.unwrap();
            // Молчим, пока не придут данные клиента (как цель-HTTPS).
            let mut hello = [0u8; 5];
            server.read_exact(&mut hello).await.unwrap();
            assert_eq!(&hello, b"hello");
            // Заголовок ответа с addons (2 байта) + данные цели одним куском.
            server.write_all(&[0x00, 0x02, 0xaa, 0xbb]).await.unwrap();
            server.write_all(b"world").await.unwrap();
        });

        let mut s = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            vless_connect(client, &id, Command::Tcp, &target, 443),
        )
        .await
        .expect("vless_connect не должен ждать ответа сервера")
        .unwrap();
        assert!(!s.response_received());
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        tokio::time::timeout(std::time::Duration::from_secs(2), s.read_exact(&mut buf))
            .await
            .expect("данные должны прийти")
            .unwrap();
        assert_eq!(
            &buf, b"world",
            "заголовок ответа и addons сняты, остались только данные"
        );
        assert!(s.response_received());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_wrong_response_version_and_early_eof() {
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(4096);
        let mut s = VlessStream::new(client);
        server.write_all(&[0x01, 0x00]).await.unwrap();
        let mut b = [0u8; 1];
        assert!(s.read(&mut b).await.is_err(), "версия ответа не 0 — ошибка");

        let (client, mut server) = tokio::io::duplex(4096);
        let mut s = VlessStream::new(client);
        server.write_all(&[0x00, 0x05, 0x01]).await.unwrap();
        drop(server);
        let err = s.read(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn parses_response_prefix_no_addons() {
        let (hdr, addons) = parse_response_prefix(&[0x00, 0x00]).unwrap();
        assert_eq!(hdr.version, 0);
        assert_eq!(addons, 0);
    }
}
