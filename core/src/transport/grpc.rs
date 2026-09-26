//! Транспорт Этапа 4: VLESS поверх одного bidi-стрима gRPC — режим
//! "gun" у Xray-core/V2Ray (без мультиплексирования, `multiMode=false`).
//!
//! Формат перепроверен по двум независимым источникам (см. PLAN.md,
//! Этап 4): путь запроса `/{serviceName}/Tun`, каждое сообщение —
//! стандартный gRPC-кадр (1 байт флага сжатия, всегда 0 — сжатие не
//! поддерживаем; 4 байта BE-длины) вокруг protobuf-сообщения
//! `Hunk { bytes data = 1; }`.
//!
//! Используем `h2` напрямую (готовая библиотека, не самописный HTTP/2)
//! — сами пишем только тонкий слой protobuf-варинта и кадрирования
//! payload'а поверх него.
//!
//! ⚠️ **Не проверено на живом Xray-core/V2Ray сервере** — в этой среде
//! его нет и не может быть. Проверено только на собственном тестовом
//! h2-сервере (`core/tests/grpc_loopback.rs`), который подтверждает
//! корректность протокольной склейки (кадрирование, protobuf, обвязка
//! AsyncRead/AsyncWrite), но не байт-в-байт совместимость с чужой
//! реализацией. Перед боевым использованием — свериться с реальным
//! сервером.
//!
//! Отправка уважает окно HTTP/2 получателя (`reserve_capacity` /
//! `poll_capacity`): при медленном сервере данные не копятся в памяти
//! без ограничения.

use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::transport::tcp_tls::connect_tls_by_security;
use crate::vless::protocol::{vless_connect, Address, Command, VlessStream};
use crate::vless::VlessConfig;

const DUPLEX_CAPACITY: usize = 64 * 1024;
const READ_CHUNK: usize = 16 * 1024;

/// Открыть один gRPC bidi-стрим и вернуть его в виде обычного
/// `AsyncRead + AsyncWrite` (через `tokio::io::duplex` — фактическая
/// работа с `h2`/protobuf-кадрированием идёт в фоновой задаче, наружу
/// отдаётся уже плоский байтовый поток). TLS под ALPN `h2` — обычный или
/// REALITY, по `cfg.security` (Этап 5).
pub async fn connect_grpc(cfg: &VlessConfig) -> Result<DuplexStream> {
    let service_name = cfg.service_name().to_string();

    // gRPC — только HTTP/2, ALPN всегда `h2`.
    let tls = connect_tls_by_security(cfg, vec![b"h2".to_vec()]).await?;

    let (send_request, connection) = h2::client::handshake(tls)
        .await
        .map_err(|e| Error::Protocol(format!("h2 handshake не удался: {e}")))?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!(error = %e, "h2-соединение (gRPC) завершилось");
        }
    });

    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| Error::Protocol(format!("h2 SendRequest не готов: {e}")))?;

    let uri: http::Uri = format!("https://{}/{}/Tun", cfg.effective_sni(), service_name)
        .parse()
        .map_err(|e| Error::Protocol(format!("не удалось собрать URI gRPC-потока: {e}")))?;

    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(())
        .map_err(|e| Error::Protocol(format!("не удалось собрать gRPC-запрос: {e}")))?;

    let (response_fut, mut send_stream) = send_request
        .send_request(request, false)
        .map_err(|e| Error::Protocol(format!("не удалось открыть gRPC-поток: {e}")))?;

    // Ответные заголовки НЕ ждём здесь: gRPC-сервер Xray (grpc-go)
    // отправляет их только вместе с первым сообщением, а первое сообщение
    // появится, лишь когда мы пришлём заголовок VLESS. Ожидание здесь было
    // взаимной блокировкой (поймано интероп-тестом против Xray-core;
    // собственный тестовый сервер отвечал заголовками сразу).
    let (user_half, internal_half) = duplex(DUPLEX_CAPACITY);
    let (mut internal_read, mut internal_write) = tokio::io::split(internal_half);

    // Отправляющая половина: то, что записал вызывающий код в
    // user_half, режем на чанки, каждый оборачиваем в gRPC/protobuf
    // Hunk-кадр и шлём в h2-поток — с учётом окна получателя: сначала
    // резервируем место (`reserve_capacity`) и ждём, пока h2 его даст
    // (`poll_capacity`). Раньше данные отдавались в `send_data` без этого,
    // и при медленном получателе h2 буферизовал их без ограничения.
    tokio::spawn(async move {
        let mut buf = vec![0u8; READ_CHUNK];
        'outer: loop {
            let n = match internal_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut frame = Bytes::from(encode_hunk_frame(&buf[..n]));
            while !frame.is_empty() {
                send_stream.reserve_capacity(frame.len());
                let cap = match std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await {
                    Some(Ok(c)) if c > 0 => c,
                    Some(Ok(_)) => continue,
                    _ => break 'outer,
                };
                let part = frame.split_to(cap.min(frame.len()));
                if send_stream.send_data(part, false).is_err() {
                    break 'outer;
                }
            }
        }
        let _ = send_stream.send_data(Bytes::new(), true);
    });

    // Принимающая половина: сырые DATA-фреймы HTTP/2 не совпадают по
    // границам с gRPC-сообщениями — копим в `HunkDecoder` и отдаём
    // вызывающему коду уже только полезную нагрузку из `Hunk.data`.
    tokio::spawn(async move {
        let response = match response_fut.await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "gRPC-сервер не ответил на поток");
                return;
            }
        };
        if response.status() != http::StatusCode::OK {
            tracing::warn!(
                status = %response.status(),
                "gRPC-сервер ответил не 200 (неверный serviceName или это не gRPC-вход)"
            );
            return;
        }
        let mut recv_stream = response.into_body();
        let mut decoder = HunkDecoder::default();
        while let Some(chunk) = recv_stream.data().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => break,
            };
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
            decoder.feed(&chunk);
            loop {
                match decoder.next_message() {
                    Ok(Some(payload)) => {
                        if internal_write.write_all(&payload).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
        }
    });

    Ok(user_half)
}

/// Полное открытие соединения Этапа 4 (gRPC): TCP -> TLS(ALPN h2) ->
/// gRPC-поток -> заголовок запроса VLESS (ответ снимается
/// лениво, см. `vless_connect`).
pub async fn connect_and_handshake_grpc(
    cfg: &VlessConfig,
    id: &Uuid,
    target: Address,
    target_port: u16,
) -> Result<VlessStream<DuplexStream>> {
    connect_command_grpc(cfg, id, Command::Tcp, target, target_port).await
}

/// Как [`connect_and_handshake_grpc`], но с явной командой VLESS (TCP/UDP).
pub async fn connect_command_grpc(
    cfg: &VlessConfig,
    id: &Uuid,
    command: Command,
    target: Address,
    target_port: u16,
) -> Result<VlessStream<DuplexStream>> {
    cfg.ensure_flow_supported()?;
    let stream = connect_grpc(cfg).await?;
    vless_connect(stream, id, command, &target, target_port).await
}

fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

/// Обернуть сырые байты payload'а в один gRPC-кадр с protobuf-сообщением
/// `Hunk{ bytes data = 1; }`: tag(0x0A) + varint(len) + data, затем
/// снаружи — 1 байт флага сжатия (0) + 4 байта BE-длины protobuf-части.
///
/// `pub`, не `pub(crate)`: пригождается тестовому h2-серверу в
/// `core/tests/grpc_loopback.rs`, который говорит на этом же формате
/// кадров, чтобы проверить клиента без реального Xray-сервера.
pub fn encode_hunk_frame(data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(data.len() + 6);
    msg.push(0x0A); // tag: field 1, wire type 2 (length-delimited)
    encode_varint(data.len() as u64, &mut msg);
    msg.extend_from_slice(data);

    let mut framed = Vec::with_capacity(msg.len() + 5);
    framed.push(0x00); // не сжато
    framed.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    framed.extend_from_slice(&msg);
    framed
}

/// Инкрементально собирает gRPC-кадры из произвольно нарезанных кусков
/// HTTP/2 DATA-фреймов и достаёт из каждого поле `data` сообщения `Hunk`.
#[derive(Default)]
pub struct HunkDecoder {
    buf: BytesMut,
}

impl HunkDecoder {
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// `Ok(Some(payload))` — есть готовое сообщение, можно звать ещё раз
    /// (в буфере может быть несколько). `Ok(None)` — данных пока не
    /// хватает, надо ждать следующий `feed`. `Err` — кадр повреждён.
    pub fn next_message(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let compressed = self.buf[0];
        if compressed != 0 {
            return Err(Error::Protocol(
                "сжатые gRPC-сообщения не поддерживаются".into(),
            ));
        }
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if self.buf.len() < 5 + len {
            return Ok(None);
        }

        let msg = self.buf[5..5 + len].to_vec();
        self.buf.advance(5 + len);

        if msg.is_empty() {
            return Ok(Some(Vec::new()));
        }
        if msg[0] != 0x0A {
            return Err(Error::Protocol(format!(
                "неожиданный protobuf-тег в Hunk: {:#04x}",
                msg[0]
            )));
        }
        let (data_len, used) = decode_varint(&msg[1..])
            .ok_or_else(|| Error::Protocol("не удалось разобрать varint-длину Hunk.data".into()))?;
        let start = 1 + used;
        let end = start
            .checked_add(data_len as usize)
            .ok_or_else(|| Error::Protocol("переполнение длины Hunk.data".into()))?;
        if end > msg.len() {
            return Err(Error::Protocol(
                "Hunk.data выходит за границы сообщения".into(),
            ));
        }
        Ok(Some(msg[start..end].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_single_chunk() {
        let payload = b"hello grpc tunnel";
        let framed = encode_hunk_frame(payload);

        let mut decoder = HunkDecoder::default();
        decoder.feed(&framed);
        let got = decoder.next_message().unwrap().unwrap();
        assert_eq!(got, payload);
        assert_eq!(decoder.next_message().unwrap(), None);
    }

    #[test]
    fn round_trips_when_split_across_feeds() {
        let payload = vec![0xABu8; 5000];
        let framed = encode_hunk_frame(&payload);

        let mut decoder = HunkDecoder::default();
        for chunk in framed.chunks(7) {
            decoder.feed(chunk);
        }
        let got = decoder.next_message().unwrap().unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn decodes_multiple_messages_from_one_feed() {
        let mut framed = encode_hunk_frame(b"one");
        framed.extend(encode_hunk_frame(b"two"));

        let mut decoder = HunkDecoder::default();
        decoder.feed(&framed);
        assert_eq!(decoder.next_message().unwrap().unwrap(), b"one");
        assert_eq!(decoder.next_message().unwrap().unwrap(), b"two");
        assert_eq!(decoder.next_message().unwrap(), None);
    }

    #[test]
    fn rejects_compressed_frame() {
        let mut framed = encode_hunk_frame(b"x");
        framed[0] = 1; // выставляем флаг сжатия
        let mut decoder = HunkDecoder::default();
        decoder.feed(&framed);
        assert!(decoder.next_message().is_err());
    }
}
