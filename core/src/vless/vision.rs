// SPDX-License-Identifier: GPL-3.0-or-later
//! XTLS Vision (`flow=xtls-rprx-vision`) — клиентская сторона.
//!
//! Перенос логики Xray-core (`proxy/proxy.go`: `VisionWriter`,
//! `VisionReader`, `XtlsPadding`, `XtlsUnpadding`, `XtlsFilterTls`,
//! `IsCompleteRecord`, `ReshapeMultiBuffer`; `proxy/vless/outbound/outbound.go`)
//! с сохранением порядка решений — чтобы сервер Xray видел ровно то же,
//! что от собственного клиента.
//!
//! Что делает Vision, по шагам:
//! 1. **Padding.** Первые пакеты в обе стороны заворачиваются в блоки
//!    `[UUID (только в самом первом)] команда(1) длина_данных(2)
//!    длина_padding(2) данные padding`. Это прячет характерные длины
//!    рукопожатия внутреннего TLS («TLS в TLS»). Заголовок VLESS уходит
//!    вместе с первым блоком; если приложение 500 мс ничего не шлёт —
//!    уходит блок из одного padding (как у Xray).
//! 2. **Распознавание внутреннего TLS.** По первым пакетам (до 8) видно
//!    ClientHello приложения и ServerHello сайта; если это TLS 1.3 с
//!    обычным AEAD-шифром, включается XTLS.
//! 3. **Прямая передача.** Как только пошли прикладные данные
//!    внутреннего TLS, сторона отправляет последний блок с командой
//!    `Direct` и дальше пишет байты внутреннего TLS прямо в TCP — без
//!    повторного шифрования внешним TLS. Получатель, увидев `Direct`,
//!    тоже читает дальше прямо из TCP. Направления переключаются
//!    независимо.
//!
//! Для п.3 чтение внешнего TLS идёт по одному рекорду за раз
//! ([`crate::transport::raw::RawConn`] в режиме `record_aligned`), иначе
//! rustls забрал бы из сокета и попытался расшифровать уже сырые байты
//! после точки переключения.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

use crate::transport::tcp_tls::TlsBoxedStream;

const COMMAND_PADDING_CONTINUE: u8 = 0x00;
const COMMAND_PADDING_END: u8 = 0x01;
const COMMAND_PADDING_DIRECT: u8 = 0x02;

/// `buf.Size` в Xray-core — размер одного буфера; на него рассчитаны
/// ограничения на длину блока.
const BUF_SIZE: usize = 8192;
/// Заголовок блока в худшем случае: UUID(16) + команда(1) + 2 + 2.
const BLOCK_OVERHEAD: usize = 21;
/// `testseed` по умолчанию (`NewVisionWriter`): порог длинного padding,
/// разброс длинного, база длинного, разброс короткого.
const TESTSEED: [usize; 4] = [900, 500, 900, 256];
/// Сколько ждать первых данных приложения, прежде чем отправить
/// заголовок VLESS с одним padding (`outbound.go`, 500 мс).
const FIRST_DATA_WAIT: Duration = Duration::from_millis(500);

const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// Общее для обоих направлений (`proxy.TrafficState` без per-direction полей).
#[derive(Debug)]
struct TrafficState {
    number_of_packet_to_filter: i32,
    enable_xtls: bool,
    is_tls12_or_above: bool,
    is_tls: bool,
    cipher: u16,
    remaining_server_hello: i32,
}

impl TrafficState {
    fn new() -> Self {
        Self {
            number_of_packet_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }

    /// `XtlsFilterTls`: по первым пакетам узнать, TLS ли это, и если да —
    /// TLS 1.3 с каким шифром.
    fn filter_tls(&mut self, buffers: &[&[u8]]) {
        for b in buffers {
            self.number_of_packet_to_filter -= 1;
            if b.len() >= 6 {
                if b[..3] == TLS_SERVER_HANDSHAKE_START && b[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO {
                    self.remaining_server_hello = ((b[3] as i32) << 8 | b[4] as i32) + 5;
                    self.is_tls12_or_above = true;
                    self.is_tls = true;
                    if b.len() >= 79 && self.remaining_server_hello >= 79 {
                        let sid_len = b[43] as usize;
                        let at = 43 + sid_len + 1;
                        if at + 2 <= b.len() {
                            self.cipher = u16::from_be_bytes([b[at], b[at + 1]]);
                        }
                    }
                } else if b[..2] == TLS_CLIENT_HANDSHAKE_START
                    && b[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
                {
                    self.is_tls = true;
                }
            }
            if self.remaining_server_hello > 0 {
                let end = (self.remaining_server_hello as usize).min(b.len());
                self.remaining_server_hello -= b.len() as i32;
                if contains(&b[..end], &TLS13_SUPPORTED_VERSIONS) {
                    // TLS_AES_128_CCM_8_SHA256 (0x1305) и не-TLS1.3 шифры
                    // XTLS не включают — как у Xray.
                    if matches!(self.cipher, 0x1301..=0x1304) {
                        self.enable_xtls = true;
                    }
                    tracing::debug!(
                        cipher = format!("{:#06x}", self.cipher),
                        xtls = self.enable_xtls,
                        "Vision: внутренний TLS 1.3"
                    );
                    self.number_of_packet_to_filter = 0;
                    return;
                } else if self.remaining_server_hello <= 0 {
                    tracing::debug!("Vision: внутренний TLS 1.2 — прямой передачи не будет");
                    self.number_of_packet_to_filter = 0;
                    return;
                }
            }
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `IsCompleteRecord`: всё содержимое — целые TLS-рекорды прикладных данных.
fn is_complete_record(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        if b.len() - i < 5 || b[i..i + 3] != TLS_APPLICATION_DATA_START {
            return false;
        }
        let len = u16::from_be_bytes([b[i + 3], b[i + 4]]) as usize;
        if len == 0 {
            // У Xray рекорд нулевой длины не проходит проверку.
            return false;
        }
        i += 5;
        if b.len() - i < len {
            return false;
        }
        i += len;
    }
    true
}

/// Разбить данные на буферы так, как их увидел бы Xray: куски по
/// `buf.Size`, а слишком длинные для блока с заголовком — ещё пополам
/// (`ReshapeMultiBuffer`: по последнему началу рекорда прикладных данных,
/// иначе посередине).
fn reshape(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    for chunk in data.chunks(BUF_SIZE) {
        if chunk.len() >= BUF_SIZE - BLOCK_OVERHEAD {
            let mut index = chunk
                .windows(3)
                .rposition(|w| w == TLS_APPLICATION_DATA_START)
                .unwrap_or(0);
            if !(BLOCK_OVERHEAD..=BUF_SIZE - BLOCK_OVERHEAD).contains(&index) {
                index = BUF_SIZE / 2;
            }
            out.push(&chunk[..index]);
            out.push(&chunk[index..]);
        } else {
            out.push(chunk);
        }
    }
    out
}

/// `XtlsPadding`: блок `[UUID] команда длина_данных длина_padding данные padding`.
fn xtls_padding(
    content: &[u8],
    command: u8,
    uuid_once: &mut Option<[u8; 16]>,
    long_padding: bool,
    out: &mut Vec<u8>,
) {
    let content_len = content.len();
    let mut rng = rand::thread_rng();
    let mut padding_len = if content_len < TESTSEED[0] && long_padding {
        rng.gen_range(0..TESTSEED[1]) + TESTSEED[2] - content_len
    } else {
        rng.gen_range(0..TESTSEED[3])
    };
    let cap = (BUF_SIZE - BLOCK_OVERHEAD).saturating_sub(content_len);
    if padding_len > cap {
        padding_len = cap;
    }
    if let Some(u) = uuid_once.take() {
        out.extend_from_slice(&u);
    }
    out.push(command);
    out.extend_from_slice(&(content_len as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
    tracing::debug!(content_len, padding_len, command, "Vision: padding");
}

/// Состояние разбора блоков в одном направлении (`XtlsUnpadding` +
/// per-direction поля `OutboundState`).
#[derive(Debug)]
struct Unpadder {
    uuid: [u8; 16],
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
    /// Самый первый блок ещё не встречен: начало потока может прийти
    /// короче 21 байта — тогда копим (у Xray такой кусок прошёл бы как
    /// есть; на практике он всегда целиком в первом рекорде).
    first_block_pending: bool,
    accum: Vec<u8>,
}

impl Unpadder {
    fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            first_block_pending: true,
            accum: Vec::new(),
        }
    }

    fn initial(&self) -> bool {
        self.remaining_command == -1 && self.remaining_content == -1 && self.remaining_padding == -1
    }

    /// Снять блоки с одного прочитанного куска, данные — в `out`.
    fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        let owned;
        let mut b: &[u8] = chunk;
        if self.initial() {
            if self.first_block_pending {
                if !self.accum.is_empty() || b.len() < BLOCK_OVERHEAD {
                    self.accum.extend_from_slice(b);
                    let n = self.accum.len().min(16);
                    if self.accum.len() < BLOCK_OVERHEAD && self.accum[..n] == self.uuid[..n] {
                        return; // ждём продолжения
                    }
                    owned = std::mem::take(&mut self.accum);
                    b = &owned;
                }
                self.first_block_pending = false;
            }
            if b.len() >= BLOCK_OVERHEAD && b[..16] == self.uuid {
                b = &b[16..];
                self.remaining_command = 5;
            } else {
                out.extend_from_slice(b);
                return;
            }
        }
        while !b.is_empty() {
            if self.remaining_command > 0 {
                let data = b[0];
                b = &b[1..];
                match self.remaining_command {
                    5 => self.current_command = data,
                    4 => self.remaining_content = (data as i32) << 8,
                    3 => self.remaining_content |= data as i32,
                    2 => self.remaining_padding = (data as i32) << 8,
                    1 => self.remaining_padding |= data as i32,
                    _ => {}
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let n = (self.remaining_content as usize).min(b.len());
                out.extend_from_slice(&b[..n]);
                b = &b[n..];
                self.remaining_content -= n as i32;
            } else {
                let n = (self.remaining_padding.max(0) as usize).min(b.len());
                b = &b[n..];
                self.remaining_padding -= n as i32;
            }
            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                if self.current_command == COMMAND_PADDING_CONTINUE {
                    self.remaining_command = 5;
                } else {
                    self.remaining_command = -1;
                    self.remaining_content = -1;
                    self.remaining_padding = -1;
                    // «shouldn't happen» у Xray: хвост после последнего блока.
                    out.extend_from_slice(b);
                    break;
                }
            }
        }
    }
}

/// Заголовок ответа VLESS: версия(1), длина addons(1), addons.
#[derive(Debug)]
enum RespState {
    Prefix { got: u8, version: u8 },
    Addons { remaining: usize },
    Done,
}

impl RespState {
    /// Сколько байт в начале `b` — ещё заголовок ответа.
    fn strip(&mut self, b: &[u8]) -> io::Result<usize> {
        let mut i = 0;
        while i < b.len() {
            match self {
                RespState::Done => break,
                RespState::Prefix { got, version } => {
                    if *got == 0 {
                        *version = b[i];
                        if *version != crate::vless::protocol::PROTOCOL_VERSION {
                            return Err(io::Error::other(format!(
                                "VLESS: неожиданная версия в ответе сервера: {version}"
                            )));
                        }
                        *got = 1;
                    } else {
                        let len = b[i] as usize;
                        *self = if len == 0 {
                            RespState::Done
                        } else {
                            RespState::Addons { remaining: len }
                        };
                    }
                    i += 1;
                }
                RespState::Addons { remaining } => {
                    let k = (*remaining).min(b.len() - i);
                    i += k;
                    *remaining -= k;
                    if *remaining == 0 {
                        *self = RespState::Done;
                    }
                }
            }
        }
        Ok(i)
    }
}

struct OutChunk {
    data: Vec<u8>,
    pos: usize,
    direct: bool,
}

/// VLESS-поток с XTLS Vision поверх внешнего TLS/REALITY.
pub struct VisionStream {
    tls: TlsBoxedStream,
    /// Разбор заголовка ответа VLESS (версия, длина addons, addons) —
    /// здесь, а не в `VlessStream`, потому что читать внешний TLS нужно
    /// строго по одному рекорду (см. `poll_read`).
    resp: RespState,
    state: TrafficState,

    // --- запись (uplink) ---
    header: Option<BytesMut>,
    uuid_once: Option<[u8; 16]>,
    is_padding: bool,
    /// Отправлен блок `Direct`: следующая запись пойдёт напрямую в TCP
    /// (у Xray переключение тоже происходит в начале следующей записи).
    switch_write_pending: bool,
    write_direct: bool,
    out: VecDeque<OutChunk>,
    first_data_timer: Option<Pin<Box<tokio::time::Sleep>>>,

    // --- чтение (downlink) ---
    unpadder: Unpadder,
    within_padding: bool,
    read_direct: bool,
    rbuf: Box<[u8]>,
    pending: Vec<u8>,
    pending_pos: usize,
}

impl std::fmt::Debug for VisionStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisionStream")
            .field("state", &self.state)
            .field("is_padding", &self.is_padding)
            .field("write_direct", &self.write_direct)
            .field("read_direct", &self.read_direct)
            .finish_non_exhaustive()
    }
}

impl VisionStream {
    /// `tls` — уже установленный внешний TLS 1.3/REALITY (с `RawConn` в
    /// режиме `record_aligned`), `header` — заголовок запроса VLESS с
    /// flow в addons; он уйдёт вместе с первыми данными.
    pub fn new(tls: TlsBoxedStream, id: &Uuid, header: BytesMut) -> Self {
        let uuid = *id.as_bytes();
        Self {
            tls,
            resp: RespState::Prefix { got: 0, version: 0 },
            state: TrafficState::new(),
            header: Some(header),
            uuid_once: Some(uuid),
            is_padding: true,
            switch_write_pending: false,
            write_direct: false,
            out: VecDeque::new(),
            first_data_timer: Some(Box::pin(tokio::time::sleep(FIRST_DATA_WAIT))),
            unpadder: Unpadder::new(uuid),
            within_padding: true,
            read_direct: false,
            rbuf: vec![0u8; 16 * 1024 + 256].into_boxed_slice(),
            pending: Vec::new(),
            pending_pos: 0,
        }
    }

    /// Отправка уже идёт напрямую в TCP (без внешнего TLS).
    pub fn is_write_direct(&self) -> bool {
        self.write_direct
    }

    /// Чтение уже идёт напрямую из TCP.
    pub fn is_read_direct(&self) -> bool {
        self.read_direct
    }

    fn tls(&mut self) -> &mut TlsBoxedStream {
        &mut self.tls
    }

    /// Первая запись: заголовок VLESS + блок(и) с данными (или один
    /// padding, если данных нет).
    fn queue_padded(&mut self, data: Option<&[u8]>) {
        let mut out = Vec::with_capacity(data.map_or(0, |d| d.len()) + 1400);
        if let Some(h) = self.header.take() {
            out.extend_from_slice(&h);
        }
        self.first_data_timer = None;

        match data {
            None => {
                // `mb[0] == nil`: длинный padding без данных, чтобы спрятать
                // длину заголовка VLESS.
                xtls_padding(
                    &[],
                    COMMAND_PADDING_CONTINUE,
                    &mut self.uuid_once,
                    true,
                    &mut out,
                );
            }
            Some(data) => {
                let is_complete = is_complete_record(data);
                let mb = reshape(data);
                let mut long_padding = self.state.is_tls;
                let last = mb.len() - 1;
                let mut i = 0;
                while i < mb.len() {
                    let b = mb[i];
                    if self.state.is_tls
                        && b.len() >= 6
                        && b[..3] == TLS_APPLICATION_DATA_START
                        && is_complete
                    {
                        if self.state.enable_xtls {
                            self.switch_write_pending = true;
                        }
                        let mut command = COMMAND_PADDING_CONTINUE;
                        if i == last {
                            command = if self.state.enable_xtls {
                                COMMAND_PADDING_DIRECT
                            } else {
                                COMMAND_PADDING_END
                            };
                        }
                        xtls_padding(b, command, &mut self.uuid_once, true, &mut out);
                        self.is_padding = false;
                        long_padding = false;
                        i += 1;
                        continue;
                    } else if !self.state.is_tls12_or_above
                        && self.state.number_of_packet_to_filter <= 1
                    {
                        // Совместимость со старыми получателями Vision:
                        // padding заканчивается на пакет раньше.
                        self.is_padding = false;
                        xtls_padding(
                            b,
                            COMMAND_PADDING_END,
                            &mut self.uuid_once,
                            long_padding,
                            &mut out,
                        );
                        for rest in &mb[i + 1..] {
                            out.extend_from_slice(rest);
                        }
                        break;
                    }
                    let mut command = COMMAND_PADDING_CONTINUE;
                    if i == last && !self.is_padding {
                        command = if self.state.enable_xtls {
                            COMMAND_PADDING_DIRECT
                        } else {
                            COMMAND_PADDING_END
                        };
                    }
                    xtls_padding(b, command, &mut self.uuid_once, long_padding, &mut out);
                    i += 1;
                }
            }
        }
        self.out.push_back(OutChunk {
            data: out,
            pos: 0,
            direct: false,
        });
    }

    /// Дописать очередь в сокет (внешний TLS или напрямую в TCP).
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut wrote_tls = false;
        while let Some(front) = self.out.front_mut() {
            let direct = front.direct;
            let data = &front.data[front.pos..];
            let n = if direct {
                ready!(Pin::new(self.tls.get_mut().0).poll_write(cx, data))?
            } else {
                wrote_tls = true;
                ready!(Pin::new(&mut self.tls).poll_write(cx, data))?
            };
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            #[allow(
                clippy::expect_used,
                reason = "инвариант: элемент есть (while let выше), берётся заново из-за заимствования"
            )]
            let front = self.out.front_mut().expect("есть элемент");
            front.pos += n;
            if front.pos == front.data.len() {
                self.out.pop_front();
            }
        }
        if wrote_tls {
            ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    /// Применить отложенное переключение записи на прямую передачу: всё,
    /// что ушло во внешний TLS, должно быть в сокете раньше сырых байт.
    fn poll_apply_write_switch(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.switch_write_pending {
            ready!(self.poll_drain(cx))?;
            ready!(Pin::new(self.tls()).poll_flush(cx))?;
            self.switch_write_pending = false;
            self.write_direct = true;
            tracing::debug!("Vision: отправка переключена на прямую передачу");
        }
        Poll::Ready(Ok(()))
    }

    /// Разобрать кусок, прочитанный из внешнего TLS (`VisionReader`).
    fn process_read_chunk(&mut self, n: usize) {
        let mut data = Vec::new();
        let chunk = &self.rbuf[..n];
        if self.within_padding || self.state.number_of_packet_to_filter > 0 {
            self.unpadder.feed(chunk, &mut data);
            let u = &self.unpadder;
            if u.remaining_content > 0 || u.remaining_padding > 0 || u.current_command == 0 {
                self.within_padding = true;
            } else if u.current_command == COMMAND_PADDING_END {
                self.within_padding = false;
            } else if u.current_command == COMMAND_PADDING_DIRECT {
                self.within_padding = false;
                self.read_direct = true;
            }
        } else {
            data.extend_from_slice(chunk);
        }
        if self.state.number_of_packet_to_filter > 0 && !data.is_empty() {
            self.state.filter_tls(&[&data]);
        }
        if self.pending_pos == self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        self.pending.extend_from_slice(&data);
    }

    /// После `Direct` от сервера: всё, что rustls успел расшифровать, —
    /// отдать как есть, а дальше читать TCP напрямую (остаток буфера
    /// `RawConn` — как `rawInput` у Go).
    fn switch_read_to_direct(&mut self) -> io::Result<()> {
        let mut tmp = [0u8; 4096];
        loop {
            let conn = &mut self.tls.get_mut().1;
            match io::Read::read(&mut conn.reader(), &mut tmp) {
                Ok(0) => break,
                Ok(n) => self.pending.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        self.tls.get_mut().0.switch_to_direct();
        tracing::debug!("Vision: приём переключён на прямую передачу");
        Ok(())
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Приложение молчит 500 мс — заголовок VLESS уходит с одним padding.
        if let Some(t) = this.first_data_timer.as_mut() {
            if t.as_mut().poll(cx).is_ready() && this.header.is_some() {
                tracing::debug!("Vision: данных от приложения нет, отправляю заголовок с padding");
                this.queue_padded(None);
            }
        }
        if !this.out.is_empty() {
            // Результат не важен: если сокет занят, допишем при следующей
            // возможности (запись сама будит задачу).
            if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                return Poll::Ready(Err(e));
            }
        }

        loop {
            if this.pending_pos < this.pending.len() {
                let n = (this.pending.len() - this.pending_pos).min(out.remaining());
                out.put_slice(&this.pending[this.pending_pos..this.pending_pos + n]);
                this.pending_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.read_direct {
                return Pin::new(this.tls.get_mut().0).poll_read(cx, out);
            }
            // Ровно один рекорд внешнего TLS за раз: `poll_fill_buf`
            // отдаёт открытый текст одного рекорда. `poll_read` у
            // tokio-rustls так не умеет — он дочитывает следующие рекорды,
            // пока есть место в буфере, и после блока `Direct` проглотил
            // бы уже сырые байты внутреннего TLS (а при ошибке расшифровки
            // ещё и отправил бы alert в поток). Поймано интероп-тестом.
            let data = ready!(tokio::io::AsyncBufRead::poll_fill_buf(
                Pin::new(&mut this.tls),
                cx
            ))
            .map_err(|e| io::Error::new(e.kind(), format!("Vision (внешний TLS): {e}")))?;
            if data.is_empty() {
                if !matches!(this.resp, RespState::Done) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VLESS: соединение закрыто до получения заголовка ответа",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            let n = data.len().min(this.rbuf.len());
            this.rbuf[..n].copy_from_slice(&data[..n]);
            tokio::io::AsyncBufRead::consume(Pin::new(&mut this.tls), n);
            let skip = this.resp.strip(&this.rbuf[..n])?;
            if skip == n {
                continue;
            }
            this.rbuf.copy_within(skip..n, 0);
            let n = n - skip;
            this.process_read_chunk(n);
            if this.read_direct {
                this.switch_read_to_direct()?;
            }
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        ready!(this.poll_apply_write_switch(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.state.number_of_packet_to_filter > 0 {
            let parts: Vec<&[u8]> = buf.chunks(BUF_SIZE).collect();
            this.state.filter_tls(&parts);
        }

        if this.is_padding || this.header.is_some() {
            // Не больше 64 КБ за раз: очередь не должна расти без предела.
            let take = buf.len().min(64 * 1024);
            if this.is_padding {
                this.queue_padded(Some(&buf[..take]));
            } else {
                let mut data = Vec::with_capacity(take + 64);
                if let Some(h) = this.header.take() {
                    data.extend_from_slice(&h);
                }
                data.extend_from_slice(&buf[..take]);
                this.out.push_back(OutChunk {
                    data,
                    pos: 0,
                    direct: false,
                });
            }
            if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(take));
        }

        if this.write_direct {
            Pin::new(this.tls.get_mut().0).poll_write(cx, buf)
        } else {
            Pin::new(&mut this.tls).poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.write_direct {
            Pin::new(this.tls.get_mut().0).poll_flush(cx)
        } else {
            Pin::new(&mut this.tls).poll_flush(cx)
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.header.is_some() {
            this.queue_padded(None);
        }
        ready!(this.poll_drain(cx))?;
        ready!(this.poll_apply_write_switch(cx))?;
        if this.write_direct {
            Pin::new(this.tls.get_mut().0).poll_shutdown(cx)
        } else {
            Pin::new(&mut this.tls).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid() -> [u8; 16] {
        *Uuid::parse_str("11111111-2222-3333-4444-555555555555")
            .unwrap()
            .as_bytes()
    }

    #[test]
    fn padding_roundtrip_through_unpadder() {
        let u = uuid();
        let mut once = Some(u);
        let mut wire = Vec::new();
        xtls_padding(
            b"hello",
            COMMAND_PADDING_CONTINUE,
            &mut once,
            true,
            &mut wire,
        );
        xtls_padding(b" world", COMMAND_PADDING_END, &mut once, false, &mut wire);
        assert!(once.is_none(), "UUID только в первом блоке");
        assert_eq!(&wire[..16], &u);
        // Длинный padding для короткого содержимого: ≥ 900 - 5.
        let pad1 = u16::from_be_bytes([wire[19], wire[20]]) as usize;
        assert!((895..900 + 500).contains(&pad1), "{pad1}");

        // Разбор кусками разной длины даёт исходные данные и команду End.
        for step in [1usize, 7, 64, 5000] {
            let mut un = Unpadder::new(u);
            let mut out = Vec::new();
            for c in wire.chunks(step) {
                un.feed(c, &mut out);
            }
            assert_eq!(out, b"hello world", "шаг {step}");
            assert_eq!(un.current_command, COMMAND_PADDING_END);
            assert!(un.initial());
        }
    }

    #[test]
    fn unpadder_passes_through_unpadded_data() {
        let mut un = Unpadder::new(uuid());
        let mut out = Vec::new();
        un.feed(b"this is definitely not a padded vision block", &mut out);
        assert_eq!(out, b"this is definitely not a padded vision block");
    }

    #[test]
    fn complete_record_detection() {
        let mut r = vec![0x17, 0x03, 0x03, 0x00, 0x03, 1, 2, 3];
        assert!(is_complete_record(&r));
        r.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x02, 9]);
        assert!(!is_complete_record(&r), "второй рекорд неполный");
        assert!(!is_complete_record(&[0x16, 0x03, 0x03, 0x00, 0x01, 0]));
    }

    #[test]
    fn filter_detects_tls13_server_hello() {
        // Минимальный ServerHello TLS 1.3: sid 32 байта, шифр 0x1301,
        // расширение supported_versions = 0x0304.
        let mut body = vec![0x02, 0, 0, 0, 0x03, 0x03];
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0xBB; 32]); // session id
        body.extend_from_slice(&[0x13, 0x01, 0x00]);
        let ext = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);

        let mut st = TrafficState::new();
        st.filter_tls(&[&rec]);
        assert!(st.is_tls && st.is_tls12_or_above);
        assert_eq!(st.cipher, 0x1301);
        assert!(st.enable_xtls);
        assert_eq!(st.number_of_packet_to_filter, 0);
    }

    #[test]
    fn reshape_splits_oversized_buffers() {
        let data = vec![0u8; BUF_SIZE + 100];
        let parts = reshape(&data);
        assert_eq!(parts.iter().map(|p| p.len()).sum::<usize>(), data.len());
        assert!(parts.iter().all(|p| p.len() < BUF_SIZE - BLOCK_OVERHEAD));
    }
}
