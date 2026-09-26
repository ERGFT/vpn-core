//! Двустороннее копирование байт между локальным SOCKS5-клиентом и
//! удалённым VLESS-соединением.
//!
//! Этап 2: буфер каждого направления копирования аллоцируется ровно
//! один раз при старте соединения и живёт до его конца — не глобальный
//! shared pool (нет межсоединенческой синхронизации/contention) и не
//! пересоздание на каждый пакет (нет churn аллокатора в hot path).
//!
//! Сознательно НЕ переизобретаем низкоуровневый poll-based state machine
//! `tokio::io::copy_bidirectional` (см. риск "соло против комьюнити" в
//! PLAN.md, Этап 4) — вместо этого разбиваем каждый поток на
//! read/write-половины через `tokio::io::split` (это стандартный,
//! отлично протестированный примитив tokio) и гоняем поверх них простой
//! ручной цикл `read`/`write_all` с закреплённым буфером. Это даёт нам
//! контроль над размером и временем жизни буфера, оставаясь на
//! проверенных примитивах там, где цена ошибки (use-after-free,
//! переиспользование чужих данных между сессиями) особенно высока.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::error::Result;

/// Соединение закрывается, если ни в одну сторону не прошло ни байта за
/// это время (у Xray — `connIdle`, 300 с). Без этого соединение, у
/// которого замолчал сервер или тихо пропала сеть, висело вечно вместе
/// с сокетами и буферами.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Когда одна сторона уже закончила (прислала EOF), вторая получает
/// столько времени тишины (у Xray — `uplinkOnly`/`downlinkOnly`, 1–5 с;
/// берём с запасом: полузакрытие бывает и у честных протоколов).
pub const HALF_CLOSED_TIMEOUT: Duration = Duration::from_secs(30);

/// Таймауты простоя для [`copy_bidirectional_with_timeouts`].
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub idle: Duration,
    pub half_closed: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            idle: IDLE_TIMEOUT,
            half_closed: HALF_CLOSED_TIMEOUT,
        }
    }
}

/// Размер буфера на одно направление по умолчанию. Сделан константой, а
/// не "магическим числом" внутри цикла — Этап 7 (профилирование
/// аллокаторов/аллокаций) будет подбирать это значение осмысленно, а не
/// вслепую.
///
/// 17 КиБ, а не 16: полный TLS-рекорд приложения — 16 КиБ данных плюс
/// заголовок и тег (у OpenSSL/BoringSSL 16 406 байт). XTLS Vision
/// переключает отправку на прямую передачу, только увидев целые рекорды
/// прикладных данных в одной записи; с буфером в ровно 16 КиБ крупные
/// рекорды всегда резались пополам, и при отправке больших объёмов
/// переключение не происходило никогда (найдено smoke-тестом против
/// Xray-core). Цена — 1 КиБ на направление соединения.
pub const DEFAULT_BUFFER_SIZE: usize = 17 * 1024;

#[derive(Debug, Default, Clone, Copy)]
pub struct RelayStats {
    pub client_to_remote: u64,
    pub remote_to_client: u64,
    /// Соединение закрыто по простою, а не по EOF с обеих сторон.
    pub idle_closed: bool,
}

/// Перекачать байты в обе стороны с буфером по умолчанию, пока одна из
/// сторон не закроется. Потребляет оба потока владением (не `&mut`) —
/// это то, что реально позволяет разбить каждый на read- и
/// write-половину и гонять оба направления конкурентно без чужого
/// unsafe/интерьерной изменяемости.
pub async fn copy_bidirectional<A, B>(a: A, b: B) -> Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional_with_timeouts(a, b, DEFAULT_BUFFER_SIZE, Timeouts::default()).await
}

/// Как [`copy_bidirectional`], но с явным размером буфера на
/// направление — нужен тестам и будущему Этапу 7 (профилирование
/// аллокаторов на разных размерах буфера).
pub async fn copy_bidirectional_with_buffer_size<A, B>(
    a: A,
    b: B,
    buf_size: usize,
) -> Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional_with_timeouts(a, b, buf_size, Timeouts::default()).await
}

/// Как [`copy_bidirectional_with_buffer_size`], но с явными таймаутами
/// простоя (см. [`Timeouts`]).
pub async fn copy_bidirectional_with_timeouts<A, B>(
    a: A,
    b: B,
    buf_size: usize,
    timeouts: Timeouts,
) -> Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = split(a);
    let (mut b_read, mut b_write) = split(b);

    // Буфер каждого направления закреплён за этим вызовом (= за этим
    // соединением) на весь его срок жизни — выделяется один раз здесь,
    // а не заново на каждую итерацию цикла внутри `pump`.
    let mut client_to_remote_buf = vec![0u8; buf_size];
    let mut remote_to_client_buf = vec![0u8; buf_size];

    let activity = Activity::new();
    let client_to_remote = pump(
        &mut a_read,
        &mut b_write,
        &mut client_to_remote_buf,
        &activity,
        0,
    );
    let remote_to_client = pump(
        &mut b_read,
        &mut a_write,
        &mut remote_to_client_buf,
        &activity,
        1,
    );
    let both = async { tokio::try_join!(client_to_remote, remote_to_client) };

    tokio::select! {
        r = both => {
            let (client_to_remote, remote_to_client) = r?;
            Ok(RelayStats { client_to_remote, remote_to_client, idle_closed: false })
        }
        _ = activity.watchdog(timeouts) => {
            tracing::debug!("соединение закрыто по простою");
            Ok(RelayStats {
                client_to_remote: activity.bytes[0].load(Ordering::Relaxed),
                remote_to_client: activity.bytes[1].load(Ordering::Relaxed),
                idle_closed: true,
            })
        }
    }
}

/// Общее для обоих направлений: когда последний раз шли данные и
/// закончилась ли уже какая-то сторона.
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
    half_closed: AtomicBool,
    bytes: [AtomicU64; 2],
}

impl Activity {
    fn new() -> Self {
        Activity {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
            half_closed: AtomicBool::new(false),
            bytes: [AtomicU64::new(0), AtomicU64::new(0)],
        }
    }

    fn touch(&self) {
        let ms = self.start.elapsed().as_millis() as u64;
        self.last_ms.fetch_max(ms, Ordering::Relaxed);
    }

    /// Завершается, когда простой превысил допустимый.
    async fn watchdog(&self, t: Timeouts) {
        loop {
            let limit = if self.half_closed.load(Ordering::Relaxed) {
                t.half_closed
            } else {
                t.idle
            };
            let deadline =
                self.start + Duration::from_millis(self.last_ms.load(Ordering::Relaxed)) + limit;
            if Instant::now() >= deadline {
                return;
            }
            // Просыпаемся не реже раза в секунду: половина соединения
            // могла закрыться, и предел сократился.
            let wake = deadline.min(Instant::now() + Duration::from_secs(1));
            tokio::time::sleep_until(wake).await;
        }
    }
}

/// Один цикл "прочитать в закреплённый буфер -> записать" до EOF, затем
/// корректно закрыть запись на приёмнике, чтобы вторая половина тоже
/// увидела EOF и завершилась.
async fn pump<R, W>(
    r: &mut R,
    w: &mut W,
    buf: &mut [u8],
    activity: &Activity,
    dir: usize,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        let n = r.read(buf).await?;
        if n == 0 {
            break;
        }
        activity.touch();
        activity.bytes[dir].fetch_add(n as u64, Ordering::Relaxed);
        w.write_all(&buf[..n]).await?;
        // Дописать всё, что осело в буферах записи (TLS держит шифротекст
        // у себя, если сокет был занят; Vision — свою очередь). Без этого
        // хвост мог застрять до следующей записи: задача ждёт новых данных
        // от читателя, а про недописанное никто не вспоминает.
        w.flush().await?;
        total += n as u64;
    }
    // Ошибку shutdown сознательно не пробрасываем: обе стороны релея уже
    // выполнили свою полезную работу (перекачали то, что должны были),
    // а закрытие уже полуразорванного соединения бывает ошибкой на
    // некоторых транспортах (например, TLS close_notify после того как
    // TCP уже закрыт с той стороны) — это не повод считать весь релей
    // проваленным.
    activity.touch();
    activity.half_closed.store(true, Ordering::Relaxed);
    let _ = w.shutdown().await;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Полностью in-memory тест (никакого реального сокета/TLS) — по
    /// плану Этапа 2 именно такие тесты должны быть в первую очередь
    /// прогоняемы под `cargo +nightly miri test -p reality-core --lib`,
    /// поскольку miri не умеет в реальные сетевые syscalls, но со
    /// `tokio::io::duplex` (чистый in-memory канал) работает.
    #[tokio::test]
    async fn relays_both_directions_and_reuses_fixed_buffers() {
        let (mut client, server_side_a) = duplex(64);
        let (server_side_b, mut echo) = duplex(64);

        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 8];
            loop {
                match echo.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(k) => {
                        if echo.write_all(&buf[..k]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let relay_task = tokio::spawn(async move {
            copy_bidirectional_with_buffer_size(server_side_a, server_side_b, 8)
                .await
                .unwrap()
        });

        client.write_all(b"ping-pong").await.unwrap();
        let mut got = vec![0u8; 9];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping-pong");
        drop(client);

        let stats = relay_task.await.unwrap();
        assert_eq!(stats.client_to_remote, 9);
        assert_eq!(stats.remote_to_client, 9);
        assert!(!stats.idle_closed);
        echo_task.await.unwrap();
    }

    /// Сервер замолчал навсегда — соединение закрывается по простою.
    #[tokio::test(start_paused = true)]
    async fn silent_remote_is_closed_after_idle_timeout() {
        let (mut client, relay_a) = duplex(64);
        let (relay_b, _silent_remote) = duplex(64);
        let relay = tokio::spawn(copy_bidirectional_with_timeouts(
            relay_a,
            relay_b,
            8,
            Timeouts {
                idle: Duration::from_secs(300),
                half_closed: Duration::from_secs(30),
            },
        ));
        client.write_all(b"hi").await.unwrap();
        tokio::time::sleep(Duration::from_secs(299)).await;
        assert!(!relay.is_finished(), "до таймаута простоя соединение живо");
        tokio::time::sleep(Duration::from_secs(3)).await;
        let stats = relay.await.unwrap().unwrap();
        assert!(stats.idle_closed);
        assert_eq!(stats.client_to_remote, 2);
    }

    /// Приложение закрыло свою сторону, сервер молчит — закрываем
    /// быстрее, по таймауту полузакрытого соединения.
    #[tokio::test(start_paused = true)]
    async fn half_closed_connection_uses_short_timeout() {
        let (client, relay_a) = duplex(64);
        let (relay_b, _silent_remote) = duplex(64);
        let relay = tokio::spawn(copy_bidirectional_with_timeouts(
            relay_a,
            relay_b,
            8,
            Timeouts {
                idle: Duration::from_secs(300),
                half_closed: Duration::from_secs(30),
            },
        ));
        drop(client);
        tokio::time::sleep(Duration::from_secs(35)).await;
        let stats = relay.await.unwrap().unwrap();
        assert!(stats.idle_closed);
    }
}
