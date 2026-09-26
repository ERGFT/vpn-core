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

use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Result;

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
    copy_bidirectional_with_buffer_size(a, b, DEFAULT_BUFFER_SIZE).await
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
    let (mut a_read, mut a_write) = split(a);
    let (mut b_read, mut b_write) = split(b);

    // Буфер каждого направления закреплён за этим вызовом (= за этим
    // соединением) на весь его срок жизни — выделяется один раз здесь,
    // а не заново на каждую итерацию цикла внутри `pump`.
    let mut client_to_remote_buf = vec![0u8; buf_size];
    let mut remote_to_client_buf = vec![0u8; buf_size];

    let client_to_remote = pump(&mut a_read, &mut b_write, &mut client_to_remote_buf);
    let remote_to_client = pump(&mut b_read, &mut a_write, &mut remote_to_client_buf);

    let (client_to_remote, remote_to_client) =
        tokio::try_join!(client_to_remote, remote_to_client)?;

    Ok(RelayStats {
        client_to_remote,
        remote_to_client,
    })
}

/// Один цикл "прочитать в закреплённый буфер -> записать" до EOF, затем
/// корректно закрыть запись на приёмнике, чтобы вторая половина тоже
/// увидела EOF и завершилась.
async fn pump<R, W>(r: &mut R, w: &mut W, buf: &mut [u8]) -> Result<u64>
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
        echo_task.await.unwrap();
    }
}
