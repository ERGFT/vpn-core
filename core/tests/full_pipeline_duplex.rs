// SPDX-License-Identifier: GPL-3.0-or-later
//! Сквозной тест Этапа 1 без реальной сети/TLS: приложение -> SOCKS5 ->
//! (VLESS-рукопожатие + релей) -> фейковый VLESS-сервер -> эхо обратно.
//!
//! Проверяет ровно ту склейку модулей, что использует `bin/client`
//! (`socks5::handshake` -> `vless_connect` -> `relay::copy_bidirectional`),
//! но на `tokio::io::duplex` — быстро, детерминированно, без портов и
//! сертификатов. Реальный TCP+TLS отдельно покрыт `tls_loopback.rs`.

use std::net::SocketAddr;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use reality_core::relay;
use reality_core::socks5::{self, TargetAddr};
use reality_core::vless::protocol::{vless_connect, Address, Command};

#[tokio::test]
async fn full_pipeline_over_duplex() {
    // локальное "приложение" <-> наш SOCKS5-сервер
    let (mut app, mut socks_side) = duplex(4096);
    // наш "клиент VLESS" <-> фейковый удалённый сервер
    let (remote_client_side, mut fake_server) = duplex(4096);

    let id = Uuid::new_v4();
    let id_for_server = id;

    let server_task = tokio::spawn(async move {
        let mut prefix = [0u8; 1 + 16 + 1 + 1 + 2 + 1]; // version+uuid+addons_len+cmd+port+atyp
        fake_server.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix[0], 0x00, "версия протокола");
        assert_eq!(&prefix[1..17], id_for_server.as_bytes(), "uuid клиента");
        assert_eq!(prefix[17], 0, "addons len");
        assert_eq!(prefix[18], Command::Tcp as u8, "команда");
        let port = u16::from_be_bytes([prefix[19], prefix[20]]);
        assert_eq!(port, 443);
        assert_eq!(prefix[21], 0x02, "тип адреса: домен");

        let mut len_buf = [0u8; 1];
        fake_server.read_exact(&mut len_buf).await.unwrap();
        let mut domain = vec![0u8; len_buf[0] as usize];
        fake_server.read_exact(&mut domain).await.unwrap();
        assert_eq!(domain, b"example.com");

        // ответ сервера: версия 0, addons 0
        fake_server.write_all(&[0x00, 0x00]).await.unwrap();

        // дальше — просто эхо, как будто там реальный сайт отвечает
        let mut buf = vec![0u8; 4096];
        loop {
            match fake_server.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    if fake_server.write_all(&buf[..k]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Наш клиент выполняет VLESS-рукопожатие поверх "транспорта"
    // (здесь — duplex вместо TLS; сам протокол транспорту не доверяет).
    let target = Address::Domain("example.com".to_string());
    let remote_client_side = vless_connect(remote_client_side, &id, Command::Tcp, &target, 443)
        .await
        .expect("vless handshake должен пройти");

    // Локальное приложение делает обычный SOCKS5 CONNECT example.com:443
    let socks_client_task = tokio::spawn(async move {
        app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet_resp = [0u8; 2];
        app.read_exact(&mut greet_resp).await.unwrap();
        assert_eq!(greet_resp, [0x05, 0x00]);

        let domain = b"example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&443u16.to_be_bytes());
        app.write_all(&req).await.unwrap();

        let mut connect_resp = [0u8; 10];
        app.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00, "SOCKS5 CONNECT должен вернуть успех");

        let payload = b"hello through the tunnel";
        app.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "эхо должно вернуться без искажений");

        drop(app);
    });

    let socks_req = socks5::handshake(&mut socks_side)
        .await
        .expect("socks5 handshake должен пройти");
    assert_eq!(
        socks_req.addr,
        TargetAddr::Domain("example.com".to_string())
    );
    assert_eq!(socks_req.port, 443);

    let bind: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    socks5::reply_success(&mut socks_side, bind)
        .await
        .expect("ответ клиенту должен отправиться");

    let stats = relay::copy_bidirectional(socks_side, remote_client_side)
        .await
        .expect("релей должен завершиться без ошибки ввода-вывода");
    assert!(
        stats.client_to_remote > 0,
        "клиент должен был что-то отправить"
    );
    assert!(
        stats.remote_to_client > 0,
        "сервер должен был что-то ответить"
    );

    socks_client_task.await.unwrap();
    server_task.await.unwrap();
}
