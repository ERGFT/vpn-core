// SPDX-License-Identifier: GPL-3.0-or-later
//! Сквозная проверка транспорта Этапа 4 (WebSocket): настоящий TCP+TLS
//! (самоподписанный тестовый сертификат, как в `tls_loopback.rs`) плюс
//! настоящий WS upgrade и фреймирование через `async-tungstenite` — не
//! против реального Xray/V2Ray-сервера (такого здесь нет), а против
//! собственного тестового WS-сервера. Подтверждает, что склейка
//! TLS -> WS -> `tokio::io::AsyncRead/AsyncWrite` -> `vless_connect`
//! работает как единое целое.

use std::sync::Arc;

use async_tungstenite::accept_async;
use async_tungstenite::tungstenite::Message;
use futures_util::StreamExt;
use rcgen::generate_simple_self_signed;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::TokioAsyncReadCompatExt;
use uuid::Uuid;

use reality_core::transport::tcp_tls::{connect_tls_with_roots, ensure_crypto_provider};
use reality_core::vless::protocol::vless_connect;
use reality_core::vless::{Address, Command, VlessConfig};

/// version(1) + uuid(16) + addons_len(1) + cmd(1) + port(2) + atyp(1) +
/// domain_len(1) + "example.com"(11) = 34 байт — ровно то, что уходит
/// одним WS-сообщением из `vless_connect` для этого конкретного адреса.
const REQUEST_HEADER_LEN: usize = 1 + 16 + 1 + 1 + 2 + 1 + 1 + 11;

#[tokio::test]
async fn ws_full_roundtrip_over_real_tls() {
    ensure_crypto_provider();

    let cert_key = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert_key.cert.der().clone();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()));

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).unwrap();

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let id = Uuid::new_v4();
    let id_for_server = id;

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor
            .accept(tcp)
            .await
            .expect("серверное TLS-рукопожатие");
        let mut ws = accept_async(tls.compat())
            .await
            .expect("серверное WS-рукопожатие");

        // Накапливаем входящие Binary-сообщения, пока не соберём весь
        // заголовок запроса VLESS (может прийти одним фреймом, а может
        // и по кусочкам — тест не полагается на то, как именно).
        let mut buf = Vec::new();
        while buf.len() < REQUEST_HEADER_LEN {
            match ws.next().await {
                Some(Ok(Message::Binary(b))) => buf.extend_from_slice(&b),
                other => panic!("ожидался Binary-фрейм с заголовком VLESS, получено {other:?}"),
            }
        }
        assert_eq!(buf[0], 0x00, "версия протокола");
        assert_eq!(&buf[1..17], id_for_server.as_bytes(), "uuid клиента");
        assert_eq!(buf[18], Command::Tcp as u8, "команда");

        ws.send(Message::Binary(vec![0x00, 0x00].into()))
            .await
            .expect("отправить заголовок ответа VLESS");

        // Дальше — обычное эхо: что пришло, то и вернуть.
        while let Some(Ok(msg)) = ws.next().await {
            if let Message::Binary(b) = msg {
                if ws.send(Message::Binary(b)).await.is_err() {
                    break;
                }
            }
        }
    });

    let cfg = VlessConfig::parse(&format!(
        "vless://{id}@127.0.0.1:{}?encryption=none&security=tls&sni=localhost&type=ws&path=/vless",
        addr.port()
    ))
    .unwrap();

    // connect_and_handshake_ws сам поднимает TLS через встроенный набор
    // публичных корней — для теста нам нужен наш тестовый корень, так
    // что рукопожатие собираем вручную теми же шагами, что и внутри
    // transport::ws, но с connect_tls_with_roots вместо connect_tls.
    let tls = connect_tls_with_roots(&cfg, roots).await.unwrap();
    let compat_tls = tls.compat();

    let uri = format!("wss://{}{}", cfg.effective_sni(), cfg.path());
    let request = async_tungstenite::tungstenite::http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", cfg.effective_sni())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            async_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .unwrap();

    let (ws, _resp) = async_tungstenite::client_async(request, compat_tls)
        .await
        .expect("клиентский WS upgrade");
    let client = ws_stream_tungstenite::WsStream::new(ws);

    let target = Address::Domain("example.com".to_string());
    let mut client = vless_connect(client, &id, Command::Tcp, &target, 443)
        .await
        .expect("vless handshake поверх WS");

    let payload = b"hello over websocket tunnel";
    client.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, payload);

    drop(client);
    server_task.await.unwrap();
}
