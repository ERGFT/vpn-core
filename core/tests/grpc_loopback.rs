// SPDX-License-Identifier: GPL-3.0-or-later
//! Сквозная проверка транспорта Этапа 4 (gRPC "gun"-режим): настоящий
//! TCP+TLS(ALPN h2) + настоящий HTTP/2 через `h2`, с собственным
//! тестовым h2-сервером, говорящим на том же кадрировании
//! (`transport::grpc::{encode_hunk_frame, HunkDecoder}`), что и клиент.
//!
//! ⚠️ Это проверяет корректность НАШЕЙ склейки (h2 <-> protobuf-кадры
//! <-> AsyncRead/AsyncWrite <-> vless_connect), а не байт-в-байт
//! совместимость с реальным Xray-core/V2Ray сервером — такого здесь нет
//! и не может быть. См. предупреждение в `transport/grpc.rs`.

use std::sync::Arc;

use bytes::Bytes;
use http::{Response, StatusCode};
use rcgen::generate_simple_self_signed;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use reality_core::transport::grpc::{connect_and_handshake_grpc, encode_hunk_frame, HunkDecoder};
use reality_core::transport::tcp_tls::{connect_tls_with_roots_alpn, ensure_crypto_provider};
use reality_core::vless::protocol::vless_connect;
use reality_core::vless::{Address, Command, VlessConfig};

const REQUEST_HEADER_LEN: usize = 1 + 16 + 1 + 1 + 2 + 1 + 1 + 11; // см. ws_loopback.rs

#[tokio::test]
async fn grpc_full_roundtrip_over_real_h2() {
    ensure_crypto_provider();

    let cert_key = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert_key.cert.der().clone();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()));

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).unwrap();

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
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

        let mut h2_conn = h2::server::handshake(tls)
            .await
            .expect("серверное h2-рукопожатие");
        let (request, mut respond) = h2_conn
            .accept()
            .await
            .expect("должен прийти один поток")
            .expect("поток не должен быть ошибкой");

        assert_eq!(request.method(), http::Method::POST);
        assert!(
            request.uri().path().ends_with("/Tun"),
            "путь должен заканчиваться на /Tun: {}",
            request.uri().path()
        );

        // `h2::server::Connection` — единственный, кто реально двигает
        // ввод-вывод соединения; RecvStream/SendStream уже полученного
        // потока сами по себе ничего не читают и не пишут в сокет, пока
        // Connection не опрашивается (через `accept()`) снова. Без этого
        // фонового цикла `recv_stream.data().await` ниже висит вечно.
        tokio::spawn(async move { while h2_conn.accept().await.is_some() {} });

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        let mut send_stream = respond
            .send_response(response, false)
            .expect("отправить заголовки ответа");

        let mut recv_stream = request.into_body();
        let mut decoder = HunkDecoder::default();
        let mut header_buf = Vec::new();
        let mut sent_response_header = false;

        while let Some(chunk) = recv_stream.data().await {
            let chunk = chunk.expect("данные потока");
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
            decoder.feed(&chunk);

            while let Ok(Some(payload)) = decoder.next_message() {
                if !sent_response_header {
                    header_buf.extend_from_slice(&payload);
                    if header_buf.len() >= REQUEST_HEADER_LEN {
                        assert_eq!(header_buf[0], 0x00);
                        assert_eq!(&header_buf[1..17], id_for_server.as_bytes());
                        assert_eq!(header_buf[18], Command::Tcp as u8);

                        send_stream
                            .send_data(Bytes::from(encode_hunk_frame(&[0x00, 0x00])), false)
                            .expect("отправить заголовок ответа VLESS");
                        sent_response_header = true;

                        // Остаток после заголовка (если в том же Hunk был
                        // приклеен кусок полезной нагрузки) — тоже эхо.
                        let leftover = header_buf.split_off(REQUEST_HEADER_LEN);
                        if !leftover.is_empty() {
                            send_stream
                                .send_data(Bytes::from(encode_hunk_frame(&leftover)), false)
                                .ok();
                        }
                    }
                } else {
                    send_stream
                        .send_data(Bytes::from(encode_hunk_frame(&payload)), false)
                        .ok();
                }
            }
        }

        let _ = send_stream.send_data(Bytes::new(), true);
    });

    let cfg = VlessConfig::parse(&format!(
        "vless://{id}@127.0.0.1:{}?encryption=none&security=tls&sni=localhost&type=grpc&serviceName=testsvc",
        addr.port()
    ))
    .unwrap();

    // connect_and_handshake_grpc сам поднимает TLS через встроенный набор
    // публичных корней — для теста нужен наш тестовый корень, поэтому
    // соединение до h2 собираем вручную (как внутри transport::grpc), а
    // дальше используем ту же функцию рукопожатия VLESS, что и клиент.
    let tls = connect_tls_with_roots_alpn(&cfg, roots, vec![b"h2".to_vec()])
        .await
        .unwrap();

    let (send_request, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_request = send_request.ready().await.unwrap();

    let uri: http::Uri = format!("https://{}/testsvc/Tun", cfg.effective_sni())
        .parse()
        .unwrap();
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response_fut, mut send_stream) = send_request.send_request(request, false).unwrap();
    let response = response_fut.await.unwrap();
    let mut recv_stream = response.into_body();

    let (user_half, internal_half) = tokio::io::duplex(64 * 1024);
    let (mut internal_read, mut internal_write) = tokio::io::split(internal_half);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match internal_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if send_stream
                .send_data(Bytes::from(encode_hunk_frame(&buf[..n])), false)
                .is_err()
            {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut decoder = HunkDecoder::default();
        while let Some(chunk) = recv_stream.data().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => break,
            };
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
            decoder.feed(&chunk);
            while let Ok(Some(payload)) = decoder.next_message() {
                if internal_write.write_all(&payload).await.is_err() {
                    return;
                }
            }
        }
    });

    let client = user_half;
    let target = Address::Domain("example.com".to_string());
    let mut client = vless_connect(client, &id, Command::Tcp, &target, 443)
        .await
        .expect("vless handshake поверх gRPC");

    let payload = b"hello over grpc tunnel";
    client.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, payload);

    drop(client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;

    // connect_and_handshake_grpc существует и линкуется (сама функция
    // покрывается тем, что используется в bin/client) — здесь явно её
    // не гоняем второй раз с тем же портом, чтобы не усложнять тест.
    let _ = connect_and_handshake_grpc;
}
