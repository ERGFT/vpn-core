//! Что делать, если вместо REALITY-сервера ответил настоящий сайт.
//!
//! Так бывает, когда цензор перенаправляет подозрительное соединение на
//! сам сайт-приманку (или сервер настроен с чужим ключом): сертификат
//! настоящий, проверку REALITY он не проходит. Браузер в такой ситуации
//! спокойно открыл бы страницу, а клиент, оборвавший рукопожатие сразу
//! после сертификата, выдаёт себя. Xray-core (`reality.go`, `UClient`)
//! поэтому доводит рукопожатие до конца и ходит по сайту как браузер,
//! после чего возвращает ошибку. Здесь то же в упрощённом виде: один
//! запрос главной страницы с заголовками Chrome («переход по адресу»),
//! ответ дочитывается и соединение закрывается.
//!
//! Ни UUID, ни заголовок VLESS по такому соединению не отправляются:
//! поток сюда передаётся целиком и наружу не возвращается.

use std::time::Duration;

use bytes::Bytes;
use http::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::fingerprint::Browser;
use crate::transport::browser_headers::{headers as browser_headers, Variant};
use crate::transport::tcp_tls::TlsBoxedStream;

/// Сколько тела ответа дочитать, прежде чем закрыть.
const MAX_BODY: usize = 1024 * 1024;
/// Сколько всего тратить на «визит».
const VISIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Запустить «визит» в фоне и сразу вернуться.
pub fn visit_in_background(tls: TlsBoxedStream, host: String, browser: Browser) {
    tokio::spawn(async move {
        let _ = tokio::time::timeout(VISIT_TIMEOUT, visit(tls, &host, browser)).await;
        tracing::debug!("REALITY: браузерный визит на настоящий сайт завершён");
    });
}

async fn visit(tls: TlsBoxedStream, host: &str, browser: Browser) {
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    if h2 {
        let _ = visit_h2(tls, host, browser).await;
    } else {
        let _ = visit_h1(tls, host, browser).await;
    }
}

async fn visit_h2(tls: TlsBoxedStream, host: &str, browser: Browser) -> Result<(), h2::Error> {
    let mut b = h2::client::Builder::new();
    b.header_table_size(65536)
        .enable_push(false)
        .initial_window_size(6 * 1024 * 1024)
        .initial_connection_window_size(15 * 1024 * 1024)
        .max_header_list_size(262144);
    let (send, conn) = b.handshake::<_, Bytes>(tls).await?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut send = send.ready().await?;
    let mut req = Request::builder().uri(format!("https://{host}/"));
    for (k, v) in browser_headers(browser, Variant::Nav) {
        req = req.header(k, v);
    }
    let Ok(req) = req.body(()) else {
        driver.abort();
        return Ok(());
    };
    let (resp, _) = send.send_request(req, true)?;
    let mut body = resp.await?.into_body();
    let mut got = 0usize;
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        got += chunk.len();
        let _ = body.flow_control().release_capacity(chunk.len());
        if got >= MAX_BODY {
            break;
        }
    }
    drop(body);
    drop(send);
    driver.abort();
    Ok(())
}

async fn visit_h1(mut tls: TlsBoxedStream, host: &str, browser: Browser) -> std::io::Result<()> {
    let mut headers = browser_headers(browser, Variant::Nav);
    let ua = headers.remove(0);
    let mut req = format!("GET / HTTP/1.1\r\nHost: {host}\r\n{}: {}\r\n", ua.0, ua.1);
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Accept-Encoding: gzip, deflate, br, zstd\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await?;
    tls.flush().await?;
    let mut buf = vec![0u8; 16 * 1024];
    let mut got = 0usize;
    while got < MAX_BODY {
        let n = tls.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        got += n;
    }
    Ok(())
}
