# Карта репозитория

**Русский** | [English](REPOSITORY.en.md)

Где что лежит в репозитории. Как устроено ядро изнутри — [ARCHITECTURE.md](ARCHITECTURE.md).

```
bin/client/            reality-client: CLI (ключи или --config), sysproxy.rs,
                       winservice.rs (служба и автозапуск Windows)
core/src/
  app/                 приложение: входы -> маршрутизатор -> выходы;
                       config/ (sing-box, Xray → одна модель), proxy_in.rs + http_in.rs (входы
                       socks/http/mixed), sniff.rs + sniff_quic.rs, router.rs + rules.rs +
                       geo.rs (правила, geosite/geoip), ruleset.rs
                       (наборы sing-box .srs/.json), outbound.rs
                       (direct, block, dns), vless_out.rs, access.rs,
                       dns/ (upstream.rs: UDP/TCP/DoT/DoH/DoQ, cache.rs,
                       fakeip.rs), dns_in.rs (вход DNS), tun/ (вход TUN
                       на smoltcp + tun-rs, udp.rs: потоки UDP,
                       route.rs: auto_route)
  net_protect.rs       метка исходящих сокетов (мимо TUN)
  vless/               разбор vless:// (uri.rs), протокол VLESS (protocol.rs),
                       XTLS Vision (vision.rs), UDP-пакеты (udp.rs), XUDP (xudp.rs)
  transport/           tcp_tls.rs (TCP, TLS, REALITY), raw.rs (сокет с выдачей
                       по одному TLS-рекорду для Vision), ws.rs, grpc.rs,
                       httpupgrade.rs, xhttp.rs, quic.rs (quinn: DoQ, HTTP/3),
                       browser_headers.rs (заголовки Chrome)
  reality/             REALITY: ключи и SessionId (auth.rs), хук в ClientHello
                       (hook.rs), проверка сертификата: HMAC и ML-DSA-65 (verifier.rs)
  fingerprint/         ClientHello как у Chrome (chrome_profile.rs), разбор, JA3/JA4
  socks5/              протокол SOCKS5: приветствие, логин/пароль, UDP-заголовки
  relay.rs             двусторонний релей, один буфер на направление
core/tests/            интеграционные тесты (loopback) + interop_xray.rs, interop_go_reality.rs
vendor/rustls-reality-patch/
                       rustls 0.23.45 с патчем: REALITY, GREASE, профиль ClientHello
                       Chrome (подключён через [patch.crates-io])
interop/go-reality-server/
                       тестовый REALITY-сервер на библиотеке XTLS/REALITY
bin/fpcheck/           снятие JA3/JA4
ffi/                   ядро как библиотека: C ABI (reality.h), пример на C
bench/                 бенчмарки (criterion) и замер памяти (memwatch, Linux)
scripts/               ci, интероп, smoke, сборка Xray, сверка отпечатка,
                       сборка под Windows, инструкции для Этапов 2 и 8
docs/                  ARCHITECTURE.md (как устроено ядро), LIBRARY.md
                       (ядро в приложении), WINDOWS.md,
                       чек-лист крипто-ревью (Этап 5)
examples/              примеры настроек: sing-box.json, xray.json, systemd
PLAN.md                план по этапам, история решений, открытые риски
```
