# Документация

**Русский** | [English](README.en.md)

С чего начать — [README](../README.md): что это за проект, сборка и первый
запуск. Здесь — подробности.

## Пользоваться

| Страница | О чём |
|---|---|
| [FEATURES.md](FEATURES.md) | все возможности, их статус и как каждая проверена; известные ограничения |
| [SHADOWSOCKS_IMPLEMENTATION_PLAN.md](SHADOWSOCKS_IMPLEMENTATION_PLAN.md) | статус и границы реализации классического Shadowsocks AEAD и отдельного этапа Shadowsocks 2022 |
| [CLI.md](CLI.md) | ключи командной строки, автозапуск (служба Windows, systemd) |
| [CONFIG.md](CONFIG.md) | поддерживаемые подмножества форматов sing-box/Xray: входы, выходы, правила, наборы правил, группы серверов, подписки, `fragment` и `noises` |
| [DNS.md](DNS.md) | свой DNS: серверы DoH/DoT/DoQ, правила, кеш, fake-IP |
| [TUN.md](TUN.md) | системная маршрутизация TCP/UDP через виртуальный интерфейс, kill switch и ограничения протоколов |
| [API.md](API.md) | локальное API (Clash API), веб-панели, перечитывание настроек |
| [LINK.md](LINK.md) | параметры ссылки `vless://` |
| [WINDOWS.md](WINDOWS.md) | сборка и запуск на Windows |
| [SECURITY-MODEL.md](SECURITY-MODEL.md) | предпосылки, границы защиты и угрозы в общей Wi-Fi сети |
| [Внутреннее ревью REALITY](reviews/2026-11-04-reality-internal-review.md) | объём и результаты внутренней проверки; это не независимый внешний аудит |

## Встраивать и разрабатывать

| Страница | О чём |
|---|---|
| [LIBRARY.md](LIBRARY.md) | ядро как библиотека (C ABI): Android, iOS, десктоп |
| [APPLICATION_ROUTING.md](APPLICATION_ROUTING.md) | привязка соединений к приложениям и сайтам, ограничения платформ |
| [ARCHITECTURE.md](ARCHITECTURE.md) | как устроено ядро изнутри |
| [REPOSITORY.md](REPOSITORY.md) | где что лежит в репозитории |
| [TESTING.md](TESTING.md) | как проверяется проект, сравнение с Xray-core, производительность |
| [PROTOCOL_ARCHITECTURE_AUDIT.md](PROTOCOL_ARCHITECTURE_AUDIT.md) | исходное состояние архитектуры и план подготовки новых протоколов |
| [RUSTLS_PATCH.md](RUSTLS_PATCH.md) | что изменено в rustls и почему |
| [stage5-crypto-review-and-interop.md](stage5-crypto-review-and-interop.md) | чек-лист для будущего независимого крипто-ревью REALITY |
| [RELEASING.md](RELEASING.md) | предварительная сборка, проверка артефактов и публикация тега |

## Правила документации

| Страница | О чём |
|---|---|
| [STYLE_GUIDE.md](STYLE_GUIDE.md) | редакционные правила VCTWS 1.0 для технической документации |
| [GLOSSARY.md](GLOSSARY.md) | согласованные русские и английские технические термины |

История решений по этапам — [PLAN.md](../PLAN.md), что изменилось —
[CHANGELOG.md](../CHANGELOG.md).
