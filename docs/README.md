# Документация

**Русский** | [English](README.en.md)

С чего начать — [README](../README.md): что это за проект, сборка и первый
запуск. Здесь — подробности.

## Пользоваться

| Страница | О чём |
|---|---|
| [FEATURES.md](FEATURES.md) | все возможности, их статус и как каждая проверена; известные ограничения |
| [CLI.md](CLI.md) | ключи командной строки, автозапуск (служба Windows, systemd) |
| [CONFIG.md](CONFIG.md) | файл настроек sing-box/Xray: входы, выходы, правила, наборы правил, группы серверов, подписки, `fragment` и `noises` |
| [DNS.md](DNS.md) | свой DNS: серверы DoH/DoT/DoQ, правила, кеш, fake-IP |
| [TUN.md](TUN.md) | весь трафик компьютера через клиент (как VPN), kill switch |
| [API.md](API.md) | локальное API (Clash API), веб-панели, перечитывание настроек |
| [LINK.md](LINK.md) | параметры ссылки `vless://` |
| [WINDOWS.md](WINDOWS.md) | сборка и запуск на Windows |
| [SECURITY-MODEL.md](SECURITY-MODEL.md) | что клиент гарантирует, угрозы в общей Wi-Fi сети |

## Встраивать и разрабатывать

| Страница | О чём |
|---|---|
| [LIBRARY.md](LIBRARY.md) | ядро как библиотека (C ABI): Android, iOS, десктоп |
| [ARCHITECTURE.md](ARCHITECTURE.md) | как устроено ядро изнутри |
| [REPOSITORY.md](REPOSITORY.md) | где что лежит в репозитории |
| [TESTING.md](TESTING.md) | как проверяется проект, сравнение с Xray-core, производительность |
| [RUSTLS_PATCH.md](RUSTLS_PATCH.md) | что изменено в rustls и почему |
| [stage5-crypto-review-and-interop.md](stage5-crypto-review-and-interop.md) | чек-лист для стороннего крипто-ревью REALITY |

История решений по этапам — [PLAN.md](../PLAN.md), что изменилось —
[CHANGELOG.md](../CHANGELOG.md).
