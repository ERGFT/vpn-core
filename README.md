# vpn-core

**Компактное VLESS-ядро на Rust** для локального прокси, TUN-клиента и встраивания в приложения через C ABI.

Поддерживает **REALITY** и **XTLS Vision**, работает с совместимыми серверами Xray-core. Проект экспериментальный: мобильную интеграцию и отдельные функции нужно оценивать по таблице ниже и подробной [матрице возможностей](docs/FEATURES.md).

**Русский** | [English](README.en.md)

[![CI](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml/badge.svg)](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.89+](https://img.shields.io/badge/rust-1.89%2B-orange.svg?logo=rust)](https://www.rust-lang.org/)

## С чего начать

| Ваша задача | Куда перейти |
|---|---|
| Запустить клиент на своём компьютере | [Быстрый старт](#быстрый-старт) |
| Встроить ядро в своё приложение | [SDK и C ABI](#для-разработчиков) · [руководство по библиотеке](docs/LIBRARY.md) |
| Проверить поддержку протоколов и ограничения | [Возможности и статус](#возможности-и-статус) · [полная матрица](docs/FEATURES.md) |
| Разобраться в устройстве и тестировании | [Документация](#документация) |

## Проект в двух словах

| Компонент | Назначение |
|---|---|
| `reality-core` (`core/`) | Библиотека: протоколы, маршрутизация, DNS и TUN |
| `reality-client` (`bin/client/`) | CLI-клиент с SOCKS5/HTTP-прокси и TUN |
| `reality-ffi` (`ffi/`, `libreality`) | C ABI для встраивания ядра в приложения на других языках |

### Платформы и готовность

| Платформа | CLI-клиент | SDK для интеграции | Статус |
|---|---:|---:|---|
| Linux x86_64 | Да | Да | Клиент и библиотека проверяются CI |
| Windows x86_64 | Да | Да | Клиент и библиотека проверяются CI; часть системных функций имеет отдельные ограничения |
| macOS arm64 | Нет | Да | SDK собирается для релизного пакета; работа приложения на устройстве отдельно не подтверждена |
| Android arm64-v8a | Нет | Да | Экспериментальная интеграция; приложению нужно самостоятельно подключить TUN |
| iOS arm64 | Нет | Да | Экспериментальная интеграция; готового клиентского приложения нет |

Release workflow собирает SDK-архивы для перечисленных ABI после versioned tag. В архив входят библиотека, `reality.h`, минимальный пример на C и документация API. [Откройте Releases](https://github.com/ERGFT/vpn-core/releases), чтобы проверить доступность опубликованных пакетов; если нужного SDK там нет, используйте сборку из исходников по [руководству](docs/LIBRARY.md).

## Быстрый старт

Требуется Rust **1.89 или новее**. На Windows также нужны [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) с компонентом *Desktop development with C++* и [Git](https://git-scm.com/download/win). Инструкции для [Windows](docs/WINDOWS.md).

**Linux**

```sh
sudo apt install build-essential git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/ERGFT/vpn-core.git
cd vpn-core
cargo build --release -p reality-client
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/ERGFT/vpn-core.git
cd vpn-core
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
```

Сохраните выданную сервером ссылку `vless://…` в `server.txt`. Она содержит UUID: ограничьте доступ к файлу и не публикуйте его.

```sh
./target/release/reality-client --server-file server.txt
```

На Windows запустите `.\target\release\reality-client.exe --server-file server.txt --system-proxy`. Прокси слушает `127.0.0.1:1080` (SOCKS5 и HTTP на одном порту). Проверка:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

На Linux исполняемый файл находится в `target/release/`, на Windows — в `target\release\`. Подробности и остальные параметры — в [CLI](docs/CLI.md), [конфигурации](docs/CONFIG.md) и [руководстве Windows](docs/WINDOWS.md).

## Для разработчиков

SDK предназначен для приложений, которым нужно встроить VLESS-клиент. Основной внешний интерфейс — C ABI; подробности по владению памятью, потокам, callback-ам и платформенным интеграциям находятся в [руководстве библиотеки](docs/LIBRARY.md) и заголовке [`reality.h`](ffi/include/reality.h).

| API | Для чего нужен |
|---|---|
| `rc_validate` | Проверить конфигурацию до запуска; вернуть успех или ошибку без раскрытия её значений |
| `rc_start` / `rc_stop` | Создать экземпляр ядра, запустить его и корректно остановить |
| `rc_request` | Вызывать API ядра напрямую, без сетевого HTTP-сервера и токена |
| `rc_reload` | Применить новую конфигурацию без пересоздания всего приложения |
| `rc_is_alive` | Проверить состояние и получить информацию о завершении с ошибкой |
| Callbacks | Получать события/журнал и предоставлять платформенные функции: защиту сокетов или определение UID приложения |

Минимальный пример и перечень файлов каждого SDK-архива описаны в [LIBRARY.md](docs/LIBRARY.md). Публичный заголовок и примеры — [каталог `ffi/`](ffi/).

## Возможности и статус

| Область | Поддержка |
|---|---|
| Протокол | VLESS, REALITY, TLS, XTLS Vision; TCP, WebSocket, gRPC, HTTPUpgrade и XHTTP |
| Сетевые функции | Входы SOCKS5/HTTP/mixed; SOCKS5 и HTTP CONNECT TCP-выходы и цепочки `detour`; быстрый выбор IPv4/IPv6 (Happy Eyeballs); UDP/XUDP, DNS (DoH/DoT/DoQ), TUN, kill switch |
| Конфигурация | Форматы Xray-core и часть формата sing-box; правила, группы серверов, подписки |
| Управление | Локальный Clash API, панели metacubexd и yacd, systemd и служба Windows |
| Экспериментально | Android/iOS через C ABI; `fragment` и `noises`; интеграция с правилами приложений |
| Не поддерживается | Транспорт KCP; ICMP/ping через TUN |

Импорт конфигурации sing-box **не означает полной совместимости** со всеми его опциями. Статус каждой функции и способ её проверки — в [полной матрице](docs/FEATURES.md).

## Как выбрать ядро

Проекты решают задачи разного масштаба; таблица сравнивает их назначение, а не качество или скорость.

| Проект | Сильная сторона | Когда рассмотреть |
|---|---|---|
| **vpn-core** | Узкое Rust-ядро для VLESS-клиента; CLI и C ABI для встраивания | Когда нужны VLESS/REALITY и собственная интеграция в приложение |
| [Xray-core](https://github.com/XTLS/Xray-core) | Широкая платформа для прокси-протоколов и сетевых сценариев | Когда важна широкая экосистема Xray или требуется больше протоколов |
| [sing-box](https://github.com/SagerNet/sing-box) | Многопротокольный прокси с большим набором входов, выходов и сетевых функций | Когда нужна универсальная прокси-платформа или готовая интеграция sing-box |

В [результатах тестирования](docs/TESTING.md) описаны локальное сравнение с Xray-core и отдельная воспроизводимая методика для `xray-rust`, включая измерение восстановления после остановки тестового сервера. Результаты двух сравнений относятся только к своим конфигурациям и не доказывают общего превосходства.

## Документация

| Тема | Документы |
|---|---|
| Запуск и настройка | [CLI](docs/CLI.md) · [конфигурация](docs/CONFIG.md) · [параметры `vless://`](docs/LINK.md) |
| Сеть | [DNS](docs/DNS.md) · [TUN](docs/TUN.md) · [маршрутизация приложений](docs/APPLICATION_ROUTING.md) |
| Разработка | [ядро как библиотека](docs/LIBRARY.md) · [API](docs/API.md) · [внутреннее устройство](docs/README.md) |
| Надёжность и безопасность | [возможности и тесты](docs/FEATURES.md) · [сравнение и методика](docs/TESTING.md) · [модель безопасности](docs/SECURITY-MODEL.md) |

## Безопасность и ограничения

Это учебно-исследовательский проект без стороннего аудита безопасности и криптографического ревью REALITY. Не считайте наличие функции гарантией безопасности для любой конфигурации.

- При `security=none` данные не защищены шифрованием; такой режим требует явного `--allow-insecure`.
- При REALITY UUID передаётся только после проверки REALITY; при TLS сервер должен предъявить действительный сертификат.
- По умолчанию локальный прокси слушает только `127.0.0.1`. DNS-поведение зависит от типа трафика и конфигурации; подробности — в [модели безопасности](docs/SECURITY-MODEL.md).
- Проект лицензирован по [GPL-3.0-or-later](LICENSE). Перед встраиванием проверьте, как лицензия применяется к вашему приложению и распространению.

Нашли уязвимость — сообщите приватно по инструкции в [SECURITY.md](SECURITY.md), а не в публичном issue.

## Участие и лицензия

Исправления и обсуждения: [CONTRIBUTING.md](CONTRIBUTING.md) · [SUPPORT.md](SUPPORT.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [CHANGELOG.md](CHANGELOG.md).

Copyright (C) 2026 ERGFT. Основной код распространяется по GNU GPL v3 или более поздней версии. Патч в `vendor/rustls-reality-patch` сохраняет лицензии rustls; перечень лицензий зависимостей формируется скриптом [`scripts/third_party_licenses.sh`](scripts/third_party_licenses.sh).
