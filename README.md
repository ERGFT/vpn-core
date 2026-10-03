# vpn-core

**Русский** | [English](README.en.md)

[![CI](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml/badge.svg)](https://github.com/ERGFT/vpn-core/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
![Rust 1.89+](https://img.shields.io/badge/rust-1.89%2B-orange.svg?logo=rust)
![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)

Клиент **VLESS** (с **REALITY** и **XTLS Vision**) на Rust, написанный с
нуля. Он поднимает на вашем компьютере локальный прокси (SOCKS5 и HTTP) или
перехватывает весь трафик (TUN, как VPN) и отправляет его на сервер
Xray-core или совместимый.

## Что как называется

| Название | Что это |
|---|---|
| **vpn-core** | этот репозиторий |
| **reality-client** | программа, которую вы запускаете (`bin/client/`) |
| **reality-core** | библиотека с самим ядром: протоколы, маршрутизация, DNS, TUN (`core/`); на ней построена `reality-client` |
| **reality-ffi** (`libreality`) | то же ядро для встраивания в приложения на других языках через C ABI (`ffi/`) |

## Платформы и статус

- **Linux, Windows** — программа `reality-client`: готово.
- **macOS** — не проверено на этой платформе.
- **Android, iOS** — только как библиотека для своего приложения:
  экспериментально ([LIBRARY.md](docs/LIBRARY.md)).

Это учебно-исследовательский проект. Всё, что перечислено как «готово»,
проверено тестами, в том числе против настоящего Xray-core, но стороннего
аудита безопасности и крипто-ревью REALITY не было. Это не замена зрелым
клиентам (v2rayN, sing-box, Xray).

> [!WARNING]
> **Готовых сборок пока нет.** В [Releases](https://github.com/ERGFT/vpn-core/releases)
> пусто: программу нужно собрать самому, это 5–10 минут (ниже). Когда
> появятся готовые файлы, здесь будут инструкции по установке, обновлению и
> удалению.

## Быстрый старт

### 1. Установить Rust

Нужен Rust 1.89 или новее.

**Linux** (Debian, Ubuntu; в других дистрибутивах — свой пакетный
менеджер):

```sh
sudo apt install build-essential git       # компилятор C и git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Windows:**

1. Rust — установщик с [rustup.rs](https://rustup.rs) (вариант по
   умолчанию, `x86_64-pc-windows-msvc`).
2. [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/),
   компонент «Desktop development with C++».
3. [Git](https://git-scm.com/download/win).

Подробнее — [docs/WINDOWS.md](docs/WINDOWS.md).

### 2. Собрать

**Linux:**

```sh
git clone https://github.com/ERGFT/vpn-core.git
cd vpn-core
cargo build --release -p reality-client
# готово: target/release/reality-client
```

**Windows** (PowerShell):

```powershell
git clone https://github.com/ERGFT/vpn-core.git
cd vpn-core
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
# готово: target\release\reality-client.exe
```

### 3. Подготовить настройки

Нужна ссылка `vless://…` — её выдаёт панель вашего сервера (3x-ui, Marzban,
Remnawave) или администратор. Сохраните её в файл: в ссылке ваш UUID, а
аргументы командной строки видны другим программам.

**Linux:**

```sh
printf '%s\n' 'vless://…ваша ссылка…' > server.txt
chmod 600 server.txt
```

**Windows:** создайте в Блокноте файл `server.txt` со ссылкой в первой
строке.

Несколько серверов, правила «это — напрямую, это — через сервер», подписки —
в [файле настроек](docs/CONFIG.md).

### 4. Запустить

**Linux:**

```sh
./target/release/reality-client --server-file server.txt
```

**Windows:**

```powershell
.\target\release\reality-client.exe --server-file server.txt --system-proxy
```

В журнале появятся строки `сервер загружен …` и
`прокси слушает … addr=127.0.0.1:1080`. Прокси — на `127.0.0.1:1080`, на
одном порту SOCKS5 и HTTP. С `--system-proxy` (только Windows) браузеры и
большинство программ пойдут через клиент без настройки. Остановить —
`Ctrl+C`. Все ключи — [docs/CLI.md](docs/CLI.md).

### 5. Проверить соединение

В другом окне терминала (на Windows 10 и новее `curl` уже есть):

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

Пришла HTML-страница — соединение через сервер работает. В браузере
укажите SOCKS5-прокси `127.0.0.1:1080`; в Firefox — ещё «DNS через SOCKS
v5», иначе имена сайтов уходят в обычный DNS.

### Обновление и удаление

- **Обновить:** в папке `vpn-core` — `git pull`, потом снова шаг 2.
- **Удалить:** если ставили автозапуск — сначала снять его: на Windows
  `reality-client --service-uninstall` или `--autostart-uninstall`; на
  Linux `sudo systemctl disable --now reality-client` и удалить то, что
  копировали по [`examples/reality-client.service`](examples/reality-client.service)
  (`/etc/systemd/system/reality-client.service`,
  `/usr/local/bin/reality-client`, `/etc/reality-client`). Затем удалить
  папку `vpn-core`. Если клиент был закрыт аварийно с
  `--system-proxy` и пропал интернет — `reality-client --system-proxy-off`.

## Возможности

Коротко; полный список, как проверена каждая возможность, и ограничения —
[docs/FEATURES.md](docs/FEATURES.md).

| Возможность | Статус |
|---|---|
| VLESS с `security=none`, `tls`, `reality`; XTLS Vision | готово |
| Транспорты `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp` (HTTP/1.1, HTTP/2, HTTP/3) | готово |
| UDP через XUDP; Mux.Cool; выход `trojan` | готово |
| TLS-отпечатки браузеров (`fp=chrome`, `firefox`, `safari` и др.) | готово |
| Входы SOCKS5, HTTP, `mixed`; файл настроек в формате sing-box или Xray-core | готово |
| Маршрутизация: домены, IP, geosite/geoip, наборы правил sing-box; sniffing | готово |
| Группы серверов (`selector`, `urltest`, `fallback`), подписки | готово |
| Свой DNS: DoH, DoT, DoQ, кеш, fake-IP | готово |
| TUN — весь трафик компьютера, kill switch (Linux, Windows) | готово |
| Локальное API (Clash API), веб-панели metacubexd и yacd | готово |
| Служба Windows, systemd | готово |
| Системный прокси и автозапуск при входе на Windows | не проверено на этой платформе (только под Wine) |
| Против DPI: `fragment`, `noises` | экспериментально |
| Встраивание в Android и iOS (C ABI) | экспериментально |
| Транспорт `kcp`; ICMP (ping) через TUN | не поддерживается |

Статусы: **готово** — работает и проверено тестами; **экспериментально** —
работает, но проверено мало или результат зависит от сети; **не
поддерживается** — нет; **не проверено на этой платформе** — код есть, но
на этой ОС по-настоящему не проверялся.

## Документация

| | |
|---|---|
| [Командная строка и автозапуск](docs/CLI.md) | все ключи, служба Windows, systemd |
| [Файл настроек](docs/CONFIG.md) | форматы sing-box и Xray, правила, группы серверов, подписки, `fragment` |
| [DNS](docs/DNS.md) · [TUN](docs/TUN.md) · [API](docs/API.md) | свой DNS, весь трафик через клиент, управление и веб-панели |
| [Параметры ссылки](docs/LINK.md) | что понимается в `vless://…` |
| [Windows](docs/WINDOWS.md) | сборка и запуск на Windows |
| [Модель безопасности](docs/SECURITY-MODEL.md) | что гарантируется, угрозы в общей Wi-Fi сети |
| [Ядро как библиотека](docs/LIBRARY.md) | встраивание в приложения |
| [Все страницы](docs/README.md) | устройство ядра, проверка проекта, сравнение с Xray-core |

## Безопасность

- С `security=reality` UUID уходит только серверу, прошедшему проверку
  REALITY, без отката на обычную проверку сертификата. С `security=tls` —
  только тому, кто предъявил действительный сертификат для этого имени.
  С `security=none` его видят все на пути до сервера.
- Для проксируемого трафика, в котором приложение передаёт имя сайта
  (SOCKS5 с именем, HTTP-прокси, TUN с fake-IP), имя разрешает сервер, и
  локальный DNS его не видит. Исключения — приложение само разрешило имя,
  выход `direct`, DNS-серверы с `detour: direct` или `type: local`;
  подробнее — в модели безопасности.
- Ссылку с `security=none` (всё открытым текстом) клиент без
  `--allow-insecure` не запускает; прокси по умолчанию слушает только
  `127.0.0.1`.

Подробно — [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md). Нашли
уязвимость — [SECURITY.md](SECURITY.md), не в открытых issues.

## Участие

Как прислать исправление — [CONTRIBUTING.md](CONTRIBUTING.md); где искать
помощь — [SUPPORT.md](SUPPORT.md); правила общения —
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md); что изменилось и что
планируется — [CHANGELOG.md](CHANGELOG.md); история решений по этапам —
[PLAN.md](PLAN.md).

## Лицензия

Copyright (C) 2026 ERGFT.

GNU General Public License v3.0 или более поздняя версия
(`GPL-3.0-or-later`) — полный текст в [`LICENSE`](LICENSE); у каждого
исходника — метка `SPDX-License-Identifier`.
Исходники в `vendor/rustls-reality-patch` — патч rustls, остаются под
его лицензиями (Apache-2.0 / ISC / MIT, файлы `LICENSE-*` там же).
Лицензии всех зависимостей, вошедших в бинарник, —
`scripts/third_party_licenses.sh` (будут прикладываться к каждому релизу).
