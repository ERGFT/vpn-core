# reality-client на Windows

Клиент и библиотека не используют ничего Unix-специфичного (проверено по
коду: без `std::os::unix`, `libc`, `/proc`). Единственная часть проекта,
которая работает только на Linux, — вспомогательный замерщик памяти
`bench/src/bin/memwatch.rs` (читает `/proc`); на сборку клиента это не
влияет.

> Честно: собрать и запустить под Windows из песочницы, где писался
> проект, не удалось — стандартная библиотека Rust для Windows-цели
> скачивается с `static.rust-lang.org`, а туда доступа не было. Всё ниже
> составлено по документации и исходникам `aws-lc-sys` 0.45 (сборочного
> скрипта криптобиблиотеки), но на реальной Windows не прогонялось.

## 1. Что поставить

1. **Rust** — <https://rustup.rs>. При установке выбрать toolchain
   `stable-x86_64-pc-windows-msvc` (по умолчанию так и есть). Проверка:
   `rustup show active-toolchain` → должно содержать `msvc`.
2. **Visual Studio Build Tools** — <https://visualstudio.microsoft.com/visual-cpp-build-tools/>,
   компонент **«Desktop development with C++»**. Он нужен, потому что
   криптография TLS (`aws-lc-rs` → `aws-lc-sys`) собирается из C-кода.
3. **NASM — не обязательно.** Если его нет, `aws-lc-sys` может взять
   готовые объектные файлы ассемблера, но только если это явно разрешено
   переменной `AWS_LC_SYS_PREBUILT_NASM=1` (скрипт ниже ставит её сам).
   CMake по умолчанию не нужен.

## 2. Сборка

Из корня репозитория, в PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
```

Или вручную:

```powershell
$env:AWS_LC_SYS_PREBUILT_NASM = "1"   # если NASM не установлен
cargo build --release -p reality-client
```

Результат: `target\release\reality-client.exe`.

## 3. Запуск

```powershell
.\target\release\reality-client.exe --server "vless://UUID@host:443?encryption=none&security=reality&sni=site&pbk=KEY&sid=ID&type=tcp" --listen 127.0.0.1:1080
```

Ссылку лучше брать в двойные кавычки: в ней есть `&`, который иначе
обработает оболочка. В консоли появятся строки
`конфигурация сервера загружена ...` и `SOCKS5 слушает addr=127.0.0.1:1080`.
Подробнее журнал: `$env:RUST_LOG = "debug"` перед запуском.

Остановить — `Ctrl+C`.

## 4. Как пользоваться

Клиент поднимает **SOCKS5-прокси** на `127.0.0.1:1080` (или адресе из
`--listen`). Системным VPN он не является: трафик идёт через него только
у программ, которым указан этот прокси.

- **Firefox:** Настройки → Сеть → Параметры соединения → Ручная
  настройка → SOCKS-хост `127.0.0.1`, порт `1080`, SOCKS v5, и галочка
  «Отправлять DNS-запросы через прокси при использовании SOCKS v5».
- **curl** (есть в Windows 10+):
  `curl --socks5-hostname 127.0.0.1:1080 https://example.com`
- **Chrome/Edge** — через параметр запуска:
  `--proxy-server="socks5://127.0.0.1:1080"`.

## 5. Дополнительные ключи

- `--auth логин:пароль` — требовать логин и пароль на SOCKS5. Без него
  клиент согласен слушать только на `127.0.0.1`; чтобы открыть прокси для
  других устройств в сети (`--listen 0.0.0.0:1080`), пароль обязателен.
- `--ca файл.pem` — свои корневые сертификаты для `security=tls` (сервер с
  самоподписанным сертификатом).

UDP (DNS, QUIC, игры) работает через SOCKS5 UDP ASSOCIATE — если
программа умеет UDP через SOCKS5. В Windows может понадобиться разрешить
клиенту входящие UDP-пакеты от localhost в брандмауэре (он спросит при
первом UDP-запросе).

## 6. Ограничения (те же, что и на Linux)

- XTLS Vision работает только с `type=tcp` и `security=tls`/`reality` —
  как и в самом Xray-core; для ws/grpc клиент сразу скажет, что так нельзя.
- Нет Mux и транспортов `xhttp`/`httpupgrade`/`kcp`/`quic`.

Полный список — в `README.md`, раздел «Что умеет и чего нет».
