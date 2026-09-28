[Русский](LIBRARY.md) | [English](LIBRARY.en.md)

# Ядро как библиотека

Ядро можно встроить прямо в приложение — Android (`VpnService`), iOS
(Network Extension), десктопный клиент — вместо того чтобы запускать
`reality-client` отдельным процессом. Интерфейс — C ABI: подходит для
Kotlin/Java (JNI), Swift, C/C++, Go (cgo), C# (P/Invoke), Python (ctypes) и
всего, что умеет вызывать функции C.

- Заголовок: [`ffi/include/reality.h`](../ffi/include/reality.h).
- Код: [`ffi/src/lib.rs`](../ffi/src/lib.rs), пример на C —
  [`ffi/examples/smoke.c`](../ffi/examples/smoke.c) (его собирает и
  запускает `scripts/ffi_smoke.sh`).
- Лицензия — та же GPL-3.0-or-later: приложение со встроенным ядром
  распространяется на условиях GPL (исходники приложения — тоже).

## Сборка

```sh
cargo build --release -p reality-ffi
# target/release/libreality.so (Linux, Android), libreality.dylib (macOS, iOS),
# reality.dll (Windows) и статическая libreality.a / reality.lib
```

Под Android — через [cargo-ndk](https://github.com/bbqsrc/cargo-ndk):

```sh
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o app/src/main/jniLibs \
    build --release -p reality-ffi
```

Под iOS — `cargo build --release -p reality-ffi --target aarch64-apple-ios`
(статическая `libreality.a` в XCFramework).

## Жизненный цикл

```c
#include "reality.h"

char *err = NULL;
RcCore *core = rc_start(config_json, base_dir, /*tun_fd*/ -1, &err);
if (!core) { printf("ошибка: %s\n", err); rc_free_string(err); return; }

int status;
char *proxies = rc_request(core, "GET", "/proxies", NULL, &status);
/* … */
rc_free_string(proxies);

rc_stop(core);
```

- **`rc_start(config, base_dir, tun_fd, &err)`** — настройки текстом (JSON
  sing-box или Xray-core, как для `reality-client --config`), папка для
  относительных путей в них (базы geosite/geoip, наборы правил, кеши
  подписок), дескриптор TUN или -1. Ошибка настроек — NULL и текст в
  `err`.
- **`rc_request(core, method, path, body, &status)`** — всё, что умеет
  HTTP API ([README](../README.md), раздел «API»), тем же путём и с тем же
  ответом, без сети и токена: группы и выбор сервера (`/proxies`), режим
  (`PATCH /configs`), соединения (`/connections`), проверка задержки,
  подписки (`/providers/proxies`), DNS-запрос, статистика (`/stats`).
  Ответ — JSON (пустая строка у 204), код — в `status`.
- **`rc_reload(core, config, &err)`** — новые настройки без разрыва
  соединений; ошибка — работают прежние. Ответ — `{"notes": […]}`: что
  вступит в силу только после перезапуска.
- **`rc_set_event_callback(core, cb, user)`** — события (как поток
  `GET /events`): открытие и закрытие соединений, переключение групп,
  обновление подписок, перечитывание, смена режима.
- **`rc_set_log_callback(core, level, cb, user)`** — журнал ядра.
- **`rc_stop(core)`** — остановить: входы закрываются, маршруты
  возвращаются.
- **`rc_free_string(s)`** — освободить строку, которую вернула библиотека.

Функции можно вызывать из любого потока. Обратные вызовы приходят из
фоновых потоков ядра: переложите данные в свой поток (UI) и верните
управление — ядро ждёт, пока обратный вызов не вернётся.

## Android

1. `VpnService.Builder` — адреса, маршруты (`addRoute("0.0.0.0", 0)`),
   DNS, `establish()` → `ParcelFileDescriptor`.
2. До `rc_start` — `rc_set_protect`: обратный вызов, который вызывает
   `VpnService.protect(fd)` для каждого сокета ядра (соединения к
   серверу, `direct`, DNS) — иначе они ушли бы в свой же VPN.
3. `rc_start(config, filesDir, pfd.detachFd(), &err)` — владение
   дескриптором переходит ядру (он закроется в `rc_stop`). В настройках —
   вход `{"type": "tun", "tag": "tun"}`: адреса, маршруты и kill switch
   задаёт `VpnService`, поэтому `auto_route`/`strict_route` не
   применяются. Перехват DNS (`hijack-dns`), sniffing, fake-IP работают
   как обычно.

Набросок JNI-обёртки (Kotlin):

```kotlin
object Core {
    init { System.loadLibrary("reality") }       // libreality.so
    external fun start(config: String, dir: String, tunFd: Int): Long   // 0 — ошибка
    external fun request(core: Long, method: String, path: String, body: String?): String
    external fun stop(core: Long)
}
```

C-часть обёртки (`jni.c`) вызывает `rc_start`/`rc_request`/`rc_stop`, а
`rc_set_protect` — с обратным вызовом, который через `JNIEnv` (поток —
`AttachCurrentThread`) вызывает `VpnService.protect(int)`.

## iOS, macOS

В `NEPacketTunnelProvider` дескриптор utun можно найти среди открытых
дескрипторов процесса (так делают WireGuard и sing-box) и передать в
`rc_start`. Сокеты ядра в Network Extension идут мимо туннеля и без
`rc_set_protect`.

## Десктоп

Проще всего — `rc_start(config, dir, -1, …)` с настройками, как для
`reality-client`: вход `tun` сам создаёт интерфейс и маршруты (нужны
права администратора или root), `mixed` — прокси. Управление —
`rc_request`, без HTTP.

## Проверка

- `cargo test -p reality-ffi` — вызовы C ABI из Rust (на Linux и
  Windows в CI);
- `scripts/ffi_smoke.sh` — настоящая программа на C: запуск, ошибка
  настроек, `rc_request` (выбор сервера, режим, 404), трафик через
  SOCKS5-вход ядра к эхо-серверу, события в обратный вызов,
  `rc_set_protect` для сокетов ядра, `rc_reload`, `rc_stop`; с root — ещё
  запуск с готовым дескриптором TUN (как от `VpnService`).
