/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * reality-core как библиотека: C ABI для приложений — Android (VpnService),
 * iOS (Network Extension), десктопных клиентов. Подробно — docs/LIBRARY.md.
 *
 * Библиотека: libreality.so / libreality.dylib / reality.dll (и статическая
 * libreality.a) — `cargo build --release -p reality-ffi`.
 *
 * Строки — UTF-8 с нулём в конце. Строки, которые возвращает библиотека,
 * освобождаются rc_free_string. Вызовы с одним RcCore сериализует приложение
 * (особенно rc_is_alive и rc_stop); callback-функции могут вызываться из
 * потоков ядра одновременно. Host обязан обеспечить потокобезопасность своего
 * состояния и не блокировать поток ядра надолго. Ни один callback не должен
 * переносить через C ABI C++-исключение, Rust panic или longjmp; ловите C++-
 * исключения внутри callback. Event/log callbacks не должны вызывать функции
 * для того же RcCore. Их JSON действует до возврата callback; user должен
 * оставаться живым до снятия callback или возврата rc_stop.
 *
 * reality-core as a library: a C ABI for apps on Android (VpnService), iOS
 * (Network Extension), and desktop. See docs/LIBRARY.en.md for details.
 *
 * Build with `cargo build --release -p reality-ffi`. Artifacts depend on the
 * target: Linux/Android use libreality.so and libreality.a; macOS uses
 * libreality.dylib and libreality.a; Windows uses reality.dll plus import
 * libraries; iOS uses static libreality.a only.
 *
 * Strings are NUL-terminated UTF-8. Strings returned by the library must be
 * released with rc_free_string. The host must serialize calls on one RcCore
 * (especially rc_is_alive and rc_stop); callbacks may run concurrently on
 * core threads. The host must make its state thread-safe and must not block a
 * core thread for long. No callback may let a C++ exception, Rust panic, or
 * longjmp cross the C ABI; catch C++ exceptions inside the callback. Event
 * and log callbacks must not call functions on the same RcCore. Their JSON is
 * valid only until the callback returns; user must stay alive until the
 * callback is removed or rc_stop returns.
 */
#ifndef REALITY_H
#define REALITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Запущенное ядро. / A running core. */
typedef struct RcCore RcCore;

/* Стабильные категории rc_last_error_code; значения входят в C ABI и
 * не должны перенумеровываться. */
/* Stable rc_last_error_code categories. These values are part of the C ABI
 * and must not be renumbered. */
enum rc_error_code {
    RC_ERROR_NONE = 0,
    RC_ERROR_INVALID_HANDLE = -1,
    RC_ERROR_CONFIGURATION = 1,
    RC_ERROR_IO = 2,
    RC_ERROR_BLOCKED = 3,
    RC_ERROR_PROTOCOL = 4,
    RC_ERROR_TLS = 5,
    RC_ERROR_DNS = 6,
    RC_ERROR_AUTHENTICATION = 7,
    RC_ERROR_INTERNAL = 255
};

/* Событие или строка журнала — JSON; строка действительна только во время
 * вызова. */
/* An event or log entry as JSON; the string is valid only during the call. */
typedef void (*rc_callback)(const char *json, void *user);

/* Защитить сокет ядра от TUN (Android: VpnService.protect(fd));
 * вернуть 1 — защищён, 0 — нет (сокет тогда не используется). */
/* Exclude a core socket from the TUN (Android: VpnService.protect(fd)).
 * Return 1 if protected, or 0 otherwise (the socket will not be used). */
typedef int (*rc_protect)(int64_t fd, void *user);

/* UID владельца TUN-потока: protocol = 6 (TCP) или 17 (UDP).
 * source/destination — исходные числовые SocketAddr (IPv6 в [скобках]),
 * до fake-IP и sniffing; строки действительны только во время callback.
 * Вернуть UID 0..UINT32_MAX или -1 (неизвестен). */
/* Resolve the owner UID of a TUN flow: protocol is 6 (TCP) or 17 (UDP).
 * source/destination are the original numeric SocketAddr values (IPv6 in
 * brackets), before fake-IP and sniffing; strings are valid only during this
 * callback. Return a UID in 0..UINT32_MAX, or -1 if unknown. */
typedef int64_t (*rc_connection_owner)(int protocol, const char *source,
                                     const char *destination, void *user);

/* Версия ядра, например "0.1.0" (освобождать не нужно).
 * Core version, for example "0.1.0" (do not free the returned pointer). */
const char *rc_version(void);

/* Предварительная проверка без запуска входов/TUN: 1 — успех, 0 — ошибка.
 * config — UTF-8 с нулём в конце, NULL недопустим; base_dir может быть NULL.
 * Читает файлы настроек (CA, правила и т.п.), но не проверяет доступность
 * сети, разрешения ОС и внешний FD; rc_start всё равно может не удаться.
 * Текст ошибок не выдаётся, чтобы не раскрыть значения конфигурации. */
/* Validate configuration without starting inbounds or TUN: 1 means success,
 * 0 means an error. config must be non-NULL, NUL-terminated UTF-8; base_dir
 * may be NULL. Reads referenced files (CA, rules, etc.) but does not check
 * network availability, OS permissions, or an external FD; rc_start may still
 * fail. Error text is not exposed to avoid leaking configuration values. */
int rc_validate(const char *config, const char *base_dir);

/*
 * Запустить ядро.
 *   config   — обязательная UTF-8 строка с нулём в конце: JSON в поддерживаемой
 *              ядром части форматов sing-box или Xray-core; см.
 *              https://github.com/ERGFT/vpn-core/blob/main/docs/CONFIG.md,
 *              как для `reality-client --config`;
 *   base_dir — папка для относительных путей в настройках (NULL — текущая);
 *   tun_fd   — дескриптор TUN от системы на Unix (Android:
 *              ParcelFileDescriptor.detachFd(); владение переходит ядру при
 *              вызове и дескриптор закрывается при ошибке запуска) или -1;
 *              с дескриптором маршруты и kill switch — забота системы, в
 *              настройках нужен вход "tun". На не-Unix системах передавать
 *              дескриптор нельзя. -1 означает отсутствие дескриптора;
 *              другие отрицательные значения недопустимы;
 *   error    — при ошибке сюда пишется её текст (освободить rc_free_string);
 *              может быть NULL.
 * Возвращает ядро или NULL.
 */
/* Start the core.
 *   config   — required NUL-terminated UTF-8 string: JSON in the subset of
 *              sing-box or Xray-core supported by the core; see
 *              https://github.com/ERGFT/vpn-core/blob/main/docs/CONFIG.md,
 *              in the same format as `reality-client --config`;
 *   base_dir — base directory for relative paths (NULL means current dir);
 *   tun_fd   — system-provided TUN descriptor on Unix (Android:
 *              ParcelFileDescriptor.detachFd()). Ownership transfers to the
 *              core on call; it is closed if startup fails. With an FD,
 *              routing and kill switch are the system's responsibility, and
 *              the config needs a "tun" inbound. Pass no descriptor on
 *              non-Unix systems. -1 means no descriptor; other negative
 *              values are invalid;
 *   error    — receives error text on failure (free with rc_free_string); may
 *              be NULL.
 * Returns the core or NULL.
 */
RcCore *rc_start(const char *config, const char *base_dir, int tun_fd, char **error);

/* Неблокирующая проверка: 1 — терминальная ошибка не получена; 0 — ошибка
 * или NULL. Ошибка сохраняется до перезапуска. Сериализовать с другими
 * операциями на живом handle, включая stop. Это не проверка интернета
 * и не гарантия обнаружения ошибок всех отсоединённых задач. */
/* Non-blocking check: 1 means no terminal error has been reported; 0 means an
 * error or NULL. The error remains until restart. Serialize with other calls
 * on a live handle, including stop. This does not test internet connectivity
 * and cannot guarantee detection of errors in every detached task. */
int rc_is_alive(RcCore *core);

/* Неблокирующий опрос терминальной ошибки. 0 — терминальной ошибки нет,
 * -1 — NULL, остальные значения — стабильные RC_ERROR_* категории.
 * Ошибка сохраняется при повторном чтении до rc_stop. Ошибки отдельных
 * rc_request/rc_reload передаются их результатом и сами по себе не меняют
 * терминальное состояние ядра. Текст общий и не содержит настроек, адресов,
 * UUID или учётных данных. Строка (пустая при отсутствии ошибки) выделена
 * библиотекой и освобождается rc_free_string. Вызовы сериализуются с
 * остальными операциями на этом RcCore; после rc_stop handle недействителен. */
/* Non-blocking terminal-error query. 0 means no terminal error; -1 means
 * NULL; other values are stable RC_ERROR_* categories. The error is retained
 * across reads until rc_stop. Individual rc_request/rc_reload failures are
 * returned by those calls and do not by themselves change the core's terminal
 * state. The generic message contains no configuration, addresses, UUIDs, or
 * credentials. The message (empty when there is no error) is library-allocated
 * and must be freed with rc_free_string. Serialize calls with all other
 * operations on this RcCore; the handle is invalid after rc_stop. */
int rc_last_error_code(RcCore *core);
char *rc_last_error_message(RcCore *core);

/* Остановить ядро: входы закрываются, маршруты auto_route, которые установило
 * ядро, снимаются. При внешнем TUN маршрутами управляет встраивающее
 * приложение. Функция ждёт завершения выполняющихся event/log callbacks и
 * запрещает новые; после
 * возврата callback-функцию и user можно освободить. Не вызывайте rc_stop из
 * callback этого core. После этого core недействителен. NULL — ничего. */
/* Stop the core: inbounds are closed and core-managed auto_route routes are
 * removed. With an external TUN, the host application controls the routes.
 * The function waits for running event/log callbacks and prevents new ones
 * from starting. After return, the
 * callback and user data may be freed. Do not call rc_stop from a callback for
 * this core. The core handle becomes invalid. NULL is a no-op. */
void rc_stop(RcCore *core);

/* Сообщить ядру, что host зафиксировал смену сети (Wi-Fi/cellular, default
 * route или VPN underlay). Ядро не отслеживает ОС самостоятельно: этот вызов
 * очищает DNS/server-address cache и отменяет текущие tracked-соединения,
 * сохраняя настройки и входы. 0 — сигнал обработан, -1 — NULL handle или
 * внутренняя ошибка. Сериализовать с операциями на RcCore. */
/* Notify the core that the host detected a network change (Wi-Fi/cellular,
 * default route, or VPN underlay). The core does not monitor the OS itself.
 * This clears DNS/server-address caches and cancels tracked connections while
 * preserving configuration and inbounds. 0 means handled; -1 means a NULL
 * handle or internal error. Serialize with other RcCore operations. */
int rc_network_changed(RcCore *core);

/*
 * Запрос к API ядра — те же пути и ответы, что у HTTP API (Clash API и
 * свои), без сети и токена:
 *   rc_request(core, "GET", "/proxies", NULL, &status);
 *   rc_request(core, "PUT", "/proxies/proxy", "{\"name\":\"auto\"}", &status);
 *   rc_request(core, "PATCH", "/configs", "{\"mode\":\"global\"}", &status);
 *   rc_request(core, "GET", "/connections", NULL, &status);
 * method/path — обязательные UTF-8 строки с нулём в конце; core — живой
 * handle. body — NULL или JSON; status — NULL или место под код ответа HTTP.
 * Возвращает выделенную библиотекой строку с телом (JSON; "" у 204), даже
 * при ошибке аргументов — освободить rc_free_string.
 * Потоки (/events, /logs…) — через rc_set_event_callback, rc_set_log_callback.
 */
/* Request the core API using the same paths and responses as the HTTP API
 * (Clash API and project-specific endpoints), without networking or a token:
 *   rc_request(core, "GET", "/proxies", NULL, &status);
 *   rc_request(core, "PUT", "/proxies/proxy", "{\"name\":\"auto\"}", &status);
 *   rc_request(core, "PATCH", "/configs", "{\"mode\":\"global\"}", &status);
 *   rc_request(core, "GET", "/connections", NULL, &status);
 * method and path are required NUL-terminated UTF-8 strings; core must be a
 * live handle. body may be NULL or JSON; status may be NULL or a pointer to
 * receive the HTTP response code. Returns a library-allocated response body
 * (JSON; empty for 204), including for argument errors; free it with
 * rc_free_string. Streams (/events, /logs, etc.) use the callback functions.
 */
char *rc_request(RcCore *core, const char *method, const char *path, const char *body,
                 int *status);

/* Применить новые настройки без разрыва соединений. config — обязательная
 * UTF-8 строка с нулём в конце; error — NULL или место под указатель.
 * Возвращает выделенный JSON {"notes": [...]} (что вступит в силу только
 * после перезапуска) или NULL при ошибке. Только при ошибке в error
 * записывается выделенная строка — освободить rc_free_string. При ошибке
 * работают прежние настройки. */
/* Apply new configuration without disconnecting existing connections.
 * config is a required NUL-terminated UTF-8 string; error may be NULL or point
 * to a location for a string pointer. Returns an allocated JSON string
 * {"notes": [...]} describing settings that take effect only after restart,
 * or NULL on error. Only on error, error receives an allocated string; free it
 * with rc_free_string. On failure, the previous configuration remains active. */
char *rc_reload(RcCore *core, const char *config, char **error);

/* События ядра (как GET /events): connection_open, connection_close,
 * group_switch, group_check, subscription_update, reload, mode_change,
 * lagged. JSON действует только до возврата callback; user должен оставаться
 * живым до снятия callback или возврата rc_stop. cb = NULL
 * снимает подписку; также при замене callback функция ждёт уже выполняющийся
 * callback. После возврата можно освободить старые callback/user. Callback не
 * должен вызывать функции для того же RcCore. 0 — успех, -1 — ошибка. */
/* Core events (as in GET /events): connection_open, connection_close,
 * group_switch, group_check, subscription_update, reload, mode_change, and
 * lagged. JSON is valid only until the callback returns; user must stay alive
 * until the callback is removed or rc_stop returns. cb = NULL unsubscribes;
 * replacing a callback waits for the current callback to finish.
 * After return, the previous callback and user data may be freed. A callback
 * must not call functions on the same RcCore. 0 means success; -1 means error. */
int rc_set_event_callback(RcCore *core, rc_callback cb, void *user);

/* Журнал ядра не подробнее level ("debug", "info", "warning", "error";
 * NULL — "info"): {"type": "info", "payload": "..."}. cb = NULL снимает
 * подписку; замена/снятие ждут текущий callback. После возврата можно
 * освободить старые callback/user. Callback не должен вызывать функции для
 * того же RcCore. 0 — успех, -1 — ошибка. */
/* Core log with maximum verbosity `level` ("debug", "info", "warning", or
 * "error"; NULL means "info"): {"type":"info","payload":"..."}. cb = NULL
 * unsubscribes; replacing/removing the callback waits for the current callback
 * to finish. After return, the previous callback and user data may be freed.
 * A callback must not call functions on the same RcCore. 0 means success;
 * -1 means error. */
int rc_set_log_callback(RcCore *core, const char *level, rc_callback cb, void *user);

/* Защищать каждый новый сокет ядра обратным вызовом (Android). Вызывать до
 * rc_start; действует на весь процесс. cb = NULL снимает callback. Callback
 * может вызываться одновременно из потоков ядра; cb/user должны быть
 * потокобезопасны. Замена/снятие ждут выполняющиеся вызовы; после возврата
 * старые callback/user можно освободить. Callback должен быстро вернуться и
 * не вызывать rc_set_protect из самого себя. */
/* Use this callback to protect every new core socket (Android). Call before
 * rc_start; it is process-wide. cb = NULL removes it. Calls may run
 * concurrently on core threads, so cb/user must be thread-safe. Replacing or
 * removing waits for active calls, so the old callback and user data may be
 * freed after return. The callback must return quickly and must not call
 * rc_set_protect recursively. */
void rc_set_protect(rc_protect cb, void *user);

/* Resolver UID: cb = NULL снимает resolver. Вызывать до rc_start, действует
 * на весь процесс. cb/user потокобезопасны. Замена/снятие ждут текущие
 * вызовы; после возврата старые callback/user можно освободить. Callback
 * должен быстро вернуться и не вызывать rc_set_connection_owner из самого себя.
 * Нужен для user_id-правил в TUN. Неизвестный UID при нужном правиле
 * блокирует поток, а не отправляет его через route.final/direct.
 * Android: ConnectivityManager.getConnectionOwnerUid (API 29+).
 * Имена пакетов и shared UID преобразует приложение, не ядро. */
/* UID resolver: cb = NULL removes the resolver. Call before rc_start; the
 * setting is process-wide. cb/user must be thread-safe. Replacing/removing
 * waits for active calls, so the old callback and user data may be freed after
 * return. The callback must return quickly and must not call
 * rc_set_connection_owner recursively.
 * Required for user_id rules in TUN. If a matching rule requires the UID and
 * it is unknown, the flow is blocked instead of using route.final/direct.
 * Android uses ConnectivityManager.getConnectionOwnerUid (API 29+). The host
 * app, not the core, maps package names and shared UIDs. */
void rc_set_connection_owner(rc_connection_owner cb, void *user);

/* Windows: dir — обязательная UTF-8 строка с нулём в конце; NULL или
 * некорректный UTF-8 даёт -1, принятие строки — 0. Функция не проверяет
 * существование каталога и его права; каталог для файла блокировки
 * auto_route приложение должно защитить так, чтобы писать могли только
 * SYSTEM и администраторы. Ошибка открытия обнаружится при запуске TUN с
 * auto_route. Путь задаётся до rc_start один раз; повторный вызов не заменит
 * уже заданный путь. На других системах настройка не действует. Строка пути
 * нужна только на время вызова. */
/* dir must be a NUL-terminated UTF-8 string; NULL or invalid UTF-8 returns
 * -1, and accepting the string returns 0. The function does not check whether
 * the directory exists or its permissions. On Windows, the host app must
 * protect the auto_route lock directory so only SYSTEM and administrators
 * can write to it; an open error is reported when TUN with auto_route starts.
 * Set the path once before rc_start; a later call does not replace it. The
 * setting has no effect on other systems. The path string is borrowed only
 * for the duration of the call. */
int rc_set_lock_dir(const char *dir);

/* Освободить строку, которую вернула библиотека. NULL — ничего.
 * Free a string returned by the library. NULL is a no-op. */
void rc_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* REALITY_H */
