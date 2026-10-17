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
 * (особенно rc_is_alive и rc_stop); обратные вызовы
 * приходят из фоновых потоков ядра — не блокируйте их надолго.
 */
#ifndef REALITY_H
#define REALITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Запущенное ядро. */
typedef struct RcCore RcCore;

/* Событие или строка журнала — JSON; строка действительна только во время
 * вызова. */
typedef void (*rc_callback)(const char *json, void *user);

/* Защитить сокет ядра от TUN (Android: VpnService.protect(fd));
 * вернуть 1 — защищён, 0 — нет (сокет тогда не используется). */
typedef int (*rc_protect)(int64_t fd, void *user);

/* UID владельца TUN-потока: protocol = 6 (TCP) или 17 (UDP).
 * source/destination — исходные числовые SocketAddr (IPv6 в [скобках]),
 * до fake-IP и sniffing; строки действительны только во время callback.
 * Вернуть UID 0..UINT32_MAX или -1 (неизвестен). */
typedef int64_t (*rc_connection_owner)(int protocol, const char *source,
                                     const char *destination, void *user);

/* Версия ядра, например "0.1.0" (освобождать не нужно). */
const char *rc_version(void);

/* Предварительная проверка без запуска входов/TUN: 1 — успех, 0 — ошибка.
 * config — UTF-8 с нулём в конце, NULL недопустим; base_dir может быть NULL.
 * Читает файлы настроек (CA, правила и т.п.), но не проверяет доступность
 * сети, разрешения ОС и внешний FD; rc_start всё равно может не удаться.
 * Текст ошибок не выдаётся, чтобы не раскрыть значения конфигурации. */
int rc_validate(const char *config, const char *base_dir);

/*
 * Запустить ядро.
 *   config   — настройки текстом: JSON sing-box или Xray-core (формат
 *              определяется сам), как файл для `reality-client --config`;
 *   base_dir — папка для относительных путей в настройках (NULL — текущая);
 *   tun_fd   — дескриптор TUN от системы (Android: ParcelFileDescriptor
 *              .detachFd() — владение переходит ядру при вызове; при ошибке
 *              rc_start ядро закроет его само) или -1; с дескриптором
 *              маршруты и kill switch — забота системы, в настройках нужен
 *              вход "tun";
 *   error    — при ошибке сюда пишется её текст (освободить rc_free_string);
 *              может быть NULL.
 * Возвращает ядро или NULL.
 */
RcCore *rc_start(const char *config, const char *base_dir, int tun_fd, char **error);

/* Неблокирующая проверка: 1 — терминальная ошибка не получена; 0 — ошибка
 * или NULL. Ошибка сохраняется до перезапуска. Сериализовать с другими
 * операциями на живом handle, включая stop. Это не проверка интернета
 * и не гарантия обнаружения ошибок всех отсоединённых задач. */
int rc_is_alive(RcCore *core);

/* Остановить ядро: входы закрываются, маршруты возвращаются, обратные
 * вызовы прекращаются. После этого core недействителен. NULL — ничего. */
void rc_stop(RcCore *core);

/*
 * Запрос к API ядра — те же пути и ответы, что у HTTP API (Clash API и
 * свои), без сети и токена:
 *   rc_request(core, "GET", "/proxies", NULL, &status);
 *   rc_request(core, "PUT", "/proxies/proxy", "{\"name\":\"auto\"}", &status);
 *   rc_request(core, "PATCH", "/configs", "{\"mode\":\"global\"}", &status);
 *   rc_request(core, "GET", "/connections", NULL, &status);
 * body — NULL или JSON. В status (если не NULL) — код ответа HTTP.
 * Возвращает тело ответа (JSON; "" у 204) — освободить rc_free_string.
 * Потоки (/events, /logs…) — через rc_set_event_callback, rc_set_log_callback.
 */
char *rc_request(RcCore *core, const char *method, const char *path, const char *body,
                 int *status);

/* Применить новые настройки без разрыва соединений. Возвращает JSON
 * {"notes": [...]} (что вступит в силу только после перезапуска) или NULL
 * при ошибке (текст — в error); при ошибке работают прежние настройки. */
char *rc_reload(RcCore *core, const char *config, char **error);

/* События ядра (как GET /events): connection_open, connection_close,
 * group_switch, group_check, subscription_update, reload, mode_change,
 * lagged. cb = NULL — перестать. 0 — успех, -1 — ошибка. */
int rc_set_event_callback(RcCore *core, rc_callback cb, void *user);

/* Журнал ядра не подробнее level ("debug", "info", "warning", "error";
 * NULL — "info"): {"type": "info", "payload": "..."}. cb = NULL —
 * перестать. 0 — успех, -1 — ошибка. */
int rc_set_log_callback(RcCore *core, const char *level, rc_callback cb, void *user);

/* Защищать каждый новый сокет ядра обратным вызовом (Android). Вызывать до
 * rc_start; действует на весь процесс. cb = NULL — перестать. */
void rc_set_protect(rc_protect cb, void *user);

/* Resolver UID: вызывать до rc_start, действует на весь процесс.
 * cb/user потокобезопасны, не блокируют и живут до остановки всех ядер и
 * завершения callback. NULL снимает resolver; снимать только после rc_stop.
 * Нужен для user_id-правил в TUN. Неизвестный UID при нужном правиле
 * блокирует поток, а не отправляет его через route.final/direct.
 * Android: ConnectivityManager.getConnectionOwnerUid (API 29+).
 * Имена пакетов и shared UID преобразует приложение, не ядро. */
void rc_set_connection_owner(rc_connection_owner cb, void *user);

/* Windows: каталог для файла блокировки auto_route — запись в него только
 * у SYSTEM и администраторов. Без него вход TUN с auto_route на Windows не
 * запускается (с готовым дескриптором TUN не нужен). Вызывать до rc_start,
 * один раз; на других системах ничего не делает. 0 — успех, -1 — ошибка. */
int rc_set_lock_dir(const char *dir);

/* Освободить строку, которую вернула библиотека. NULL — ничего. */
void rc_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* REALITY_H */
