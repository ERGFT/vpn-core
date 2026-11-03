/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Проверка C ABI (scripts/ffi_smoke.sh): приложение на C запускает ядро,
 * получает события, управляет им через rc_request, перечитывает настройки
 * и останавливает. Настоящий трафик — SOCKS5 через вход ядра к эхо-серверу
 * этого же процесса.
 */
#include <arpa/inet.h>
#include <fcntl.h>
#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#endif
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "reality.h"

static int events_seen = 0;
static int mode_changes = 0;
static int closes = 0;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t callback_cv = PTHREAD_COND_INITIALIZER;
static int blocking_callback_entered = 0;
static int release_blocking_callback = 0;
static int unsubscribe_started = 0;
static int unsubscribe_done = 0;

static void on_event(const char *json, void *user) {
    pthread_mutex_lock(&mu);
    events_seen++;
    if (user) (*(int *)user)++;
    if (strstr(json, "\"mode_change\"")) mode_changes++;
    if (strstr(json, "\"connection_close\"")) closes++;
    pthread_mutex_unlock(&mu);
}

static void on_blocking_event(const char *json, void *user) {
    (void)json;
    (void)user;
    pthread_mutex_lock(&mu);
    blocking_callback_entered = 1;
    pthread_cond_broadcast(&callback_cv);
    while (!release_blocking_callback) pthread_cond_wait(&callback_cv, &mu);
    pthread_mutex_unlock(&mu);
}

static void *unsubscribe_event_callback(void *arg) {
    RcCore *core = (RcCore *)arg;
    pthread_mutex_lock(&mu);
    unsubscribe_started = 1;
    pthread_cond_broadcast(&callback_cv);
    pthread_mutex_unlock(&mu);
    if (rc_set_event_callback(core, NULL, NULL) != 0) return (void *)1;
    pthread_mutex_lock(&mu);
    unsubscribe_done = 1;
    pthread_cond_broadcast(&callback_cv);
    pthread_mutex_unlock(&mu);
    return NULL;
}

static int protected_sockets = 0;
static int on_protect(int64_t fd, void *user) {
    (void)user;
    pthread_mutex_lock(&mu);
    if (fd >= 0) protected_sockets++;
    pthread_mutex_unlock(&mu);
    return 1;
}

#define FAIL(...)                                                                                  \
    do {                                                                                           \
        fprintf(stderr, "ОШИБКА: " __VA_ARGS__);                                                   \
        fprintf(stderr, "\n");                                                                     \
        exit(1);                                                                                   \
    } while (0)

static const char *CONFIG =
    "{\n"
    "  // комментарии — как в файле настроек\n"
    "  \"inbounds\": [{\"type\": \"socks\", \"tag\": \"in\", \"listen\": \"127.0.0.1\", "
    "\"listen_port\": 17971}],\n"
    "  \"outbounds\": [\n"
    "    {\"type\": \"selector\", \"tag\": \"proxy\", \"outbounds\": [\"block\", \"direct\"]},\n"
    "    {\"type\": \"direct\", \"tag\": \"direct\"},\n"
    "    {\"type\": \"block\", \"tag\": \"block\"}\n"
    "  ],\n"
    "  \"route\": {\"final\": \"proxy\"}\n"
    "}";

/* Эхо-сервер на 127.0.0.1:17972 (одно соединение). */
static void *echo(void *arg) {
    int l = *(int *)arg;
    int c = accept(l, NULL, NULL);
    char buf[64];
    ssize_t n = read(c, buf, sizeof buf);
    if (n > 0) write(c, buf, (size_t)n);
    close(c);
    return NULL;
}

/* SOCKS5 CONNECT к 127.0.0.1:17972 и эхо; 0 — прошло. */
static int socks_echo(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(17971)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a)) return -1;
    unsigned char hello[] = {5, 1, 0}, rep[10];
    write(s, hello, 3);
    read(s, rep, 2);
    unsigned char req[] = {5, 1, 0, 1, 127, 0, 0, 1, 17972 >> 8, 17972 & 0xff};
    write(s, req, sizeof req);
    if (read(s, rep, 10) != 10 || rep[1] != 0) {
        close(s);
        return -2;
    }
    write(s, "ping", 4);
    char back[4];
    ssize_t n = read(s, back, 4);
    close(s);
    return (n == 4 && memcmp(back, "ping", 4) == 0) ? 0 : -3;
}

static int64_t on_connection_owner(int protocol, const char *source,
                                 const char *destination, void *user) {
    (void)protocol; (void)source; (void)destination; (void)user;
    return -1;
}

int main(void) {
    printf("reality-core %s\n", rc_version());
    if (rc_validate(CONFIG, NULL) != 1) FAIL("rc_validate: корректные настройки отклонены");
    if (rc_validate("{bad-json}", NULL) != 0) FAIL("rc_validate: битые настройки приняты");
    if (rc_is_alive(NULL) != 0) FAIL("rc_is_alive: NULL принят");
    if (rc_last_error_code(NULL) != RC_ERROR_INVALID_HANDLE) FAIL("rc_last_error_code: NULL принят");
    char *diagnostic = rc_last_error_message(NULL);
    if (!diagnostic || strcmp(diagnostic, "Invalid core handle")) FAIL("rc_last_error_message: NULL");
    rc_free_string(diagnostic);

    char *err = NULL;
    if (rc_start("{ битые настройки", NULL, -1, &err) != NULL) FAIL("битые настройки приняты");
    if (!err || !*err) FAIL("нет текста ошибки");
    printf("OK: ошибка настроек: %s\n", err);
    rc_free_string(err);
    err = NULL;

    rc_set_protect(on_protect, NULL);
    rc_set_connection_owner(on_connection_owner, NULL);
    RcCore *core = rc_start(CONFIG, NULL, -1, &err);
    if (!core) FAIL("rc_start: %s", err);
    if (rc_network_changed(core) != 0) FAIL("rc_network_changed failed");
    printf("OK: host network-change signal accepted\n");
    if (rc_is_alive(core) != 1) FAIL("rc_is_alive: ядро не работает");
    if (rc_last_error_code(core) != RC_ERROR_NONE) FAIL("rc_last_error_code: неожиданная ошибка");
    diagnostic = rc_last_error_message(core);
    if (!diagnostic || *diagnostic) FAIL("rc_last_error_message: ожидалась пустая строка");
    rc_free_string(diagnostic);
    int callback_user_events = 0;
    if (rc_set_event_callback(core, on_event, &callback_user_events) != 0)
        FAIL("rc_set_event_callback");

    int status = 0;
    char *body = rc_request(core, "GET", "/proxies", NULL, &status);
    if (status != 200 || !strstr(body, "\"GLOBAL\"")) FAIL("GET /proxies: %d %s", status, body);
    rc_free_string(body);
    printf("OK: GET /proxies\n");

    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(17972)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(l, (struct sockaddr *)&a, sizeof a) || listen(l, 4)) FAIL("эхо-сервер");
    pthread_t th;
    pthread_create(&th, NULL, echo, &l);

    if (socks_echo() == 0) FAIL("selector смотрит на block, а соединение прошло");
    body = rc_request(core, "PUT", "/proxies/proxy", "{\"name\":\"direct\"}", &status);
    if (status != 204) FAIL("PUT /proxies/proxy: %d %s", status, body);
    rc_free_string(body);
    if (socks_echo() != 0) FAIL("после выбора direct эхо не прошло");
    pthread_join(th, NULL);
    printf("OK: трафик через SOCKS5-вход ядра, выбор сервера через rc_request\n");

    body = rc_request(core, "PATCH", "/configs", "{\"mode\":\"global\"}", &status);
    if (status != 204) FAIL("PATCH /configs: %d %s", status, body);
    rc_free_string(body);
    body = rc_request(core, "GET", "/nope", NULL, &status);
    if (status != 404 || !strstr(body, "message")) FAIL("GET /nope: %d %s", status, body);
    rc_free_string(body);
    body = rc_request(core, NULL, "/proxies", NULL, &status);
    if (status != 400 || !strstr(body, "message")) FAIL("ошибка аргументов rc_request: %d %s", status, body);
    rc_free_string(body);
    if (rc_last_error_code(core) != RC_ERROR_NONE)
        FAIL("ошибка rc_request ошибочно стала терминальной ошибкой ядра");

    char *notes = rc_reload(core, CONFIG, &err);
    if (!notes) FAIL("rc_reload: %s", err);
    rc_free_string(notes);
    if (rc_reload(core, "{\"route\": {\"final\": \"nope\"}}", &err) != NULL) FAIL("битый reload принят");
    rc_free_string(err);
    if (rc_last_error_code(core) != RC_ERROR_NONE)
        FAIL("ошибка rc_reload ошибочно стала терминальной ошибкой ядра");
    diagnostic = rc_last_error_message(core);
    if (!diagnostic || *diagnostic) FAIL("rc_reload изменил диагностику здорового ядра");
    rc_free_string(diagnostic);
    err = NULL;
    notes = rc_reload(core, CONFIG, &err);
    if (!notes || err != NULL) FAIL("rc_reload: успешный вызов оставил диагностику");
    rc_free_string(notes);
    printf("OK: rc_reload\n");

    for (int i = 0; i < 100; i++) {
        pthread_mutex_lock(&mu);
        int ok = mode_changes > 0 && closes > 0;
        pthread_mutex_unlock(&mu);
        if (ok) break;
        usleep(20000);
    }
    pthread_mutex_lock(&mu);
    printf("событий: %d (mode_change: %d, connection_close: %d), защищено сокетов: %d\n",
           events_seen, mode_changes, closes, protected_sockets);
    if (mode_changes == 0 || closes == 0) FAIL("события не дошли");
    if (protected_sockets == 0) FAIL("rc_set_protect не вызывался");
    pthread_mutex_unlock(&mu);

    if (rc_set_event_callback(core, NULL, NULL) != 0) FAIL("снятие event callback");
    pthread_mutex_lock(&mu);
    int callbacks_at_unsubscribe = events_seen;
    callback_user_events = -1;
    pthread_mutex_unlock(&mu);
    usleep(100000);
    pthread_mutex_lock(&mu);
    if (events_seen != callbacks_at_unsubscribe || callback_user_events != -1)
        FAIL("event callback использовал user после снятия подписки");
    callback_user_events = 0;
    pthread_mutex_unlock(&mu);
    if (rc_set_event_callback(core, on_event, &callback_user_events) != 0)
        FAIL("повторная регистрация event callback");

    /* Hold a callback in flight and prove unsubscribe waits for its return. */
    if (rc_set_event_callback(core, on_blocking_event, NULL) != 0)
        FAIL("установка блокирующего callback");
    notes = rc_reload(core, CONFIG, &err);
    if (!notes) FAIL("rc_reload для проверки callback barrier: %s", err ? err : "unknown");
    rc_free_string(notes);
    rc_free_string(err);
    err = NULL;
    for (int i = 0; i < 500; i++) {
        pthread_mutex_lock(&mu);
        int entered = blocking_callback_entered;
        pthread_mutex_unlock(&mu);
        if (entered) break;
        usleep(10000);
    }
    pthread_mutex_lock(&mu);
    if (!blocking_callback_entered) FAIL("rc_reload не доставил событие блокирующему callback");
    pthread_mutex_unlock(&mu);

    pthread_t unsubscribe_thread;
    if (pthread_create(&unsubscribe_thread, NULL, unsubscribe_event_callback, core) != 0)
        FAIL("pthread_create для снятия callback");
    for (int i = 0; i < 500; i++) {
        pthread_mutex_lock(&mu);
        int started = unsubscribe_started;
        pthread_mutex_unlock(&mu);
        if (started) break;
        usleep(10000);
    }
    pthread_mutex_lock(&mu);
    if (!unsubscribe_started) FAIL("поток снятия подписки не запустился");
    pthread_mutex_unlock(&mu);
    usleep(100000);
    pthread_mutex_lock(&mu);
    if (unsubscribe_done) FAIL("снятие callback вернулось до завершения активного callback");
    release_blocking_callback = 1;
    pthread_cond_broadcast(&callback_cv);
    pthread_mutex_unlock(&mu);
    void *unsubscribe_result = NULL;
    pthread_join(unsubscribe_thread, &unsubscribe_result);
    if (unsubscribe_result) FAIL("параллельное снятие callback");
    printf("OK: unsubscribe ждёт активный callback и сохраняет lifetime user\n");

    rc_stop(core);
    rc_stop(NULL);
    pthread_mutex_lock(&mu);
    int callbacks_at_stop = events_seen;
    callback_user_events = -1; /* caller-owned callback state can now be released */
    pthread_mutex_unlock(&mu);
    /* rc_stop is a callback lifetime barrier for the consumer's user data. */
    usleep(100000);
    pthread_mutex_lock(&mu);
    if (events_seen != callbacks_at_stop || callback_user_events != -1)
        FAIL("event callback used consumer state after rc_stop returned");
    pthread_mutex_unlock(&mu);
    printf("OK: rc_stop prevents later event callbacks; NULL stop is safe\n");
    rc_set_protect(NULL, NULL);
    rc_set_connection_owner(NULL, NULL);

#ifdef __linux__
    /* Готовый дескриптор TUN (как от Android VpnService) — нужен root. */
    if (geteuid() == 0) {
        int fd = open("/dev/net/tun", O_RDWR);
        struct ifreq ifr;
        memset(&ifr, 0, sizeof ifr);
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, "rc-ffi0", IFNAMSIZ - 1);
        if (fd < 0 || ioctl(fd, TUNSETIFF, &ifr) < 0) FAIL("не удалось открыть TUN");
        const char *tun_cfg = "{\"inbounds\": [{\"type\": \"tun\", \"tag\": \"tun\"}],"
                              " \"outbounds\": [{\"type\": \"direct\", \"tag\": \"direct\"}]}";
        RcCore *t = rc_start(tun_cfg, NULL, fd, &err);
        if (!t) FAIL("rc_start с дескриптором TUN: %s", err);
        body = rc_request(t, "GET", "/configs", NULL, &status);
        if (status != 200 || !strstr(body, "\"enable\":true")) FAIL("GET /configs: %s", body);
        rc_free_string(body);
        rc_stop(t);
        printf("OK: ядро с готовым дескриптором TUN\n");
        /* Владение дескриптором переходит ядру и при ошибке: передаём
         * свой, свежий (не чужой номер — ядро его закроет), и проверяем,
         * что он закрыт. */
        int stray = open("/dev/null", O_RDONLY);
        if (stray < 0) FAIL("не удалось открыть /dev/null");
        if (rc_start(CONFIG, NULL, stray, &err) != NULL) FAIL("дескриптор без входа tun принят");
        rc_free_string(err);
        if (fcntl(stray, F_GETFD) != -1) FAIL("rc_start не закрыл дескриптор при ошибке");
        printf("OK: при ошибке rc_start закрыл переданный дескриптор\n");
    } else {
        printf("SKIP: дескриптор TUN — нужен root\n");
    }
#endif
    printf("FFI SMOKE PASSED\n");
    return 0;
}
