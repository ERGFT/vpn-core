/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Minimal embedding example; see docs/LIBRARY.md for the full contract. */
#include <stdio.h>

#include "reality.h"

static const char CONFIG[] =
    "{\"inbounds\":[{\"type\":\"socks\",\"tag\":\"local-socks\","
    "\"listen\":\"127.0.0.1\",\"listen_port\":0}],"
    "\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],"
    "\"route\":{\"final\":\"direct\"}}";

int main(void) {
    char *error = NULL;
    RcCore *core;
    int status = 0;

    printf("vpn-core %s\n", rc_version());
    if (rc_validate(CONFIG, NULL) != 1) {
        fputs("configuration is invalid\n", stderr);
        return 1;
    }

    core = rc_start(CONFIG, NULL, -1, &error);
    if (core == NULL) {
        fprintf(stderr, "could not start vpn-core: %s\n", error ? error : "unknown error");
        rc_free_string(error);
        return 1;
    }

    char *proxies = rc_request(core, "GET", "/proxies", NULL, &status);
    if (proxies == NULL || status != 200) {
        fprintf(stderr, "GET /proxies failed (status %d)\n", status);
        rc_free_string(proxies);
        rc_stop(core);
        return 1;
    }
    puts(proxies);
    rc_free_string(proxies);

    /* A real app keeps core alive and calls rc_request/callback APIs as needed. */
    rc_stop(core);
    return 0;
}
