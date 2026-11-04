// SPDX-License-Identifier: GPL-3.0-or-later
#include <iostream>

#include "reality.h"

int main() {
    constexpr char config[] =
        R"({"inbounds":[{"type":"socks","tag":"local-socks","listen":"127.0.0.1","listen_port":0}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})";
    const char *version = rc_version();
    if (version == nullptr || rc_validate(config, nullptr) != 1) {
        return 1;
    }

    std::cout << "vpn-core C++ SDK consumer " << version << '\n';
    return 0;
}
