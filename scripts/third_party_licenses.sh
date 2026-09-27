#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Лицензии всех зависимостей reality-client, вошедших в бинарник, одним
# HTML-файлом — прикладывается к каждому релизу (многие из них, MIT и
# Apache-2.0, требуют передавать свой текст вместе с бинарником).
#
#   scripts/third_party_licenses.sh [файл]   (по умолчанию THIRD-PARTY-LICENSES.html)
#
# Нужен cargo-about: cargo install cargo-about --locked --features cli
# Разрешённые лицензии — about.toml.
set -euo pipefail
cd "$(dirname "$0")/.."

out="${1:-THIRD-PARTY-LICENSES.html}"
cargo about generate --locked --manifest-path bin/client/Cargo.toml \
    --output-file "$out" scripts/about/third-party-licenses.hbs
echo "готово: $out"
