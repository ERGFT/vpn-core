#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Разница между vendor/rustls-reality-patch и исходным rustls той же
# версии с crates.io — vendor/rustls-reality-patch.diff (docs/RUSTLS_PATCH.md).
#
#   scripts/rustls_patch.sh          — пересоздать .diff
#   scripts/rustls_patch.sh --check  — .diff совпадает с vendor/ (для ci.sh)
#
# То же, что scripts/vendor_patch.sh rustls.
exec bash "$(dirname "$0")/vendor_patch.sh" rustls "$@"
