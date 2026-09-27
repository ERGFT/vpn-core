#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Проверка, что у каждого своего исходника (не vendor/) в первых строках
# есть SPDX-метка лицензии проекта. Новый файл без неё — ошибка с его
# именем; добавить: `// SPDX-License-Identifier: GPL-3.0-or-later`
# (или `#` для sh/ps1/py; у скриптов — сразу после строки #!).
set -euo pipefail
cd "$(dirname "$0")/.."

TAG='SPDX-License-Identifier: GPL-3.0-or-later'
missing=0
while IFS= read -r f; do
    if ! head -n 3 "$f" | grep -qF "$TAG"; then
        echo "нет SPDX-метки: $f"
        missing=1
    fi
done < <(git ls-files '*.rs' '*.go' '*.sh' '*.ps1' '*.py' ':!vendor/')

[[ $missing -eq 0 ]] && echo "SPDX-метки на месте"
exit "$missing"
