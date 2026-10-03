#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Проверка ссылок между документами: у каждой относительной ссылки в .md
# (кроме vendor/) есть файл, а у ссылки с #якорем — заголовок с таким
# якорем. Якорь считается так же, как на GitHub: строчные буквы, пробелы →
# «-», знаки препинания убираются, повтор заголовка — «-1», «-2».
# `<a id="…">` якорем не считается: GitHub такие id в Markdown не оставляет
# (из-за этого переходы на #english не работали). Внешние ссылки (http)
# не проверяются — для этого нужна сеть.
#
#   scripts/check_doc_links.py

import os
import re
import subprocess
import sys
import unicodedata

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

FENCE = re.compile(r"^(```|~~~)")


def slug(heading: str) -> str:
    h = heading.replace("`", "")
    h = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", h)
    h = re.sub(r"<[^>]+>", "", h).strip().lower()
    out = []
    for ch in h:
        if ch == " " or ch == "-":
            out.append("-")
        elif ch == "_" or unicodedata.category(ch)[0] in "LN":
            out.append(ch)
    return "".join(out)


_anchors: dict[str, set[str]] = {}


def anchors(path: str) -> set[str]:
    if path not in _anchors:
        found: set[str] = set()
        seen: dict[str, int] = {}
        in_code = False
        with open(path, encoding="utf-8") as f:
            for line in f:
                if FENCE.match(line):
                    in_code = not in_code
                    continue
                m = None if in_code else re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
                if m:
                    s = slug(m.group(1))
                    n = seen.get(s, 0)
                    seen[s] = n + 1
                    found.add(s if n == 0 else f"{s}-{n}")
        _anchors[path] = found
    return _anchors[path]


def main() -> int:
    files = subprocess.check_output(["git", "ls-files", "*.md", ":!vendor/"], text=True).split()
    bad = 0
    for f in files:
        with open(f, encoding="utf-8") as fh:
            text = fh.read()
        text = re.sub(r"```.*?```", "", text, flags=re.S)
        text = re.sub(r"`[^`\n]*`", "", text)
        for m in re.finditer(r"\[[^\]]*\]\(([^)\s]+)\)", text):
            target = m.group(1)
            if re.match(r"^(https?|mailto):", target):
                continue
            path, _, frag = target.partition("#")
            dest = os.path.normpath(os.path.join(os.path.dirname(f), path)) if path else f
            if not os.path.exists(dest):
                print(f"{f}: нет файла: {target}")
                bad += 1
            elif frag and dest.endswith(".md") and frag not in anchors(dest):
                print(f"{f}: нет заголовка для якоря: {target}")
                bad += 1
    if bad:
        print(f"битых ссылок: {bad}")
        return 1
    print(f"ссылки в документации в порядке ({len(files)} файлов)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
