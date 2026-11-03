#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the public C ABI header, Rust exports, and reviewed ABI baseline."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "ffi/include/reality.h"
RUST = ROOT / "ffi/src/lib.rs"
BASELINE = ROOT / "ffi/abi-baseline.json"


def public_api(header: str) -> dict[str, object]:
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", header, flags=re.S)
    functions: dict[str, str] = {}
    for declaration, name in re.findall(
        r"((?:[A-Za-z_][A-Za-z0-9_\s*]*?)\b(rc_[A-Za-z0-9_]+)\s*\([^;]*?\)\s*;)",
        source,
        re.S,
    ):
        functions[name] = " ".join(declaration.split())
    typedefs = sorted(
        " ".join(declaration.split())
        for declaration in re.findall(r"\btypedef\b[^;]*;", source, re.S)
        if "rc_" in declaration or "RcCore" in declaration
    )
    enums: dict[str, dict[str, int]] = {}
    for name, body in re.findall(r"\benum\s+(\w+)\s*\{([^}]*)\}", source, re.S):
        values: dict[str, int] = {}
        for item, value in re.findall(r"\b(RC_[A-Za-z0-9_]+)\s*=\s*(-?\d+)", body):
            values[item] = int(value)
        if values:
            enums[name] = dict(sorted(values.items()))
    if not functions or not enums:
        raise ValueError("header parser found no rc_* functions or RC_* enum values")
    return {
        "format": 1,
        "functions": dict(sorted(functions.items())),
        "typedefs": typedefs,
        "enums": dict(sorted(enums.items())),
    }


def rust_exports(source: str) -> set[str]:
    pattern = r"#\s*\[\s*no_mangle\s*\]\s*pub(?:\s+unsafe)?\s+extern\s+\"C\"\s+fn\s+(rc_[A-Za-z0-9_]+)"
    return set(re.findall(pattern, source))


def compare(snapshot: dict[str, object], baseline: dict[str, object]) -> list[str]:
    errors: list[str] = []
    before = baseline.get("functions", {})
    after = snapshot["functions"]
    if before != after:
        before_names = set(before)
        after_names = set(after)
        if before_names - after_names:
            errors.append("removed/renamed C functions: " + ", ".join(sorted(before_names - after_names)))
        if after_names - before_names:
            errors.append("new C functions require reviewed baseline update: " + ", ".join(sorted(after_names - before_names)))
        changed = sorted(name for name in before_names & after_names if before[name] != after[name])
        if changed:
            errors.append("changed C function signatures: " + ", ".join(changed))
    if snapshot["typedefs"] != baseline.get("typedefs"):
        errors.append("public C ABI typedefs differ from the reviewed baseline")
    if snapshot["enums"] != baseline.get("enums"):
        errors.append("C ABI enum names/values differ from the reviewed baseline")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-baseline", action="store_true", help="rewrite the ABI snapshot after manual compatibility review")
    args = parser.parse_args()

    snapshot = public_api(HEADER.read_text(encoding="utf-8"))
    header_functions = set(snapshot["functions"])
    exports = rust_exports(RUST.read_text(encoding="utf-8"))
    if header_functions != exports:
        missing = sorted(header_functions - exports)
        undeclared = sorted(exports - header_functions)
        print(f"C header/Rust exports differ; missing exports={missing}, undeclared exports={undeclared}", file=sys.stderr)
        return 1

    if args.update_baseline:
        BASELINE.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Updated reviewed ABI snapshot: {BASELINE.relative_to(ROOT)}")
        return 0

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    errors = compare(snapshot, baseline)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print("Review the ABI change and update ffi/abi-baseline.json explicitly if it is intentional.", file=sys.stderr)
        return 1
    print(f"C ABI matches reviewed baseline ({len(header_functions)} functions, {len(snapshot['typedefs'])} typedefs, {sum(map(len, snapshot['enums'].values()))} enum values).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
