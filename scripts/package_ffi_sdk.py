# SPDX-License-Identifier: GPL-3.0-or-later
"""Package a platform's C ABI library and integration files for a release."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = (
    "LIBRARY.md",
    "LIBRARY.en.md",
    "API.md",
    "API.en.md",
    "APPLICATION_ROUTING.md",
    "APPLICATION_ROUTING.en.md",
)
TARGETS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "windows-x86_64": "x86_64-pc-windows-msvc",
    "macos-arm64": "aarch64-apple-darwin",
    "android-arm64-v8a": "aarch64-linux-android",
    "ios-arm64": "aarch64-apple-ios",
}
MINIMUM_OS = {"ios-arm64": "13.0"}


def library_kind(name: str) -> str:
    if name.endswith(".dll.lib"):
        return "import"
    if name.endswith((".so", ".dylib", ".dll")):
        return "shared"
    if name.endswith((".a", ".lib")):
        return "static"
    raise ValueError(f"unrecognized library artifact: {name}")


def tool_version(command: str) -> str:
    return subprocess.run(
        [command, "--version"], check=True, capture_output=True, text=True
    ).stdout.strip().splitlines()[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--library", action="append", type=Path, required=True,
        help="shared/static library or import library to include; repeat as needed",
    )
    args = parser.parse_args()

    if args.platform not in TARGETS:
        parser.error(f"unsupported platform: {args.platform}")
    if TARGETS[args.platform] != args.target:
        parser.error(f"target for {args.platform} must be {TARGETS[args.platform]}")

    for path in args.library:
        if not path.is_file():
            parser.error(f"library does not exist: {path}")

    archive = args.output / f"vpn-core-sdk-{args.platform}.zip"
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vpn-core-sdk-") as temporary:
        stage = Path(temporary)
        (stage / "include").mkdir()
        (stage / "lib").mkdir()
        (stage / "examples").mkdir()
        (stage / "docs").mkdir()

        shutil.copy2(ROOT / "ffi/include/reality.h", stage / "include/reality.h")
        shutil.copy2(ROOT / "ffi/examples/minimal.c", stage / "examples/minimal.c")
        for name in DOCS:
            shutil.copy2(ROOT / "docs" / name, stage / "docs" / name)
        shutil.copy2(ROOT / "LICENSE", stage / "LICENSE")
        for library in args.library:
            shutil.copy2(library, stage / "lib" / library.name)

        (stage / "README.md").write_text(
            f"# vpn-core C ABI SDK {args.version}\n\n"
            f"Platform: `{args.platform}`. See `manifest.json` for the target, "
            "toolchain, minimum OS information, and per-file SHA-256 values. "
            "This package contains the compiled "
            "vpn-core library, its C ABI header, a minimal C integration "
            "example, and the API/integration guides in `docs/`.\n\n"
            "Start with `docs/LIBRARY.md` or `docs/LIBRARY.en.md`. The API can "
            "be called directly through `rc_request`; event and log streams "
            "are available through callbacks. Android and iOS VPN host APIs "
            "remain the responsibility of the embedding application.\n\n"
            "License: GPL-3.0-or-later. Read `LICENSE` and the release's "
            "third-party license notices before distributing an application "
            "that embeds this library.\n",
            encoding="utf-8",
        )

        files = []
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                relative = path.relative_to(stage).as_posix()
                data = path.read_bytes()
                record = {
                    "path": relative,
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                if relative.startswith("lib/"):
                    record["kind"] = library_kind(path.name)
                files.append(record)

        manifest = {
            "schema_version": 1,
            "project": "vpn-core",
            "version": args.version.removeprefix("v"),
            "release_tag": args.version if args.version.startswith("v") else f"v{args.version}",
            "platform": args.platform,
            "target": args.target,
            "minimum_os": MINIMUM_OS.get(args.platform),
            "minimum_os_note": (
                "Project minimum is not declared; verify against the target toolchain."
                if args.platform not in MINIMUM_OS
                else "Configured by IPHONEOS_DEPLOYMENT_TARGET in the release workflow."
            ),
            "toolchain": {
                "rustc": tool_version("rustc"),
                "cargo": tool_version("cargo"),
                "build_host": platform.system(),
            },
            "files": files,
        }
        (stage / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    zf.write(path, Path("vpn-core-sdk") / path.relative_to(stage))

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + ".sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="ascii"
    )


if __name__ == "__main__":
    main()
