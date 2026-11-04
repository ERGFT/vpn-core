# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the release SDK archive and its checksum independently of the source tree."""

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

LIBRARIES = {
    "linux-x86_64": {"libreality.so", "libreality.a"},
    "windows-x86_64": {"reality.dll", "reality.dll.lib", "reality.lib"},
    "macos-arm64": {"libreality.dylib", "libreality.a"},
    "android-arm64-v8a": {"libreality.so", "libreality.a"},
    "ios-arm64": {"libreality.a"},
}
TARGETS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "windows-x86_64": "x86_64-pc-windows-msvc",
    "macos-arm64": "aarch64-apple-darwin",
    "android-arm64-v8a": "aarch64-linux-android",
    "ios-arm64": "aarch64-apple-ios",
}
MINIMUM_OS = {"ios-arm64": "13.0"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=LIBRARIES)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()

    checksum = args.archive.with_suffix(args.archive.suffix + ".sha256")
    expected = f"{hashlib.sha256(args.archive.read_bytes()).hexdigest()}  {args.archive.name}"
    if checksum.read_text(encoding="ascii").strip() != expected:
        raise SystemExit("SDK checksum mismatch")

    required = {
        "vpn-core-sdk/README.md", "vpn-core-sdk/LICENSE", "vpn-core-sdk/manifest.json",
        "vpn-core-sdk/include/reality.h", "vpn-core-sdk/examples/minimal.c",
        *(f"vpn-core-sdk/docs/{name}" for name in (
            "LIBRARY.md", "LIBRARY.en.md", "API.md", "API.en.md",
            "APPLICATION_ROUTING.md", "APPLICATION_ROUTING.en.md",
        )),
        *(f"vpn-core-sdk/lib/{name}" for name in LIBRARIES[args.platform]),
    }
    with zipfile.ZipFile(args.archive) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise SystemExit("SDK contains duplicate paths")
        if any(not name.startswith("vpn-core-sdk/") for name in names):
            raise SystemExit("SDK archive contains files outside vpn-core-sdk/")
        missing = required - set(names)
        if missing:
            raise SystemExit(f"SDK missing files: {sorted(missing)}")
        if any(archive.getinfo(name).file_size == 0 for name in required):
            raise SystemExit("SDK contains an empty required file")
        if archive.testzip() is not None:
            raise SystemExit("SDK archive is corrupt")
        prefix = "vpn-core-sdk/"
        manifest = json.loads(archive.read(prefix + "manifest.json"))
        if not isinstance(manifest, dict):
            raise SystemExit("SDK manifest must be a JSON object")
        if manifest.get("schema_version") != 1:
            raise SystemExit("unsupported SDK manifest schema_version")
        if (manifest.get("project") != "vpn-core" or manifest.get("platform") != args.platform
                or manifest.get("target") != TARGETS[args.platform]):
            raise SystemExit("SDK manifest project/platform/target mismatch")
        if not isinstance(manifest.get("version"), str) or not isinstance(manifest.get("release_tag"), str):
            raise SystemExit("SDK manifest version/release_tag must be strings")
        minimum_os = manifest.get("minimum_os")
        if minimum_os != MINIMUM_OS.get(args.platform):
            raise SystemExit("SDK manifest minimum_os does not match the platform build settings")
        toolchain = manifest.get("toolchain")
        if not isinstance(toolchain, dict) or any(
            not isinstance(toolchain.get(key), str) or not toolchain[key]
            for key in ("rustc", "cargo", "build_host")
        ):
            raise SystemExit("SDK manifest toolchain metadata is incomplete")
        static_link = manifest.get("static_link")
        if (not isinstance(static_link, dict)
                or static_link.get("source") != "rustc --print=native-static-libs"
                or not isinstance(static_link.get("arguments"), list)
                or any(not isinstance(argument, str) or not argument
                       for argument in static_link["arguments"])):
            raise SystemExit("SDK manifest static_link metadata is incomplete or invalid")
        records = manifest.get("files")
        if not isinstance(records, list):
            raise SystemExit("SDK manifest files must be an array")
        paths = [item.get("path") for item in records if isinstance(item, dict)]
        if (len(paths) != len(records) or any(not isinstance(path, str) for path in paths)
                or len(paths) != len(set(paths))):
            raise SystemExit("SDK manifest has invalid or duplicate file records")
        archived = {name[len(prefix):] for name in names if name.startswith(prefix)}
        if archived != set(paths) | {"manifest.json"}:
            raise SystemExit("SDK manifest file list does not match archive contents")
        for item in records:
            name = item["path"]
            if name.startswith("/") or ".." in name.split("/"):
                raise SystemExit(f"unsafe path in SDK manifest: {name}")
            if (not isinstance(item.get("size_bytes"), int) or item["size_bytes"] < 0
                    or not isinstance(item.get("sha256"), str)
                    or len(item["sha256"]) != 64
                    or any(char not in "0123456789abcdef" for char in item["sha256"])):
                raise SystemExit(f"invalid size/hash in SDK manifest: {name}")
            data = archive.read(prefix + name)
            if item.get("size_bytes") != len(data):
                raise SystemExit(f"SDK manifest size mismatch: {name}")
            if item.get("sha256") != hashlib.sha256(data).hexdigest():
                raise SystemExit(f"SDK manifest SHA-256 mismatch: {name}")
        library_records = {item["path"].removeprefix("lib/"): item.get("kind")
                           for item in records if item["path"].startswith("lib/")}
        expected_kinds = {
            name: ("import" if name.endswith(".dll.lib") else
                   "shared" if name.endswith((".so", ".dylib", ".dll")) else "static")
            for name in LIBRARIES[args.platform]
        }
        if library_records != expected_kinds:
            raise SystemExit("SDK manifest library list/kinds do not match platform")
    print(f"SDK archive and checksum OK: {args.archive}")


if __name__ == "__main__":
    main()
