# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the release SDK archive and its checksum independently of the source tree."""

import argparse
import hashlib
import zipfile
from pathlib import Path

LIBRARIES = {
    "linux-x86_64": {"libreality.so", "libreality.a"},
    "windows-x86_64": {"reality.dll", "reality.dll.lib", "reality.lib"},
    "macos-arm64": {"libreality.dylib", "libreality.a"},
    "android-arm64-v8a": {"libreality.so", "libreality.a"},
    "ios-arm64": {"libreality.a"},
}


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
        "vpn-core-sdk/README.md", "vpn-core-sdk/LICENSE",
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
        missing = required - set(names)
        if missing:
            raise SystemExit(f"SDK missing files: {sorted(missing)}")
        if any(archive.getinfo(name).file_size == 0 for name in required):
            raise SystemExit("SDK contains an empty required file")
        if archive.testzip() is not None:
            raise SystemExit("SDK archive is corrupt")
    print(f"SDK archive and checksum OK: {args.archive}")


if __name__ == "__main__":
    main()
