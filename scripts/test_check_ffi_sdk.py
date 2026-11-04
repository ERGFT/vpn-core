# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression checks for SDK archive validation."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

CHECKER = Path(__file__).with_name("check_ffi_sdk.py")
DOCS = ("LIBRARY.md", "LIBRARY.en.md", "API.md", "API.en.md",
        "APPLICATION_ROUTING.md", "APPLICATION_ROUTING.en.md")
FILES = ("README.md", "LICENSE", "include/reality.h", "examples/minimal.c",
         "lib/libreality.so", "lib/libreality.a", "lib/pkgconfig/vpn-core.pc",
         "cmake/vpn-core/vpn-coreConfig.cmake", "cmake/vpn-core/vpn-coreConfigVersion.cmake",
         *(f"docs/{x}" for x in DOCS))
TARGET = "x86_64-unknown-linux-gnu"


class ArchiveCheck(unittest.TestCase):
    def test_valid_corrupt_and_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "sdk.zip"
            checksum = archive.with_suffix(".zip.sha256")

            def create(files, *, extra=None, manifest_overrides=None, data="fixture"):
                contents = {name: data.encode() for name in files}
                if extra:
                    contents.update({name: value.encode() for name, value in extra.items()})
                records = [
                    {"path": name, "size_bytes": len(value),
                     "sha256": hashlib.sha256(value).hexdigest(),
                     **({"kind": "shared"} if name == "lib/libreality.so" else
                        {"kind": "static"} if name == "lib/libreality.a" else {})}
                    for name, value in sorted(contents.items())
                ]
                manifest = {
                    "schema_version": 1, "project": "vpn-core", "version": "0.1.0",
                    "release_tag": "v0.1.0", "platform": "linux-x86_64", "target": TARGET,
                    "minimum_os": None, "toolchain": {
                        "rustc": "rustc 1.89", "cargo": "cargo 1.89", "build_host": "Linux"
                    },
                    "static_link": {"source": "rustc --print=native-static-libs",
                                    "arguments": ["-ldl", "-lpthread"]},
                    "files": records,
                }
                manifest.update(manifest_overrides or {})
                contents["manifest.json"] = (json.dumps(manifest) + "\n").encode()
                with zipfile.ZipFile(archive, "w") as out:
                    for name, value in contents.items():
                        out.writestr(f"vpn-core-sdk/{name}", value)
                checksum.write_text(
                    f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
                    encoding="ascii",
                )

            def check():
                return subprocess.run([sys.executable, str(CHECKER), "linux-x86_64", str(archive)],
                                      capture_output=True, text=True)

            create(FILES)
            result = check()
            self.assertEqual(result.returncode, 0, result.stderr)
            checksum.write_text("wrong\n", encoding="ascii")
            self.assertNotEqual(check().returncode, 0)
            create([name for name in FILES if name != "lib/libreality.so"])
            result = check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("libreality.so", result.stderr)

    def test_manifest_detects_tampering_even_with_updated_archive_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "sdk.zip"
            files = {name: b"fixture" for name in FILES}
            manifest_files = [
                {"path": name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                 **({"kind": "shared"} if name == "lib/libreality.so" else
                    {"kind": "static"} if name == "lib/libreality.a" else {})}
                for name, data in sorted(files.items())
            ]
            manifest = {"schema_version": 1, "project": "vpn-core", "version": "0.1.0",
                        "release_tag": "v0.1.0",
                        "platform": "linux-x86_64", "target": TARGET,
                        "toolchain": {"rustc": "rustc 1.89", "cargo": "cargo 1.89", "build_host": "Linux"},
                        "static_link": {"source": "rustc --print=native-static-libs", "arguments": ["-ldl"]},
                        "files": manifest_files}
            files["manifest.json"] = json.dumps(manifest).encode()
            files["README.md"] = b"changed"
            with zipfile.ZipFile(archive, "w") as out:
                for name, data in files.items():
                    out.writestr(f"vpn-core-sdk/{name}", data)
            archive.with_suffix(".zip.sha256").write_text(
                f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n", encoding="ascii"
            )
            result = subprocess.run([sys.executable, str(CHECKER), "linux-x86_64", str(archive)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest SHA-256 mismatch", result.stderr)

    def test_rejects_unlisted_files_and_wrong_target(self):
        for overrides, extra in (({}, {"unexpected.bin": "extra"}),
                                 ({"target": "aarch64-linux-android"}, None),
                                 ({"static_link": {"source": "rustc", "arguments": "-ldl"}}, None)):
            with self.subTest(overrides=overrides, extra=extra), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "sdk.zip"
                with zipfile.ZipFile(archive, "w") as out:
                    contents = {name: b"fixture" for name in FILES}
                    if extra:
                        contents.update({name: value.encode() for name, value in extra.items()})
                    listed_contents = {name: data for name, data in contents.items()
                                       if not (extra and name in extra)}
                    records = [{"path": name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                **({"kind": "shared"} if name == "lib/libreality.so" else
                                   {"kind": "static"} if name == "lib/libreality.a" else {})}
                               for name, data in sorted(listed_contents.items())]
                    manifest = {"schema_version": 1, "project": "vpn-core", "version": "0.1.0",
                                "release_tag": "v0.1.0",
                                "platform": "linux-x86_64", "target": TARGET,
                                "toolchain": {"rustc": "rustc 1.89", "cargo": "cargo 1.89", "build_host": "Linux"},
                                "static_link": {"source": "rustc --print=native-static-libs", "arguments": ["-ldl"]},
                                "files": records, **overrides}
                    contents["manifest.json"] = json.dumps(manifest).encode()
                    for name, data in contents.items():
                        out.writestr(f"vpn-core-sdk/{name}", data)
                archive.with_suffix(".zip.sha256").write_text(
                    f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n", encoding="ascii"
                )
                result = subprocess.run([sys.executable, str(CHECKER), "linux-x86_64", str(archive)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
