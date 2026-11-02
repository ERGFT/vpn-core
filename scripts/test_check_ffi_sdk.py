# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression checks for SDK archive validation."""

import hashlib
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
         "lib/libreality.so", "lib/libreality.a", *(f"docs/{x}" for x in DOCS))


class ArchiveCheck(unittest.TestCase):
    def test_valid_corrupt_and_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "sdk.zip"
            checksum = archive.with_suffix(".zip.sha256")

            def create(files):
                with zipfile.ZipFile(archive, "w") as out:
                    for name in files:
                        out.writestr(f"vpn-core-sdk/{name}", "fixture")
                checksum.write_text(
                    f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
                    encoding="ascii",
                )

            def check():
                return subprocess.run([sys.executable, str(CHECKER), "linux-x86_64", str(archive)],
                                      capture_output=True, text=True)

            create(FILES)
            self.assertEqual(check().returncode, 0)
            checksum.write_text("wrong\n", encoding="ascii")
            self.assertNotEqual(check().returncode, 0)
            create([name for name in FILES if name != "lib/libreality.so"])
            result = check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("libreality.so", result.stderr)


if __name__ == "__main__":
    unittest.main()
