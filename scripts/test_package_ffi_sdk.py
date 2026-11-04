# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression tests for SDK package metadata parsing."""

import tempfile
import unittest
from pathlib import Path

from package_ffi_sdk import manifest_file_record, parse_native_static_libs


class NativeStaticLinkArgs(unittest.TestCase):
    def test_parses_arguments_and_framework_pairs(self):
        output = (
            "warning: build script warning\n"
            "note: link against native libraries\n"
            "note: native-static-libs: -lgcc_s -lutil -framework Security "
            "-framework SystemConfiguration\n"
        )
        self.assertEqual(
            parse_native_static_libs(output),
            ["-lgcc_s", "-lutil", "-framework", "Security", "-framework", "SystemConfiguration"],
        )

    def test_rejects_missing_or_ambiguous_diagnostic(self):
        for output in ("warning: no link data\n", "native-static-libs: -lm\nnative-static-libs: -ldl\n"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                parse_native_static_libs(output)

    def test_accepts_empty_dependency_list(self):
        self.assertEqual(parse_native_static_libs("note: native-static-libs:\n"), [])

    def test_strips_rustc_color_escape_from_final_argument(self):
        output = "note: native-static-libs: -landroid -lc\x1b[0m\n"
        self.assertEqual(parse_native_static_libs(output), ["-landroid", "-lc"])


class ManifestFileRecords(unittest.TestCase):
    def test_pkg_config_metadata_is_not_classified_as_a_library(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            library = stage / "lib" / "libreality.a"
            metadata = stage / "lib" / "pkgconfig" / "vpn-core.pc"
            library.parent.mkdir(parents=True)
            metadata.parent.mkdir()
            library.write_bytes(b"archive")
            metadata.write_text("Name: vpn-core\n", encoding="utf-8")

            self.assertEqual(manifest_file_record(stage, library)["kind"], "static")
            self.assertNotIn("kind", manifest_file_record(stage, metadata))


if __name__ == "__main__":
    unittest.main()
