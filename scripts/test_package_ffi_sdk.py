# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression tests for SDK package metadata parsing."""

import unittest

from package_ffi_sdk import parse_native_static_libs


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


if __name__ == "__main__":
    unittest.main()
