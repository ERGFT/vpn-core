# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for relocatable CMake and pkg-config SDK metadata."""

import tempfile
import unittest
from pathlib import Path

from ffi_sdk_metadata import generate_metadata, validate_link_arguments


class MetadataGeneration(unittest.TestCase):
    def test_linux_metadata_is_relocatable_and_preserves_static_link_args(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "vpn-core-sdk"
            (stage / "lib").mkdir(parents=True)
            (stage / "lib/libreality.so").touch()
            (stage / "lib/libreality.a").touch()
            generate_metadata(stage, "linux-x86_64", "0.1.0", ["-ldl", "-lpthread"])

            config = (stage / "cmake/vpn-core/vpn-coreConfig.cmake").read_text()
            pc = (stage / "lib/pkgconfig/vpn-core.pc").read_text()
            self.assertIn("${CMAKE_CURRENT_LIST_DIR}/../..", config)
            self.assertIn("libreality.so", config)
            self.assertIn("libreality.a", config)
            self.assertIn("-ldl", config)
            self.assertIn("prefix=${pcfiledir}/../..", pc)
            self.assertIn("Libs.private: -ldl -lpthread", pc)
            self.assertNotIn(str(stage), config)
            self.assertNotIn(str(stage), pc)

    def test_windows_uses_dll_import_library_and_no_pkg_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "vpn-core-sdk"
            (stage / "lib").mkdir(parents=True)
            for name in ("reality.dll", "reality.dll.lib", "reality.lib"):
                (stage / "lib" / name).touch()
            generate_metadata(stage, "windows-x86_64", "68/merge", [
                "/DEFAULTLIB:ws2_32", "/defaultlib:msvcrt",
            ])

            config = (stage / "cmake/vpn-core/vpn-coreConfig.cmake").read_text()
            self.assertIn("IMPORTED_IMPLIB", config)
            self.assertIn("reality.dll.lib", config)
            self.assertIn("reality.lib", config)
            self.assertNotIn("pkgconfig", config)
            self.assertFalse((stage / "lib/pkgconfig/vpn-core.pc").exists())
            self.assertIn('PACKAGE_VERSION "0.0.0"',
                          (stage / "cmake/vpn-core/vpn-coreConfigVersion.cmake").read_text())

    def test_ios_static_only_package_defaults_to_static(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "vpn-core-sdk"
            (stage / "lib").mkdir(parents=True)
            (stage / "lib/libreality.a").touch()
            generate_metadata(stage, "ios-arm64", "0.1.0", ["-framework", "Security"])
            config = (stage / "cmake/vpn-core/vpn-coreConfig.cmake").read_text()
            self.assertIn("INTERFACE_LINK_LIBRARIES", config)
            self.assertIn("Security", config)
            self.assertIn("vpn-core::static", config)
            self.assertFalse((stage / "lib/pkgconfig/vpn-core.pc").exists())

    def test_rejects_absolute_and_malformed_arguments(self):
        for arguments in (["-L/usr/local/lib"], ["/Users/runner/sysroot/lib.a"],
                          ["C:\\runner\\sysroot\\dnsapi.lib"], ["../dnsapi.lib"],
                          ["-framework"], ["-lfoo;message(FATAL_ERROR x)"]):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                validate_link_arguments(arguments)

    def test_preserves_plain_windows_system_library_names(self):
        self.assertEqual(validate_link_arguments(["dnsapi.lib", "bcrypt.lib"]),
                         ["dnsapi.lib", "bcrypt.lib"])
        self.assertEqual(validate_link_arguments(["/DEFAULTLIB:ws2_32", "/defaultlib:msvcrt"]),
                         ["/DEFAULTLIB:ws2_32", "/defaultlib:msvcrt"])


if __name__ == "__main__":
    unittest.main()
