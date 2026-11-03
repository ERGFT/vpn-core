#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the C ABI compatibility checker."""

import unittest

from check_ffi_abi import compare, public_api, rust_exports


HEADER = """
/* rc_ignored(void) */
typedef struct RcCore RcCore;
enum rc_error_code { RC_ERROR_NONE = 0, RC_ERROR_IO = 2, RC_ERROR_INTERNAL = 255 };
const char *rc_version(void);
int rc_start(const char *config, char **error);
"""
RUST = '''
#[no_mangle]
pub extern "C" fn rc_version() {}
#[no_mangle]
pub unsafe extern "C" fn rc_start() {}
'''


class AbiCheckerTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = public_api(HEADER)

    def test_extracts_functions_and_stable_enum_values(self):
        self.assertEqual(sorted(self.snapshot["functions"]), ["rc_start", "rc_version"])
        self.assertEqual(self.snapshot["enums"]["rc_error_code"]["RC_ERROR_IO"], 2)
        self.assertEqual(rust_exports(RUST), {"rc_start", "rc_version"})

    def test_accepts_unchanged_snapshot(self):
        self.assertEqual(compare(self.snapshot, self.snapshot), [])

    def test_flags_removed_or_added_functions(self):
        changed = {**self.snapshot, "functions": {"rc_version": self.snapshot["functions"]["rc_version"]}}
        errors = compare(changed, self.snapshot)
        self.assertTrue(any("removed/renamed" in error for error in errors))
        changed = {**self.snapshot, "functions": {**self.snapshot["functions"], "rc_new": "void rc_new(void);"}}
        errors = compare(changed, self.snapshot)
        self.assertTrue(any("new C functions" in error for error in errors))

    def test_flags_renumbered_enum(self):
        changed = {**self.snapshot, "enums": {"rc_error_code": {"RC_ERROR_NONE": 0, "RC_ERROR_IO": 3, "RC_ERROR_INTERNAL": 255}}}
        self.assertTrue(any("enum names/values" in error for error in compare(changed, self.snapshot)))

    def test_flags_changed_function_signature(self):
        changed = {**self.snapshot, "functions": {**self.snapshot["functions"], "rc_start": "int rc_start(int incompatible);"}}
        self.assertTrue(any("changed C function signatures" in error for error in compare(changed, self.snapshot)))

    def test_flags_changed_callback_typedef(self):
        changed = {**self.snapshot, "typedefs": ["typedef void (*rc_callback)(int incompatible);"]}
        self.assertTrue(any("typedefs" in error for error in compare(changed, self.snapshot)))


if __name__ == "__main__":
    unittest.main()
