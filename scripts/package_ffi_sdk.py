# SPDX-License-Identifier: GPL-3.0-or-later
"""Package a platform's C ABI library and integration files for a release."""

from __future__ import annotations

import argparse
import hashlib
import shutil
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--library", action="append", type=Path, required=True,
        help="shared/static library or import library to include; repeat as needed",
    )
    args = parser.parse_args()

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
            f"Platform: `{args.platform}`. This package contains the compiled "
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
