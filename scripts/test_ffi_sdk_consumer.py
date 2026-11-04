# SPDX-License-Identifier: GPL-3.0-or-later
"""Build independent consumers using only an extracted C ABI SDK archive."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONSUMER = ROOT / "scripts" / "sdk-consumer"


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {subprocess.list2cmdline(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result.stdout.strip()


def cmake_arguments(platform: str, sdk: Path, linkage: str) -> list[str]:
    arguments = [
        "-DVPN_CORE_SDK_ROOT=" + str(sdk),
        "-DVPN_CORE_LINKAGE=" + linkage,
        "-DCMAKE_PREFIX_PATH=" + str(sdk / "cmake"),
    ]
    if platform == "android-arm64-v8a":
        ndk = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
        if not ndk:
            raise RuntimeError("Android NDK environment variable is missing")
        toolchain = Path(ndk) / "build" / "cmake" / "android.toolchain.cmake"
        if not toolchain.is_file():
            raise RuntimeError(f"Android NDK CMake toolchain not found: {toolchain}")
        arguments.extend((
            "-DCMAKE_TOOLCHAIN_FILE=" + str(toolchain),
            "-DANDROID_ABI=arm64-v8a",
            "-DANDROID_PLATFORM=android-24",
        ))
    elif platform == "ios-arm64":
        arguments.extend((
            "-G",
            "Xcode",
            "-DCMAKE_SYSTEM_NAME=iOS",
            "-DCMAKE_OSX_SYSROOT=iphoneos",
            "-DCMAKE_OSX_ARCHITECTURES=arm64",
            "-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0",
        ))
    return arguments


def executable_path(build: Path, target: str) -> Path:
    filename = target + (".exe" if os.name == "nt" else "")
    for configuration in ("Release", "RelWithDebInfo", "Debug", None):
        directory = build if configuration is None else build / configuration
        candidate = directory / filename
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"CMake did not produce {filename} under {build}")


def runtime_environment(sdk: Path) -> dict[str, str]:
    env = os.environ.copy()
    key = "PATH" if os.name == "nt" else ("DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH")
    env[key] = str(sdk / "lib") + os.pathsep + env.get(key, "")
    return env


def verify_pkg_config(sdk: Path, consumer_source: Path, build_dir: Path) -> None:
    if sys.platform == "darwin":
        package = shutil.which("pkg-config") or shutil.which("pkgconf")
    else:
        package = shutil.which("pkg-config") or shutil.which("pkgconf")
    if not package:
        raise RuntimeError("pkg-config (or pkgconf) is required for the Unix SDK consumer check")
    build_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PKG_CONFIG_PATH"] = str(sdk / "lib" / "pkgconfig")
    env.pop("PKG_CONFIG_LIBDIR", None)
    run([package, "--exists", "vpn-core"], env=env)
    flags = run([package, "--static", "--cflags", "--libs", "vpn-core"], env=env)
    command = [shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")]
    if command[0] is None:
        raise RuntimeError("a C compiler is required for the pkg-config consumer check")
    command.extend([str(consumer_source), *shlex.split(flags), "-o", str(build_dir / "pkg-config-consumer")])
    run(command, env=env)
    run([str(build_dir / "pkg-config-consumer")], env=runtime_environment(sdk))


def verify_archive(platform: str, archive: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="vpn core sdk consumer ") as temporary:
        root = Path(temporary)
        extracted = root / "first extraction"
        extracted.mkdir()
        with zipfile.ZipFile(archive) as package:
            package.extractall(extracted)
        initial_sdk = extracted / "vpn-core-sdk"
        if not initial_sdk.is_dir():
            raise RuntimeError("archive does not contain vpn-core-sdk/")

        # Force the imported targets and pkg-config metadata to survive moving the SDK.
        sdk = root / "relocated SDK with spaces"
        shutil.move(str(initial_sdk), sdk)
        linkages = ["static"]
        if platform != "ios-arm64":
            linkages.insert(0, "shared")

        for linkage in linkages:
            build = root / f"CMake build {linkage}"
            run([
                "cmake", "-S", str(CONSUMER), "-B", str(build),
                *cmake_arguments(platform, sdk, linkage),
            ])
            run(["cmake", "--build", str(build), "--config", "Release"])
            if platform not in {"android-arm64-v8a", "ios-arm64"}:
                run([str(executable_path(build, "vpn-core-sdk-consumer"))], env=runtime_environment(sdk))
                run([str(executable_path(build, "vpn-core-sdk-consumer-cpp"))], env=runtime_environment(sdk))

        if platform in {"linux-x86_64", "macos-arm64"}:
            verify_pkg_config(sdk, sdk / "examples" / "minimal.c", root / "pkg config build")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    verify_archive(args.platform, args.archive.resolve())


if __name__ == "__main__":
    main()
