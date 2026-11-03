# Preparing a release

[Русский](RELEASING.md) | **English**

Publish a stable tag only after checking the builds and artifacts.

## Preflight build without publishing

1. Merge the planned PRs and wait for green CI on `main`.
2. In GitHub, open **Actions → Release → Run workflow**. Select the `main`
   branch and enter the exact version, for example `v0.1.0`.
3. Confirm that the workflow built the Linux/Windows CLI and SDKs for Linux,
   Windows, macOS, Android, and iOS. A manual run creates no release and does
   not write to git.
4. Download every job artifact. Verify SHA-256, inspect each SDK archive's
   header, libraries, examples, docs, and license, and inspect the SBOM.
   SDK jobs also compile and run minimal C consumers where supported by the
   runner, and check mobile headers/libraries.
5. Record the source `main` commit SHA used by the run. Do not change `main`
   before publishing. If it changes, run preflight again.

## Publish

Create and push tag `vX.Y.Z` at the exact commit SHA checked by preflight. The
tag workflow rebuilds and attaches the files, checksums, licenses, CycloneDX
SBOM, and GitHub build provenance to the release. Compare the published asset
names and SHA-256 with the preflight artifacts. The attestation verification
command is documented in `.github/workflows/release.yml`.

Android/iOS artifacts are cross-compiled and linked; this does not confirm
execution on physical devices. REALITY has not received an external
cryptographic audit; see the [internal report](reviews/2026-11-04-reality-internal-review.en.md).
