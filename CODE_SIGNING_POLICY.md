# Code signing policy

This project signs and distributes release artifacts. This document describes **what is
signed, how it is built, and who is allowed to approve a signing request**.

## Windows — SignPath Foundation

Free code signing provided by [SignPath.io](https://signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

- Signing is performed by SignPath.io. The private key is generated and stored on the
  Foundation's Hardware Security Module (HSM). **This project never stores, and never has
  access to, the private key.**
- Only artifacts built by this repository's public CI are submitted for signing. Builds
  produced on a developer machine are not signed.

### What will be signed

Windows executables published on
[GitHub Releases](https://github.com/kooofy/IPScanner/releases):

| Artifact | Description | Distributed as |
|---|---|---|
| `IPScanner.exe` | desktop GUI (PyInstaller onedir bundle) | `IPScanner_<version>-win64.zip` |
| `IPScanner_cli.exe` | headless CLI (single file) | `IPScanner_cli_<version>.exe` |

### Build and signing process

1. A `v*` tag is pushed to this repository.
2. GitHub Actions runs [`.github/workflows/release.yml`](.github/workflows/release.yml),
   which verifies the tag matches `version.py`, runs the test suite, builds both
   artifacts from the tagged source, and packages them.
3. The CI-built executables are submitted to SignPath for signing.
4. Signing happens **before** the artifacts are archived, so the signature covers the
   executables themselves rather than the surrounding archive.
5. The signed artifacts, together with `SHA256SUMS.txt`, are attached to the GitHub
   Release.

The build recipes ([`IPScanner.spec`](IPScanner.spec), [`IPScanner_cli.spec`](IPScanner_cli.spec))
and the release workflow are committed, so the release build is reproducible from the
tagged source.

### Team roles (single-maintainer project)

- **Authors** — commit access, may modify the repository without additional reviews:
  - <https://github.com/kooofy>

- **Reviewers** — review required for changes proposed by non-committers, e.g. pull
  requests:
  - <https://github.com/kooofy>
  - Policy: all external pull requests are reviewed by the maintainer before merge.

- **Approvers** — approve each signing request:
  - <https://github.com/kooofy>
  - Policy: every signing request requires explicit approval by the maintainer.

## Other platforms

This project does not currently distribute macOS or Linux builds, so no signing is
performed for those platforms. If that changes, this document will be updated before
such artifacts are published.

## Official distribution locations

Only the following location is official:

- <https://github.com/kooofy/IPScanner/releases>

Artifacts obtained from anywhere else are **not** covered by this policy and should not
be trusted.

## Verification

Every release ships a `SHA256SUMS.txt`. Verify a downloaded artifact against it:

```sh
sha256sum -c SHA256SUMS.txt
```

On Windows (PowerShell):

```powershell
Get-FileHash .\IPScanner_<version>-win64.zip -Algorithm SHA256
```

The computed hash must match the corresponding line in `SHA256SUMS.txt`.

## Privacy policy

IPScanner does not send telemetry and does not contact any server operated by this
project. It performs network probes (ICMP / ARP / TCP / UDP and WMI queries) against the
address range the user explicitly configures, and stores its results locally. No data
leaves the user's machine unless the user exports it.
