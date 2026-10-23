# Fractum test suite

[![Tests](https://github.com/katvio/fractum-tests/actions/workflows/tests.yml/badge.svg)](https://github.com/katvio/fractum-tests/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Cross-platform test suite for [Fractum](https://github.com/katvio/fractum), the
offline CLI that splits a sensitive file into encrypted Shamir shares.

This repository exists for one reason: to run Fractum's tests on **real operating
systems**, not only inside a Linux container. Every suite here runs natively on
macOS and Windows in CI, so OS-specific behaviour (memory locking, file
permissions, path handling, console encoding) is checked against the actual
platform instead of a mock.

The rest of the test base (compatibility, fuzzing, performance, security
scanning, UX modes, OS mocking) lives in the main
[fractum](https://github.com/katvio/fractum) repo and runs there.

## Where things live

Fractum is spread over three repositories. This one holds tests only, and no
Fractum code you should ever edit here.

| | What it is | Go there for |
|---|---|---|
| **[katvio/fractum](https://github.com/katvio/fractum)** | The source of truth: the CLI, the crypto, the release pipeline, and most of the test base | Bug reports, feature requests, anything that changes how Fractum behaves |
| **[katvio/fractum-tests](https://github.com/katvio/fractum-tests)** (this repo) | Cross-platform test suites run natively on Linux, macOS and Windows | Test-only changes, new fixtures, CI matrix work |
| **[fractum.katvio.com](https://fractum.katvio.com/)** | The documentation site: install guides, usage, threat model, contributing guide. Built from [katvio/fractum-frontend](https://github.com/katvio/fractum-frontend) | Learning what Fractum does and how to use it |

Start with the [documentation site](https://fractum.katvio.com/) if you want to
know what Fractum does and how to use it. This README only covers how its tests
are run.

## What is covered

**221 test methods** in 12 suites, run against Fractum 1.4.2 on Linux, macOS and
Windows on every push and pull request:

| Suite | Tests | What it checks |
|---|---:|---|
| [`tests/test_error_messages.py`](tests/test_error_messages.py) | 32 | Accuracy of every user-facing error: `ShareManager` failures, CLI argument errors, corrupt or missing metadata, edge cases |
| [`tests/test_file_corruption.py`](tests/test_file_corruption.py) | 25 | Deterministic corruption of `.enc` files (header, ciphertext, GCM tag, metadata) is always detected, never silently decrypted |
| [`tests/test_memory_security.py`](tests/test_memory_security.py) | 21 | `mlock`, buffer zeroing on normal exit and on exception, key material leakage, temporary file leakage |
| [`tests/test_core_crypto.py`](tests/test_core_crypto.py) | 18 | `ShareManager`, `FileEncryptor` and `SecureMemory` unit behaviour |
| [`tests/test_functional.py`](tests/test_functional.py) | 9 | End-to-end CLI flows, K-of-N threshold combinations, self-contained archive creation |
| [`tests/test_minimal_metadata.py`](tests/test_minimal_metadata.py) | 25 | What the default share format writes and omits, the label echoed then dropped (katvio/fractum#32), and thresholds above five, which the default format could not recover before 1.4.2 |
| [`tests/test_properties.py`](tests/test_properties.py) | 18 | Property-based checks with hypothesis: any threshold-sized subset reconstructs, fewer is refused, AES-GCM round trip and tamper detection over arbitrary inputs |
| [`tests/test_package_integrity.py`](tests/test_package_integrity.py) | 17 | The offline wheels match `CHECKSUMS.sha256`, and its detached GPG signature verifies against the shipped key, and fails once a digest is changed |
| [`tests/test_release_1_4_2.py`](tests/test_release_1_4_2.py) | 19 | The 1.4.2 changes: key material held in wipeable `bytearray`, `secure_clear` refusing `bytes`, core dumps disabled before any command, one directory per share set under `shares/` |
| [`tests/test_disk_hygiene.py`](tests/test_disk_hygiene.py) | 8 | What a run leaves on disk: outputs created 0600, no extracted share material after a failed decrypt, no plaintext share file after a failed archiving (FSB-2026-02) |
| [`tests/test_share_metadata.py`](tests/test_share_metadata.py) | 15 | `ShareMetadata.validate()` guards and the fallbacks used when a share omits a field |
| [`tests/test_interactive_mode.py`](tests/test_interactive_mode.py) | 14 | The guided mode (`fractum -i`): encrypt, reuse of existing shares, decrypt by directory or by manual entry |

Tests run against realistic file fixtures rather than random bytes: password
manager exports, BIP-39 seed phrase files, PEM private keys, break-glass
credential files, financial and payroll exports. See
[Test data](#test-data) below.

## Repository layout

```
src/          mirror of the Fractum source under test (see note below)
tests/        the suites, fixtures, and the runner
packages/     vendored wheels + SHA-256 checksums for offline install
bootstrap-*   one-shot environment setup for Linux / macOS / Windows
```

> **`src/` is a mirror, not the source of truth.** It is copied from
> [katvio/fractum](https://github.com/katvio/fractum) so the suites can be
> installed and executed standalone with their own CI. Never patch a bug here:
> fix it upstream, then re-sync. Pull requests that change `src/` without a
> matching upstream change will be closed.

## Running the tests

### Docker (recommended)

```bash
git clone https://github.com/katvio/fractum-tests.git
cd fractum-tests
docker build -t fractum-test -f tests/Dockerfile.test .
docker run --rm fractum-test
```

### Natively

Bootstrap pins Python 3.12.11 through pyenv and installs the vendored wheels
after verifying their checksums.

**Linux**

```bash
chmod +x bootstrap-linux.sh && ./bootstrap-linux.sh
source .venv/bin/activate
cd tests && python run_tests.py
```

**macOS**

```bash
chmod +x bootstrap-macos.sh && ./bootstrap-macos.sh
source .venv/bin/activate
cd tests && python run_tests.py
```

**Windows (PowerShell)**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\bootstrap-windows.ps1
.\.venv\Scripts\Activate.ps1
cd tests ; python run_tests.py
```

Run a single suite with `python test_core_crypto.py`.

## Continuous integration

[`.github/workflows/tests.yml`](.github/workflows/tests.yml) runs on every push
to `main` and every pull request:

- **Linux**: builds `tests/Dockerfile.test` and runs the suite as a non-root user
  inside the container.
- **macOS and Windows**: installs Fractum and runs `run_tests.py` natively, with
  no Docker in the path, so platform behaviour is exercised for real.

Both checkout steps run with `persist-credentials: false`, actions are pinned by
commit SHA, and the workflow token is limited to `contents: read`.

## Test data

Every fixture in [`tests/fixtures.py`](tests/fixtures.py) is **synthetic**. The
files are shaped like real secrets on purpose, because Fractum is meant to
protect real secrets and the suites should exercise realistic sizes, encodings
and structures. None of it is live: the credentials are invented, the domains
are RFC 2606 reserved (`example.com`, `acme.example`), the PEM block is not a
usable key, and the BIP-39 mnemonic is the standard `abandon ...` test vector
that derives a well-known public wallet.

Please keep it that way. Any pull request adding a fixture must use reserved
domains and clearly fictional values.

## Known platform notes

- `test_file_access_issues` can behave differently under Docker because of
  permission handling inside containers.
- Memory measurements differ under containerisation, so memory tests assert
  behaviour, not absolute values.
- `actions/setup-python` publishes 3.12.11 for Linux only; macOS and Windows
  runners use 3.12.10, and `conftest.py` relaxes the runtime version guard
  accordingly.

## Contributing

Issues and pull requests are welcome. Test-only changes belong here; anything
touching Fractum's behaviour belongs in the
[main repo](https://github.com/katvio/fractum).

Full guide: **[fractum.katvio.com/contributing](https://fractum.katvio.com/contributing/)**

## License

Apache License 2.0, see [LICENSE](LICENSE). The Fractum and Katvio names and
logos are trademarks of S.A.S.U. Katvio and are not covered by that grant; the
trademark policy is included at the end of the license file.

---

📚 **[Documentation](https://fractum.katvio.com/)** ·
🔧 **[Main repository](https://github.com/katvio/fractum)** ·
📝 **[Documentation sources](https://github.com/katvio/fractum-frontend)**
