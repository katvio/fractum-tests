# Fractum Tests - Documentation

This repo holds the Fractum test suites that exercise realistic file fixtures
(Bitwarden exports, hardware wallet seeds, break-glass credentials, etc. — see
`fixtures.py`). It mirrors the relevant `src/` code from the main
[fractum](https://github.com/katvio/fractum) repo so these tests can run here
with their own CI, including native (non-Docker) runs on macOS and Windows to
validate real cross-OS behavior. The base test suite (compatibility, fuzzing,
performance, security, UX modes, OS mocking) stays in the main `fractum` repo.

## Test files in this repo

| File | Covers |
|------|--------|
| `test_core_crypto.py` | `ShareManager`, `FileEncryptor`, `SecureMemory` unit tests |
| `test_functional.py` | End-to-end CLI flows, threshold combinations, archive creation |
| `test_error_messages.py` | Error message accuracy (ShareManager, CLI, edge cases) |
| `test_file_corruption.py` | Deterministic corruption detection on `.enc` files |
| `test_memory_security.py` | mlock, secure_clear, key leakage, temp file leakage |

All fixtures in `fixtures.py` are synthetic: invented credentials, a fictional
company ("Acme Corp"), RFC 2606 reserved domains, and the standard BIP-39
`abandon ...` test vector. No real secret is stored in this repository.

## Test Environment Setup

Before running tests, you need to set up the test environment:

### Bootstrap your environment:

Linux:
`chmod +x bootstrap-linux.sh && ./bootstrap-linux.sh && source .venv/bin/activate`

MacOS:
`chmod +x bootstrap-macos.sh && ./bootstrap-macos.sh && source .venv/bin/activate`

Windows:

* `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
* `.\bootstrap-windows.ps1`
* `.\.venv\Scripts\Activate.ps1`

### Running Tests

To run all tests:

```
python run_tests.py
```

To run a specific test:

```
python test_core_crypto.py
```
## Running tests with Docker

To run tests in Docker:

### Build the Docker image for testing

From the repository root:

```
docker build -t fractum-test -f tests/Dockerfile.test .
```
### Run all tests with docker
```
docker run --rm fractum-test
```

## CI

`.github/workflows/tests.yml` runs this suite on every push/PR to `main`:
one job builds and runs `tests/Dockerfile.test` on Linux, and a matrix job
runs `run_tests.py` natively on `macos-latest` and `windows-latest` (no
Docker) to validate real cross-OS behavior, not mocked behavior.

See the table above for what each test file covers; consult each file's
docstrings for method-level detail (the per-method breakdown previously
here had drifted out of sync with the code and was removed).

## Docker Test Notes

Some tests may behave differently in Docker environments:

- The `test_file_access_issues` test may fail due to differences in permission handling.
- Memory tests might report different values due to containerization.
- Performance tests should be interpreted relative to the Docker environment rather than absolute values.

## Test Best Practices

1. **Isolation**: All tests create temporary directories to avoid affecting user files.

2. **Cleanup**: Temporary data is deleted after each test, even in case of failure.

3. **Verbosity**: Verbose mode helps diagnose problems by displaying execution details.

4. **Independence**: Each test is designed to run independently of others.

5. **Reproducibility**: Tests use predefined seeds for random generation when necessary. 