#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the three changes that go into Fractum 1.4.2.

Each one fails on the code as it stood before its fix:

  - bytearray port: secure_clear() used to accept bytes, copy them into a
    bytearray, wipe the copy and return. The caller's secret was untouched, so
    the call read as correct and did nothing. combine_shares() and
    load_shares() returned bytes, so the AES key and the shares could not be
    wiped at all.
  - core dumps: RLIMIT_CORE was unlimited for the whole time the process held
    the AES key. A crash at that moment writes the key to a file that outlives
    the process. mlock does not help: it stops swapping, not dumping.
  - shares directory: a second run wrote into the same shares/, mixing two sets
    in one place with nothing in the file names to tell them apart. The next
    set now goes to shares/set-2/, set-3/..., still under shares/.

The core dump limit is a POSIX mechanism. On Windows the `resource` module does
not exist, so the limit tests are skipped there and a separate test checks that
the CLI says so instead of staying silent.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from src.cli.commands import decrypt, encrypt
from src.cli.core import cli
from src.crypto.memory import SecureMemory, disable_core_dumps
from src.shares.manager import ShareManager

REPO_ROOT = str(Path(__file__).resolve().parent.parent)
HAS_RESOURCE = sys.platform != "win32"


class TestSecureClearRefusesImmutable(unittest.TestCase):
    """Wiping an immutable object is a no-op, and a silent one is worse than an
    exception."""

    def test_bytes_are_refused(self):
        with self.assertRaises(TypeError) as ctx:
            SecureMemory.secure_clear(b"CANARY-MATERIAL-0123456789ABCDEF")
        self.assertIn("bytes", str(ctx.exception))

    def test_readonly_memoryview_is_refused(self):
        with self.assertRaises(TypeError):
            SecureMemory.secure_clear(memoryview(b"CANARY-0123456789ABCDEF01234567"))

    def test_bytearray_is_really_wiped(self):
        buffer = bytearray(b"CANARY-MATERIAL-0123456789ABCDEF")
        SecureMemory.secure_clear(buffer)
        self.assertEqual(bytes(buffer), bytes(len(buffer)))

    def test_writable_memoryview_is_wiped(self):
        source = bytearray(b"CANARY-MATERIAL-0123456789ABCDEF")
        SecureMemory.secure_clear(memoryview(source))
        self.assertEqual(bytes(source), bytes(len(source)))

    def test_immutable_list_element_is_dropped_not_raised(self):
        """A bytes object inside a list must not abort the wipe of the elements
        after it. Raising there would leave every mutable element further down
        the list untouched."""
        mutable = bytearray(b"SECRET-0123456789ABCDEF012345678")
        elements = [b"immutable", mutable, bytearray(b"more")]
        SecureMemory.secure_clear(elements)
        self.assertEqual(
            bytes(mutable),
            bytes(len(mutable)),
            "the mutable element after the immutable one was left untouched",
        )


class TestKeyMaterialIsWipeable(unittest.TestCase):
    """The reconstructed key and the loaded shares are the buffers the CLI wipes,
    so they have to be mutable."""

    def test_combine_returns_a_wipeable_buffer(self):
        secret = os.urandom(32)
        manager = ShareManager(3, 5)
        shares = manager.generate_shares(secret, "wipe")
        key = manager.combine_shares(shares[:3])

        self.assertIsInstance(
            key, bytearray, "the AES key came back as an unwipeable bytes object"
        )
        self.assertEqual(bytes(key), secret)

        SecureMemory.secure_clear(key)
        self.assertEqual(bytes(key), bytes(32))

    def test_loaded_shares_are_wipeable(self):
        directory = tempfile.mkdtemp()
        try:
            path = os.path.join(directory, "share_1.txt")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "share_index": 1,
                        "share_key": base64.b64encode(os.urandom(32)).decode(),
                        "threshold": 2,
                        "total_shares": 3,
                    },
                    f,
                )
            shares, _ = ShareManager.load_shares([path])
            for _, data in shares:
                self.assertIsInstance(data, bytearray, "a loaded share cannot be wiped")
                SecureMemory.secure_clear(data)
                self.assertEqual(bytes(data), bytes(len(data)))
        finally:
            shutil.rmtree(directory, ignore_errors=True)


def _run_python(code: str) -> subprocess.CompletedProcess:
    """The core dump limit is process-wide. Each check runs in its own
    interpreter so that lowering it here does not leak into the other suites."""
    return subprocess.run(
        [sys.executable, "-c", f"import sys; sys.path.insert(0, {REPO_ROOT!r});\n" + code],
        capture_output=True,
        text=True,
    )


@unittest.skipUnless(HAS_RESOURCE, "no RLIMIT_CORE on Windows")
class TestCoreDumpsAreDisabled(unittest.TestCase):
    """A crash while the key is in memory used to write it to disk."""

    def test_limit_is_lowered_to_zero(self):
        r = _run_python(
            "import resource\n"
            "soft, hard = resource.getrlimit(resource.RLIMIT_CORE)\n"
            "resource.setrlimit(resource.RLIMIT_CORE, (hard, hard))\n"
            "before = resource.getrlimit(resource.RLIMIT_CORE)[0]\n"
            "from src.crypto.memory import disable_core_dumps\n"
            "ok = disable_core_dumps()\n"
            "after = resource.getrlimit(resource.RLIMIT_CORE)[0]\n"
            "print(before, after, ok)\n"
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        before, after, ok = r.stdout.split()
        if before == "0":
            # Docker sets a hard limit of 0 by default. Nothing can be lowered,
            # so this run proves nothing either way (docker run --ulimit core=-1).
            self.skipTest("the hard core limit is already 0 in this environment")
        self.assertEqual(after, "0", "core dumps are still allowed")
        self.assertEqual(ok, "True", "the function did not report success")

    def test_the_cli_calls_it_before_any_command(self):
        """--version included: no path may skip it."""
        r = _run_python(
            "import resource\n"
            "from click.testing import CliRunner\n"
            "from src.cli.core import cli\n"
            "CliRunner().invoke(cli, ['--version'])\n"
            "print(resource.getrlimit(resource.RLIMIT_CORE)[0])\n"
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(), "0", "the CLI ran a command with core dumps enabled"
        )

    def test_the_cli_prints_no_warning_when_it_succeeds(self):
        r = subprocess.run(
            [sys.executable, "-c",
             f"import sys; sys.path.insert(0, {REPO_ROOT!r});"
             "from src.cli.core import cli; cli(['--version'])"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("core dumps could not be disabled", r.stdout + r.stderr)


class TestCoreDumpFallback(unittest.TestCase):
    """Where the limit cannot be set, the CLI runs anyway and says so."""

    def test_returns_a_boolean(self):
        """Callers warn on False rather than aborting, so the type matters.

        In a subprocess like the others: the call lowers the hard limit, which
        cannot be raised again, and every later test would inherit it."""
        r = _run_python(
            "from src.crypto.memory import disable_core_dumps\n"
            "print(type(disable_core_dumps()).__name__)\n"
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "bool")

    @unittest.skipIf(HAS_RESOURCE, "only Windows lacks RLIMIT_CORE")
    def test_windows_reports_failure_and_the_cli_warns(self):
        self.assertFalse(disable_core_dumps())
        result = CliRunner().invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("core dumps could not be disabled", result.output)


class TestSharesDirectoryIsNeverReused(unittest.TestCase):
    """A second run used to write into the same shares/, mixing two sets.

    Every set must stay under shares/: with Docker, shares/ is the mounted
    volume, and anything written beside it is lost with the container.
    """

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.mkdtemp()
        self.previous_cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.previous_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _encrypt(self, name: str):
        Path(name).write_text("content of " + name, encoding="utf-8")
        result = self.runner.invoke(encrypt, [name, "-t", "2", "-n", "3", "-l", name])
        self.assertEqual(result.exit_code, 0, result.output)
        return result

    def _zips(self, directory: str) -> list:
        return sorted(p.name for p in Path(directory).glob("*.zip"))

    def test_each_run_gets_its_own_directory_under_shares(self):
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        self._encrypt("three.txt")
        for expected in ("shares", "shares/set-2", "shares/set-3"):
            with self.subTest(directory=expected):
                self.assertEqual(len(self._zips(expected)), 3, expected)

    def test_nothing_is_written_beside_shares(self):
        """The Docker case: only shares/ is mounted, so a sibling such as
        shares-2/ would never reach the host."""
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        siblings = sorted(p.name for p in Path(".").iterdir()
                          if p.is_dir() and p.name != "shares")
        self.assertEqual(siblings, [])

    def test_an_empty_shares_directory_is_used_as_is(self):
        """A fresh Docker mount is an existing, empty shares/."""
        Path("shares").mkdir()
        self._encrypt("one.txt")
        self.assertEqual(len(self._zips("shares")), 3)
        self.assertFalse(Path("shares/set-2").exists())

    def test_the_user_is_told_where_the_second_set_went(self):
        self._encrypt("one.txt")
        result = self._encrypt("two.txt")
        self.assertIn("set-2", result.output)

    def test_no_set_is_mixed_into_another(self):
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        self.assertEqual(len(self._zips("shares")), 3)
        self.assertEqual(len(self._zips("shares/set-2")), 3)

    def test_an_existing_numbered_directory_is_not_overwritten(self):
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        before = sorted(p.name for p in Path("shares/set-2").iterdir())
        self._encrypt("three.txt")
        self.assertEqual(sorted(p.name for p in Path("shares/set-2").iterdir()), before)
        self.assertTrue(Path("shares/set-3").is_dir())

    def test_each_set_decrypts_from_its_own_directory(self):
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        os.remove("one.txt")
        os.remove("two.txt")
        for name, directory in (("one.txt", "shares"), ("two.txt", "shares/set-2")):
            with self.subTest(directory=directory):
                result = self.runner.invoke(
                    decrypt, [name + ".enc", "--shares-dir", directory]
                )
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertEqual(
                    Path(name).read_text(encoding="utf-8"), "content of " + name
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
