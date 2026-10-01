#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the default (minimal metadata) share format.

Since --full-metadata became opt-in, `fractum encrypt` writes only four fields
per share: share_index, share_key, threshold and hash. Label, total_shares,
share_set_id, tool_integrity and python_version are omitted unless the flag is
passed. That default is the one every user gets, and it was covered by nothing:
the string "minimal" did not appear anywhere under tests/.

Two behaviours are pinned here that are not obviously intended, and both are
marked so they show up rather than being quietly frozen as correct:

  - the label is echoed at encrypt time and then dropped (katvio/fractum#32);
  - a minimal share set with a threshold above five can be neither decrypted nor
    reused via --existing-shares, because the absent total_shares field falls
    back to a fixed 5. This is still the case in 1.4.2; 2.0.0 falls back to the
    threshold instead. The tests carry @unittest.expectedFailure until then.
"""

import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from click.testing import CliRunner
from fixtures import BREAK_GLASS_CREDENTIALS

from src.cli.commands import decrypt, encrypt


class _CliInTempDir(unittest.TestCase):
    """`encrypt` writes shares/ relative to the working directory, so each test
    runs inside its own directory and restores the previous one afterwards."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        self.previous_cwd = Path.cwd()
        os.chdir(self.tmp_dir)

    def tearDown(self):
        os.chdir(self.previous_cwd)
        self.tmp.cleanup()

    # ── helpers ─────────────────────────────────────────────────────────────

    def _write_secret(self, name: str = "break_glass.txt") -> Path:
        path = self.tmp_dir / name
        path.write_bytes(BREAK_GLASS_CREDENTIALS)
        return path

    def _encrypt(self, source: Path, *extra_args: str, threshold=3, shares=5):
        return self.runner.invoke(
            encrypt,
            [
                str(source),
                "--threshold",
                str(threshold),
                "--shares",
                str(shares),
                *extra_args,
            ],
        )

    def _share_payloads(self) -> list:
        """Read back the share JSON out of every generated archive."""
        payloads = []
        for archive in sorted(Path("shares").glob("*.zip")):
            with zipfile.ZipFile(archive) as zipf:
                names = [
                    n
                    for n in zipf.namelist()
                    if n.startswith("share_") and n.endswith(".txt")
                ]
                self.assertTrue(names, f"No share file inside {archive.name}")
                payloads.append(json.loads(zipf.read(names[0]).decode("utf-8")))
        return payloads

    def _extract_shares_to(self, directory: str) -> Path:
        """Unpack the bare share JSON files into their own directory, which is
        what --existing-shares expects."""
        target = self.tmp_dir / directory
        target.mkdir(exist_ok=True)
        for archive in sorted(Path("shares").glob("*.zip")):
            with zipfile.ZipFile(archive) as zipf:
                for name in zipf.namelist():
                    if name.startswith("share_") and name.endswith(".txt"):
                        zipf.extract(name, target)
        return target


class TestDefaultShareFields(_CliInTempDir):
    """What the default mode does and does not write into a share."""

    def setUp(self):
        super().setUp()
        source = self._write_secret()
        result = self._encrypt(source, "--label", "break_glass")
        self.assertEqual(result.exit_code, 0, result.output)
        self.payloads = self._share_payloads()

    def test_five_shares_are_produced(self):
        self.assertEqual(len(self.payloads), 5)

    def test_every_share_carries_the_fields_needed_to_decrypt(self):
        """These four are the whole minimal format. Losing any of them makes the
        share unusable."""
        for payload in self.payloads:
            with self.subTest(index=payload.get("share_index")):
                for field in ("share_index", "share_key", "threshold", "hash"):
                    self.assertIn(field, payload)

    def test_label_is_absent_from_every_share(self):
        for payload in self.payloads:
            with self.subTest(index=payload["share_index"]):
                self.assertNotIn("label", payload)

    def test_total_shares_is_absent_from_every_share(self):
        for payload in self.payloads:
            with self.subTest(index=payload["share_index"]):
                self.assertNotIn("total_shares", payload)

    def test_share_set_id_is_absent_from_every_share(self):
        """In 1.4.2 the minimal format does not carry the set ID.

        Consequence: two runs in one directory produce share files that cannot
        be told apart, and decrypt then fails with "No compatible shares found".
        1.4.2 avoids the mix at the source instead, by writing each run into its
        own directory (shares/, shares/set-2/, ...). 2.0.0 writes the ID in minimal
        mode as well.
        """
        for payload in self.payloads:
            with self.subTest(index=payload["share_index"]):
                self.assertNotIn("share_set_id", payload)

    def test_tool_integrity_and_python_version_are_absent(self):
        """Both describe the machine that produced the shares."""
        for payload in self.payloads:
            with self.subTest(index=payload["share_index"]):
                self.assertNotIn("tool_integrity", payload)
                self.assertNotIn("python_version", payload)

    def test_share_indices_are_unique_and_contiguous(self):
        indices = sorted(p["share_index"] for p in self.payloads)
        self.assertEqual(indices, [1, 2, 3, 4, 5])

    def test_threshold_is_recorded_verbatim(self):
        for payload in self.payloads:
            with self.subTest(index=payload["share_index"]):
                self.assertEqual(payload["threshold"], 3)


class TestFullMetadataShareFields(_CliInTempDir):
    """--full-metadata is the opposite default and must write everything."""

    def setUp(self):
        super().setUp()
        source = self._write_secret()
        result = self._encrypt(source, "--label", "break_glass", "--full-metadata")
        self.assertEqual(result.exit_code, 0, result.output)
        self.payloads = self._share_payloads()

    def test_label_is_written(self):
        for payload in self.payloads:
            with self.subTest(index=payload["share_index"]):
                self.assertEqual(payload.get("label"), "break_glass")

    def test_total_shares_is_written(self):
        for payload in self.payloads:
            with self.subTest(index=payload["share_index"]):
                self.assertEqual(payload.get("total_shares"), 5)

    def test_share_set_id_is_written_and_identical_across_shares(self):
        set_ids = {payload.get("share_set_id") for payload in self.payloads}
        self.assertEqual(len(set_ids), 1, f"Shares disagree on the set ID: {set_ids}")
        self.assertIsNotNone(set_ids.pop())

    def test_tool_integrity_and_python_version_are_written(self):
        for payload in self.payloads:
            with self.subTest(index=payload["share_index"]):
                self.assertIn("tool_integrity", payload)
                self.assertIn("python_version", payload)


class TestLabelHandlingInDefaultMode(_CliInTempDir):
    """katvio/fractum#32: the label is asked for, echoed, and then thrown away."""

    def test_verbose_announces_a_label_that_no_share_will_carry(self):
        """Current behaviour, pinned so that a fix has to update this test.

        `encrypt -v -l break_glass` prints 'Using label: break_glass' before it
        knows whether the label will be persisted, and in the default mode it
        never is. At decrypt time the shares group under '_unlabeled'.
        """
        source = self._write_secret()
        result = self._encrypt(source, "--label", "break_glass", "--verbose")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Using label: break_glass", result.output)
        for payload in self._share_payloads():
            self.assertNotIn("label", payload)

    def test_archive_names_do_not_carry_the_label_either(self):
        """So the label survives nowhere: not in the JSON, not in the file name."""
        source = self._write_secret()
        result = self._encrypt(source, "--label", "break_glass")
        self.assertEqual(result.exit_code, 0, result.output)
        names = sorted(p.name for p in Path("shares").glob("*.zip"))
        self.assertEqual(
            names,
            ["share_1.zip", "share_2.zip", "share_3.zip", "share_4.zip", "share_5.zip"],
        )

    def test_default_label_is_the_input_filename_and_is_also_dropped(self):
        """Without -l the label defaults to the file stem, with the same fate."""
        source = self._write_secret("quarterly_report.txt")
        result = self._encrypt(source, "--verbose")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Using label: quarterly_report", result.output)
        for payload in self._share_payloads():
            self.assertNotIn("label", payload)


class TestMinimalModeRoundTrip(_CliInTempDir):
    """A share set with no label must still decrypt."""

    def _round_trip(self, *extra_args: str) -> str:
        source = self._write_secret("break_glass.txt")
        original = source.read_bytes()
        result = self._encrypt(source, *extra_args)
        self.assertEqual(result.exit_code, 0, result.output)
        # Free the output path: decrypt writes back to break_glass.txt.
        source.unlink()

        decrypted = self.runner.invoke(
            decrypt,
            [str(self.tmp_dir / "break_glass.txt.enc"), "--shares-dir", "shares"],
        )
        self.assertEqual(decrypted.exit_code, 0, decrypted.output)
        self.assertEqual((self.tmp_dir / "break_glass.txt").read_bytes(), original)
        return decrypted.output

    def test_default_mode_round_trip(self):
        self._round_trip()

    def test_full_metadata_round_trip(self):
        self._round_trip("--full-metadata")


class TestHighThresholdInDefaultMode(_CliInTempDir):
    """A default-mode share set is only recoverable up to a threshold of five.

    Shares written without --full-metadata carry no total_shares field. Both
    branches of `decrypt` fill that gap with the hardcoded default of five
    (src/cli/commands.py, `share_info.get("total_shares", 5)`), then build a
    ShareManager(threshold, 5). For any threshold above five the constructor
    raises, the exception is swallowed by the broad `except Exception` around the
    label loop, and the user is told the shares are incompatible.

    Encryption exits 0 either way, so nothing warns at backup time. The failure
    only appears at recovery, which is the one moment it must not.
    """

    def _encrypt_and_decrypt(self, threshold: int, shares: int, *extra_args: str):
        source = self._write_secret("vault.txt")
        self.original = source.read_bytes()
        encrypted = self._encrypt(
            source, *extra_args, threshold=threshold, shares=shares
        )
        self.assertEqual(encrypted.exit_code, 0, encrypted.output)
        # Encryption never complains, whatever the threshold.
        source.unlink()
        return self.runner.invoke(
            decrypt, [str(self.tmp_dir / "vault.txt.enc"), "--shares-dir", "shares"]
        )

    def test_five_of_nine_is_recoverable(self):
        """Five is the last threshold that survives, because it happens to equal
        the hardcoded fallback."""
        result = self._encrypt_and_decrypt(threshold=5, shares=9)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual((self.tmp_dir / "vault.txt").read_bytes(), self.original)

    @unittest.expectedFailure
    def test_six_of_nine_is_recoverable(self):
        """A 6-of-9 backup taken with the default settings must be readable.

        It is not, in 1.4.2: minimal shares do not carry total_shares, the reader
        falls back to 5, which is below the threshold, and decrypt answers "No
        compatible shares found". Any scheme above 5-of-N is unreadable by the
        tool that produced it. Fixed in 2.0.0, where the fallback lands on the
        threshold. Remove the marker in the commit that brings the fix here.
        """
        result = self._encrypt_and_decrypt(threshold=6, shares=9)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual((self.tmp_dir / "vault.txt").read_bytes(), self.original)

    @unittest.expectedFailure
    def test_a_threshold_well_above_the_old_fallback_also_works(self):
        """Guards the boundary rather than one value: 5 is the fallback."""
        result = self._encrypt_and_decrypt(threshold=8, shares=10)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual((self.tmp_dir / "vault.txt").read_bytes(), self.original)

    def test_six_of_nine_is_recoverable_with_full_metadata(self):
        """Same threshold, same share count, only difference is that
        total_shares is written down. This is what isolates the cause to the
        missing field rather than to the splitting itself."""
        result = self._encrypt_and_decrypt(6, 9, "--full-metadata")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual((self.tmp_dir / "vault.txt").read_bytes(), self.original)


class TestReusingMinimalShares(_CliInTempDir):
    """--existing-shares re-encrypts a second file under the same key, reading the
    parameters back from the shares. In minimal mode total_shares is not there to
    be read."""

    def _encrypt_then_reuse(self, threshold: int, shares: int):
        first = self._write_secret("first.txt")
        result = self._encrypt(first, threshold=threshold, shares=shares)
        self.assertEqual(result.exit_code, 0, result.output)
        existing = self._extract_shares_to("existing")

        second = self.tmp_dir / "second.txt"
        second.write_bytes(b"a second secret protected by the same key")
        return self._encrypt(
            second,
            "--existing-shares",
            str(existing),
            "--verbose",
            threshold=threshold,
            shares=shares,
        )

    def test_reuse_works_when_the_threshold_is_at_most_five(self):
        """3-of-5 happens to survive because the fallback total_shares is 5."""
        result = self._encrypt_then_reuse(threshold=3, shares=5)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue((self.tmp_dir / "second.txt.enc").is_file())

    def test_reuse_reports_the_minimal_mode_to_the_user(self):
        result = self._encrypt_then_reuse(threshold=3, shares=5)
        self.assertIn("no label", result.output)

    @unittest.expectedFailure
    def test_reuse_works_when_the_threshold_exceeds_five(self):
        """Reusing a 6-of-10 set taken in the default mode must work.

        It does not, in 1.4.2. Minimal shares carry threshold but not
        total_shares, and both ShareMetadata.from_share_info and the reader in
        commands.py fall back to a fixed 5. ShareManager(6, 5) is then rejected,
        two lines after the command has printed the correct total of 10. Fixed in
        2.0.0; remove the marker with the fix.
        """
        result = self._encrypt_then_reuse(threshold=6, shares=10)
        self.assertEqual(result.exit_code, 0, result.output)

    def test_reuse_still_works_at_the_default_threshold(self):
        """The common case must not have been broken by the fix above."""
        result = self._encrypt_then_reuse(threshold=2, shares=3)
        self.assertEqual(result.exit_code, 0, result.output)


if __name__ == "__main__":
    unittest.main()
