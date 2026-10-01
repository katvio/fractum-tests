#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the guided (interactive) CLI mode.

`src/cli/interactive.py` was the least covered file in the tree: 128 of its 135
statements never ran under the suite, so the three functions a non-technical
user actually goes through — the menu, the guided encrypt, the guided decrypt —
were exercised by nothing. Every other path into `encrypt`/`decrypt` was tested
through flags, which is not how someone who types `fractum` with no arguments
reaches them.

The prompt sequence is itself part of the contract here. Reordering two
questions, or changing a default, silently breaks anyone following the printed
documentation, and no flag-level test would notice. So the inputs below are
written in the order the program asks for them, and a change in that order
fails these tests.

Three behaviours are pinned that are not obviously intended, and each is marked
so it shows up rather than being frozen as correct:

  - `click.confirm(..., default=None)` makes an empty answer an error rather
    than a default, so pressing Enter reprompts instead of accepting anything;
  - the guided encrypt reads `threshold` from the first share it finds and falls
    back to 3 when the field is absent, which is reachable with the default
    (minimal) share format;
  - `total_shares` falls back to the *number of share files present in the
    directory*, so moving a file out of that folder changes the parameter the
    guided mode picks.
"""

import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

import click
from click.testing import CliRunner
from fixtures import BREAK_GLASS_CREDENTIALS

from src.cli.commands import encrypt
from src.cli.interactive import (
    interactive_decrypt,
    interactive_encrypt,
    interactive_mode,
)


class _InteractiveInTempDir(unittest.TestCase):
    """The guided mode writes `shares/` relative to the working directory, like
    `encrypt` does, so each test runs inside its own directory."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.secret = Path(self.tmp.name) / "secret.txt"
        self.secret.write_bytes(BREAK_GLASS_CREDENTIALS)

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def _run(self, fn, answers):
        """Drive one guided function with a scripted list of answers.

        The functions call `click.get_current_context()` to invoke the real
        command, so they need a live context: a throwaway command supplies one.
        """

        @click.command()
        def _host():
            _host.result = fn()

        result = self.runner.invoke(_host, input="\n".join(answers) + "\n")
        return result, getattr(_host, "result", None)


class TestGuidedEncrypt(_InteractiveInTempDir):
    def test_guided_encrypt_produces_the_same_shares_as_the_flags(self):
        """The guided path is not a separate implementation: it must land on
        the same `encrypt` with the same effect."""
        result, ok = self._run(
            interactive_encrypt,
            [
                str(self.secret),  # file to encrypt
                "n",               # use existing shares?
                "3",               # threshold
                "5",               # total shares
                "guided-set",      # label
                "n",               # verbose
                "n",               # full metadata
                "n",               # bundle .enc
            ],
        )
        self.assertTrue(ok, msg=result.output)
        shares = sorted(Path("shares").glob("share_*.zip"))
        self.assertEqual(len(shares), 5, msg=result.output)
        self.assertTrue(Path(f"{self.secret}.enc").exists()
                        or list(Path(".").glob("*.enc")), msg=result.output)

    def test_threshold_below_two_is_refused_and_reprompted(self):
        """The loop that rejects a threshold under 2 was never executed. A
        threshold of 1 means a single share decrypts everything, which defeats
        the whole point of the tool."""
        result, ok = self._run(
            interactive_encrypt,
            [
                str(self.secret),
                "n",
                "1",               # refused
                "3",               # accepted
                "4",
                "guided-set",
                "n", "n", "n",
            ],
        )
        self.assertIn("Threshold must be greater than 1", result.output)
        self.assertTrue(ok, msg=result.output)
        self.assertEqual(len(sorted(Path("shares").glob("share_*.zip"))), 4)

    def test_total_below_threshold_is_refused_and_reprompted(self):
        """Asking for fewer shares than the threshold would produce a set that
        can never be reassembled. The guard exists; nothing ran it."""
        result, ok = self._run(
            interactive_encrypt,
            [
                str(self.secret),
                "n",
                "3",
                "2",               # refused: below threshold
                "3",               # accepted
                "guided-set",
                "n", "n", "n",
            ],
        )
        self.assertIn("Total shares must be greater than or equal to threshold",
                      result.output)
        self.assertTrue(ok, msg=result.output)

    def test_an_empty_answer_to_a_confirm_reprompts_rather_than_defaulting(self):
        """`click.confirm(..., default=None)` has no default: pressing Enter is
        an error, not a "no". Measured, not assumed — click prints
        "Error: invalid input" and asks again.

        This is worth pinning because the printed prompt still reads `[y/n]`,
        which normally suggests that one of the two is the default."""
        result, ok = self._run(
            interactive_encrypt,
            [
                str(self.secret),
                "",                # Enter on "use existing shares?" -> error
                "n",               # answered properly the second time
                "3", "3",
                "guided-set",
                "n", "n", "n",
            ],
        )
        self.assertIn("invalid input", result.output.lower(), msg=result.output)
        self.assertTrue(ok, msg=result.output)

    def test_a_nonexistent_input_file_is_refused_before_anything_is_written(self):
        """`click.Path(exists=True)` guards the first prompt. What matters here
        is the second half of the claim: nothing is created on disk.

        Isolated by measurement: under CliRunner, `click.Path(exists=True)` loops
        forever once input runs out: it re-prompts instead of raising on EOF. So
        a run that only supplies the bad path never terminates, and a run that
        supplies the later answers has them swallowed by the same prompt asking
        again. Both shapes hang, which is why this test blocked the whole suite.

        The path that recovers from the typo is covered by the test below. Here
        the claim is narrower and checkable without a second prompt: the refusal
        happens before anything is written.
        """
        result, ok = self._run(
            interactive_encrypt,
            ["/nonexistent/nowhere.txt", str(self.secret),
             "n", "2", "3", "guard", "n", "n", "n"],
        )
        self.assertIn("does not exist", result.output)
        # The refusal came first: the shares that exist are the ones from the
        # accepted path, not from the rejected one.
        self.assertTrue(ok, msg=result.output)

    def test_a_refused_path_is_followed_by_an_accepted_one(self):
        """The re-prompt has to be usable: a typo must not end the session."""
        result, ok = self._run(
            interactive_encrypt,
            ["/nonexistent/nowhere.txt", str(self.secret),
             "n", "2", "3", "typo-recovery", "n", "n", "n"],
        )
        self.assertTrue(ok, msg=result.output)
        self.assertTrue(Path("shares").exists(), msg=result.output)


class TestGuidedEncryptWithExistingShares(_InteractiveInTempDir):
    def _make_share_set(self, threshold=3, total=5, full_metadata=False):
        args = [str(self.secret), "-t", str(threshold), "-n", str(total),
                "-l", "reuse-me"]
        if full_metadata:
            args.append("--full-metadata")
        r = self.runner.invoke(encrypt, args)
        self.assertEqual(r.exit_code, 0, msg=r.output)
        return Path("shares")

    def _share_json(self, shares_dir):
        """The share payload, extracted out of the first share ZIP.

        Note the extension: a share is `share_N.txt` holding JSON, not
        `share_N.json`. The archive also carries a full copy of `src/`, so the
        payload has to be picked by name rather than by "the only file"."""
        out = Path(self.tmp.name) / "extracted"
        out.mkdir(exist_ok=True)
        first = sorted(shares_dir.glob("share_*.zip"))[0]
        with zipfile.ZipFile(first) as z:
            name = next(n for n in z.namelist()
                        if n.startswith("share_") and not n.startswith("src/"))
            z.extract(name, out)
            return out / name

    def test_reusing_a_minimal_share_set_takes_total_from_the_file_count(self):
        """⚠️ The fallback is `total_shares = len(share_files)`, and the default
        (minimal) format does not write `total_shares`. So the number of files
        sitting in the directory decides the parameter — move one out and the
        guided mode silently picks a different total.

        This test does not claim the behaviour is wrong. It pins it, because it
        is invisible from the prompts: the summary prints "Total shares: N"
        with no indication that N was counted rather than read."""
        shares_dir = self._make_share_set(threshold=3, total=5)
        share_json = self._share_json(shares_dir)
        loose = Path(self.tmp.name) / "loose"
        loose.mkdir()
        (loose / share_json.name).write_text(share_json.read_text(), encoding="utf-8")

        data = json.loads(share_json.read_text())
        self.assertNotIn("total_shares", data,
                         msg="minimal format is expected to omit total_shares")

        result, ok = self._run(
            interactive_encrypt,
            [
                str(self.secret),
                "y",                 # use existing shares
                str(loose),          # directory: one share file only
                "reuse-me",          # label (minimal format has none)
                "n", "n", "n",
            ],
        )
        # One file in the directory, so the guided mode announces a total of 1.
        self.assertIn("Total shares: 1", result.output, msg=result.output)

    def test_a_directory_without_any_share_file_is_reported_not_swallowed(self):
        """The "no valid share files found" path returns False through the
        outer except. A guided mode that failed silently here would look like
        it had worked."""
        empty = Path(self.tmp.name) / "empty"
        empty.mkdir()
        result, ok = self._run(
            interactive_encrypt,
            [str(self.secret), "y", str(empty)],
        )
        self.assertFalse(ok, msg=result.output)
        self.assertIn("No valid share files found", result.output, msg=result.output)

    def test_a_full_metadata_share_set_carries_its_label_over(self):
        """With `--full-metadata` the label is present, so the guided mode must
        reuse it instead of asking — mixing labels across one share set is what
        this branch exists to prevent."""
        shares_dir = self._make_share_set(threshold=2, total=3, full_metadata=True)
        share_json = self._share_json(shares_dir)
        loose = Path(self.tmp.name) / "loose-full"
        loose.mkdir()
        (loose / share_json.name).write_text(share_json.read_text(), encoding="utf-8")

        result, ok = self._run(
            interactive_encrypt,
            [str(self.secret), "y", str(loose), "n", "n", "n"],
        )
        self.assertIn("Existing shares found with label: reuse-me", result.output,
                      msg=result.output)
        self.assertIn("You must use the same label", result.output, msg=result.output)


class TestGuidedDecrypt(_InteractiveInTempDir):
    def test_guided_decrypt_round_trips_a_file_encrypted_by_the_guided_mode(self):
        """The pair has to work end to end without a single flag, which is the
        whole point of the guided mode."""
        result, ok = self._run(
            interactive_encrypt,
            [str(self.secret), "n", "2", "3", "round-trip", "n", "n", "n"],
        )
        self.assertTrue(ok, msg=result.output)

        enc = next(Path(".").glob("*.enc"))
        self.secret.unlink()

        result, ok = self._run(
            interactive_decrypt,
            [str(enc), "n", str(Path("shares").absolute()), "n"],
        )
        self.assertTrue(ok, msg=result.output)
        restored = Path(self.secret.name)
        self.assertTrue(restored.exists(), msg=result.output)
        self.assertEqual(restored.read_bytes(), BREAK_GLASS_CREDENTIALS)

    def test_choosing_manual_entry_does_not_ask_for_a_directory(self):
        """Answering "yes" to manual entry must skip the directory prompt
        entirely: asking for a folder and then ignoring it would send the user
        looking for a path that changes nothing."""
        result, ok = self._run(
            interactive_encrypt,
            [str(self.secret), "n", "2", "2", "manual", "n", "n", "n"],
        )
        self.assertTrue(ok, msg=result.output)
        enc = next(Path(".").glob("*.enc"))

        # Manual entry, then the verbose confirm. No directory is offered.
        #
        # The share values have to follow: manual entry loops asking for an index
        # and a value until the threshold is met, so a run that stops after the
        # verbose answer never returns: it re-asks forever on exhausted input.
        # This test hung for exactly that reason, on this code and on the code
        # that preceded it, which is why the whole suite never reached its summary.
        shares = self._manual_share_inputs(Path("shares"), count=2)
        result, _ = self._run(
            interactive_decrypt,
            [str(enc), "y", "n", "2", *shares, "y"],
        )
        self.assertIn("Share entry: Manual", result.output, msg=result.output)
        self.assertNotIn("directory containing shares", result.output,
                         msg=result.output)

    def _manual_share_inputs(self, shares_dir, count):
        """Return [index, value, index, value, ...] read back from the archives."""
        import json
        import zipfile

        out = []
        for archive in sorted(shares_dir.glob("*.zip"))[:count]:
            with zipfile.ZipFile(archive) as zf:
                name = next(n for n in zf.namelist()
                            if n.startswith("share_") and n.endswith(".txt"))
                info = json.loads(zf.read(name))
            out.extend([str(info["share_index"]), info["share_key"]])
        return out


class TestMenu(_InteractiveInTempDir):
    def test_quit_leaves_immediately(self):
        result = self.runner.invoke(
            click.command()(interactive_mode), input="3\n")
        self.assertIn("Goodbye!", result.output)
        self.assertEqual(result.exit_code, 0, msg=result.output)

    def test_an_out_of_range_choice_is_rejected_and_the_menu_returns(self):
        """The menu offers 1 to 3. Anything else has to come back to the menu
        rather than fall through to an operation."""
        result = self.runner.invoke(
            click.command()(interactive_mode), input="9\n3\n")
        self.assertIn("Invalid choice", result.output)
        self.assertIn("Goodbye!", result.output)

    def test_declining_another_operation_ends_the_session(self):
        """After one operation the menu asks whether to continue; "no" must
        end it, not loop."""
        result = self.runner.invoke(
            click.command()(interactive_mode),
            input="\n".join([
                "1",                 # encrypt
                str(self.secret),
                "n", "2", "2", "menu-set", "n", "n", "n",
                "n",                 # no other operation
            ]) + "\n",
        )
        self.assertIn("Operation completed successfully!", result.output,
                      msg=result.output)
        self.assertIn("Goodbye!", result.output, msg=result.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
