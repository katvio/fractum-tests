#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for `ShareMetadata`: the guards on the share header, and the fallbacks
applied when a field is missing.

`src/shares/metadata.py` sat at 65% with `validate()` entirely unexercised —
every one of its four guards was dead code as far as the suite was concerned.
Those guards are what stop a share set from being created in a shape that can
never be reassembled, so they are worth pinning individually rather than through
one end-to-end encrypt.

Two of the fallbacks in `from_share_info` deserve their own tests because they are
silent and they are reachable with the DEFAULT share format:

  - `threshold` falls back to 3;
  - `total_shares` falls back to 5.

The minimal format writes `threshold` but not `total_shares`, so the second one
fires on a perfectly ordinary share set. This is the same root cause as the
reuse defect already recorded in `tests/README.md` for `--existing-shares`; the
test below pins the mechanism itself, at the level where it originates.
"""

import unittest

from src.config import VERSION
from src.shares.metadata import ShareMetadata


class TestValidateGuards(unittest.TestCase):
    """Each guard, one test. A single test that walks all four would stop at
    the first failure and hide the other three."""

    def _valid(self, **over):
        base = dict(version=VERSION, label="set", threshold=3, total_shares=5)
        base.update(over)
        return ShareMetadata(**base)

    def test_a_valid_set_passes(self):
        """The witness. Without it, a validate() that raised on everything
        would satisfy all the tests below and look correct."""
        self._valid().validate()

    def test_threshold_of_one_is_refused(self):
        """A threshold of 1 means any single share decrypts the file, which is
        the one outcome the tool exists to prevent."""
        with self.assertRaises(ValueError) as e:
            self._valid(threshold=1).validate()
        self.assertIn("greater than 1", str(e.exception))

    def test_threshold_of_zero_and_negative_are_refused(self):
        for bad in (0, -1, -255):
            with self.subTest(threshold=bad), self.assertRaises(ValueError):
                self._valid(threshold=bad, total_shares=255).validate()

    def test_a_non_integer_threshold_is_refused(self):
        """`isinstance(..., int)` is in the guard, so a string that looks like a
        number must not slip through: "3" would compare fine in some paths and
        break in others."""
        for bad in ("3", 3.0, None):
            with self.subTest(threshold=bad), self.assertRaises(ValueError):
                self._valid(threshold=bad).validate()

    def test_total_below_threshold_is_refused(self):
        """A set of 2 shares with a threshold of 3 can never be reassembled.
        Creating it would produce an archive that is silently already lost."""
        with self.assertRaises(ValueError) as e:
            self._valid(threshold=3, total_shares=2).validate()
        self.assertIn("greater than or equal to threshold", str(e.exception))

    def test_total_equal_to_threshold_is_allowed(self):
        """The boundary. n-of-n is a legitimate configuration — every holder
        must be present — and the guard must not reject it."""
        self._valid(threshold=3, total_shares=3).validate()

    def test_total_above_255_is_refused(self):
        """255 is not an arbitrary cap: Shamir's scheme here works over
        GF(256), which leaves 255 distinct non-zero x-coordinates. Asking for
        256 shares cannot produce 256 distinct shares."""
        with self.assertRaises(ValueError) as e:
            self._valid(threshold=2, total_shares=256).validate()
        self.assertIn("cannot exceed 255", str(e.exception))

    def test_exactly_255_is_allowed(self):
        """The other side of the same boundary."""
        self._valid(threshold=2, total_shares=255).validate()

    def test_an_empty_label_is_refused_but_none_is_accepted(self):
        """These two are NOT the same thing, and the distinction carries the
        minimal-metadata mode: `None` means "no label field written", an empty
        string means "a label was asked for and left blank"."""
        with self.assertRaises(ValueError) as e:
            self._valid(label="").validate()
        self.assertIn("empty string", str(e.exception))
        self._valid(label=None).validate()


class TestFromShareInfoFallbacks(unittest.TestCase):
    def test_threshold_falls_back_to_three_when_absent(self):
        """⚠️ Silent fallback. A share header without `threshold` does not
        fail: it becomes a 3-of-N set. Pinned, not endorsed — nothing in the
        output tells the caller the value was invented."""
        m = ShareMetadata.from_share_info({"share_index": 1, "share_key": "x"})
        self.assertEqual(m.threshold, 3)

    def test_total_shares_falls_back_to_five_when_absent(self):
        """⚠️ Same, and this one fires on the DEFAULT format: minimal shares
        write `threshold` but not `total_shares`. A 7-of-9 set read back
        through this path becomes 7-of-5, which then fails validate() — the
        defect already recorded for `--existing-shares` reuse."""
        m = ShareMetadata.from_share_info(
            {"share_index": 1, "share_key": "x", "threshold": 7})
        self.assertEqual(m.total_shares, 5)
        with self.assertRaises(ValueError):
            m.validate()

    def test_an_explicit_total_is_preferred_over_the_fallback(self):
        """A share that does record the count keeps it."""
        m = ShareMetadata.from_share_info(
            {"share_index": 1, "share_key": "x", "threshold": 3, "total_shares": 9})
        self.assertEqual(m.total_shares, 9)
        m.validate()

    def test_the_version_is_read_from_the_three_shapes_in_priority_order(self):
        """Three historical layouts carry the tool version, and the order
        matters: a share holding both must be read as the newer one."""
        nested = {"tool_integrity": {"shares_tool_version": "nested"},
                  "shares_tool_version": "flat", "version": "legacy"}
        self.assertEqual(ShareMetadata.from_share_info(nested).version, "nested")
        self.assertEqual(
            ShareMetadata.from_share_info(
                {"shares_tool_version": "flat", "version": "legacy"}).version,
            "flat")
        self.assertEqual(ShareMetadata.from_share_info({"version": "legacy"}).version,
                         "legacy")

    def test_a_share_with_no_version_at_all_takes_the_running_version(self):
        """The last branch of the chain. It matters because it means an
        unversioned share is treated as current rather than rejected."""
        self.assertEqual(ShareMetadata.from_share_info({}).version, VERSION)

    def test_round_trip_through_to_dict_preserves_every_field(self):
        """`to_dict` feeds what is written into the share. A field dropped here
        is a field the next reader falls back on."""
        original = ShareMetadata(version=VERSION, label="round",
                                 threshold=4, total_shares=9)
        again = ShareMetadata.from_share_info(original.to_dict())
        self.assertEqual(again.version, original.version)
        self.assertEqual(again.label, original.label)
        self.assertEqual(again.threshold, original.threshold)
        self.assertEqual(again.total_shares, original.total_shares)


if __name__ == "__main__":
    unittest.main(verbosity=2)
