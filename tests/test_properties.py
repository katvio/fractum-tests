#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Property-based tests for share splitting and file encryption.

Every other suite here is example-based: a fixed threshold, a fixed secret, a
fixed corruption. That covers the cases someone thought of. The properties below
are the ones that must hold for *every* input, and hypothesis searches for the
counter-example instead of us guessing it.

Four invariants of Shamir's secret sharing as Fractum uses it:

  - any subset of exactly `threshold` shares reconstructs the secret, whichever
    shares they are;
  - any subset smaller than `threshold` is refused outright;
  - the reconstruction is the secret zero-padded to 32 bytes, since that is what
    _prepare_secret hands to Shamir;
  - duplicate indices are always rejected, never silently combined.

Plus the AES-GCM round trip and its authentication, over arbitrary payloads.

hypothesis is an optional test dependency (extras_require["test"]). When it is
missing the classes below are skipped rather than erroring out, so a bare
`pip install -e .` followed by `python run_tests.py` still works.
"""

import tempfile
import unittest
from pathlib import Path

from src.crypto import FileEncryptor
from src.shares import ShareManager

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    HAS_HYPOTHESIS = True
except ImportError:  # pragma: no cover - exercised only on a bare install
    HAS_HYPOTHESIS = False

    def given(*args, **kwargs):
        def decorate(function):
            return function

        return decorate

    def settings(*args, **kwargs):
        def decorate(function):
            return function

        return decorate

    class _MissingStrategies:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    st = _MissingStrategies()


# The AES key is 32 bytes. _prepare_secret zero-pads anything shorter, so a
# secret of any length from 1 to 32 is accepted and comes back padded, which is
# why the assertions below compare against secret.ljust(32, b"\0").
#
# Defined after the import block on purpose: `st` is either hypothesis or the
# stub below it, and this must work with both.
SECRET_SIZE = 32
SECRETS = st.binary(min_size=1, max_size=SECRET_SIZE)

SKIP_REASON = "hypothesis is not installed (pip install -e '.[test]')"

# Shamir.split is not free, so keep the parameter space small enough that a full
# run stays in the same order of magnitude as the rest of the suite.
EXAMPLES = settings(max_examples=25, deadline=None)


@unittest.skipUnless(HAS_HYPOTHESIS, SKIP_REASON)
class TestShareSplittingProperties(unittest.TestCase):
    """Invariants that must hold for every threshold, share count and secret."""

    @staticmethod
    def _draw_parameters(data):
        """threshold in [2, 6], total in [threshold, threshold + 4]."""
        threshold = data.draw(st.integers(min_value=2, max_value=6), label="threshold")
        total = data.draw(
            st.integers(min_value=threshold, max_value=threshold + 4), label="total"
        )
        return threshold, total

    @EXAMPLES
    @given(st.data())
    def test_any_threshold_sized_subset_reconstructs_the_secret(self, data):
        """The whole point of a k-of-n scheme: which k does not matter."""
        threshold, total = self._draw_parameters(data)
        secret = data.draw(SECRETS, label="secret")

        manager = ShareManager(threshold, total)
        shares = manager.generate_shares(secret, "property")
        subset = data.draw(st.permutations(shares), label="subset")[:threshold]

        self.assertEqual(manager.combine_shares(subset), secret.ljust(32, b"\0"))

    @EXAMPLES
    @given(st.data())
    def test_more_shares_than_the_threshold_still_reconstruct(self, data):
        """Handing over every share must work as well as handing over exactly k."""
        threshold, total = self._draw_parameters(data)
        secret = data.draw(SECRETS, label="secret")

        manager = ShareManager(threshold, total)
        shares = manager.generate_shares(secret, "property")

        self.assertEqual(manager.combine_shares(shares), secret.ljust(32, b"\0"))

    @EXAMPLES
    @given(st.data())
    def test_fewer_shares_than_the_threshold_are_refused(self, data):
        """Refused explicitly, never answered with a wrong secret."""
        threshold, total = self._draw_parameters(data)
        secret = data.draw(SECRETS, label="secret")
        held = data.draw(
            st.integers(min_value=0, max_value=threshold - 1), label="held"
        )

        manager = ShareManager(threshold, total)
        shares = manager.generate_shares(secret, "property")

        with self.assertRaises(ValueError):
            manager.combine_shares(shares[:held])

    @EXAMPLES
    @given(st.data())
    def test_duplicated_shares_never_stand_in_for_distinct_ones(self, data):
        """Presenting the same share k times must not reconstruct anything."""
        threshold, total = self._draw_parameters(data)
        secret = data.draw(SECRETS, label="secret")

        manager = ShareManager(threshold, total)
        shares = manager.generate_shares(secret, "property")
        position = data.draw(
            st.integers(min_value=0, max_value=total - 1), label="position"
        )

        with self.assertRaises(ValueError):
            manager.combine_shares([shares[position]] * threshold)

    @EXAMPLES
    @given(st.data())
    def test_generate_shares_returns_the_requested_count_with_unique_indices(
        self, data
    ):
        threshold, total = self._draw_parameters(data)
        secret = data.draw(SECRETS, label="secret")

        shares = ShareManager(threshold, total).generate_shares(secret, "property")

        self.assertEqual(len(shares), total)
        indices = [index for index, _ in shares]
        self.assertEqual(len(set(indices)), total)

    @EXAMPLES
    @given(st.data())
    def test_every_share_is_thirty_two_bytes(self, data):
        """Two 16-byte Shamir halves concatenated, whatever the secret length."""
        threshold, total = self._draw_parameters(data)
        secret = data.draw(SECRETS, label="secret")

        shares = ShareManager(threshold, total).generate_shares(secret, "property")

        for index, share in shares:
            with self.subTest(index=index):
                self.assertEqual(len(share), 32)

    @EXAMPLES
    @given(st.data())
    def test_a_share_never_contains_the_secret_verbatim(self, data):
        """A single share must leak nothing readable. The secret is padded to 32
        bytes and each share is 32 bytes, so an equality check is the strongest
        statement available at this level."""
        threshold, total = self._draw_parameters(data)
        secret = data.draw(SECRETS, label="secret")

        shares = ShareManager(threshold, total).generate_shares(secret, "property")

        padded = secret.ljust(32, b"\0")
        for index, share in shares:
            with self.subTest(index=index):
                self.assertNotEqual(share, padded)


@unittest.skipUnless(HAS_HYPOTHESIS, SKIP_REASON)
class TestShareManagerValidationProperties(unittest.TestCase):
    """The constructor and _prepare_secret guards, over their whole domain."""

    @EXAMPLES
    @given(st.integers(min_value=-1000, max_value=1))
    def test_a_threshold_below_two_is_always_rejected(self, threshold):
        """A 1-of-n split would hand the secret to every holder."""
        with self.assertRaises(ValueError):
            ShareManager(threshold, 5)

    @EXAMPLES
    @given(st.data())
    def test_fewer_total_shares_than_the_threshold_is_always_rejected(self, data):
        threshold = data.draw(st.integers(min_value=2, max_value=50))
        total = data.draw(st.integers(min_value=0, max_value=threshold - 1))
        with self.assertRaises(ValueError):
            ShareManager(threshold, total)

    @EXAMPLES
    @given(st.integers(min_value=256, max_value=10_000))
    def test_more_than_255_shares_is_always_rejected(self, total):
        """PyCryptodome's limit: indices live in GF(2^8)."""
        with self.assertRaises(ValueError):
            ShareManager(2, total)

    @EXAMPLES
    @given(st.binary(min_size=SECRET_SIZE + 1, max_size=256))
    def test_a_secret_longer_than_32_bytes_is_always_rejected(self, secret):
        with self.assertRaises(ValueError):
            ShareManager(3, 5).generate_shares(secret, "property")

    @EXAMPLES
    @given(st.binary(min_size=1, max_size=SECRET_SIZE - 1))
    def test_a_secret_shorter_than_32_bytes_comes_back_zero_padded(self, secret):
        """The other side of the boundary, pinned as it is in 1.4.x: a short
        secret is padded, not refused. A short secret is therefore
        indistinguishable from a full-length one ending in zeros. 2.0.0 refuses
        it instead."""
        manager = ShareManager(3, 5)
        shares = manager.generate_shares(secret, "property")
        self.assertEqual(manager.combine_shares(shares[:3]), secret.ljust(32, b"\0"))

    @EXAMPLES
    @given(SECRETS)
    def test_an_empty_label_is_always_rejected(self, secret):
        with self.assertRaises(ValueError):
            ShareManager(3, 5).generate_shares(secret, "")


@unittest.skipUnless(HAS_HYPOTHESIS, SKIP_REASON)
class TestEncryptionProperties(unittest.TestCase):
    """AES-256-GCM round trip and authentication, over arbitrary payloads."""

    def _round_trip(self, key: bytes, payload: bytes, metadata=None) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "plain.bin"
            encrypted = Path(tmp) / "plain.bin.enc"
            restored = Path(tmp) / "restored.bin"
            source.write_bytes(payload)

            encryptor = FileEncryptor(key)
            encryptor.encrypt_file(str(source), str(encrypted), metadata)
            encryptor.decrypt_file(str(encrypted), str(restored))
            return restored.read_bytes()

    @EXAMPLES
    @given(
        st.binary(min_size=32, max_size=32),
        st.binary(min_size=1, max_size=4096),
    )
    def test_decrypting_what_was_encrypted_returns_the_input(self, key, payload):
        self.assertEqual(self._round_trip(key, payload), payload)

    @EXAMPLES
    @given(
        st.binary(min_size=32, max_size=32),
        st.binary(min_size=1, max_size=1024),
        st.text(min_size=1, max_size=64),
    )
    def test_the_round_trip_survives_arbitrary_metadata(self, key, payload, label):
        """Metadata is the AAD, so it must travel unchanged, including non-ASCII
        labels."""
        self.assertEqual(
            self._round_trip(key, payload, {"share_set_id": label}), payload
        )

    @EXAMPLES
    @given(
        st.binary(min_size=32, max_size=32),
        st.binary(min_size=32, max_size=32),
        st.binary(min_size=1, max_size=512),
    )
    def test_a_different_key_never_decrypts(self, key, other_key, payload):
        if key == other_key:
            return  # the strategy is allowed to collide; nothing to assert
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "plain.bin"
            encrypted = Path(tmp) / "plain.bin.enc"
            source.write_bytes(payload)
            FileEncryptor(key).encrypt_file(str(source), str(encrypted))

            with self.assertRaises(ValueError):
                FileEncryptor(other_key).decrypt_file(
                    str(encrypted), str(Path(tmp) / "restored.bin")
                )

    @EXAMPLES
    @given(st.data())
    def test_flipping_any_single_byte_of_the_ciphertext_is_detected(self, data):
        """GCM authenticates. No byte of the tail may be modified undetected,
        wherever it falls."""
        key = data.draw(st.binary(min_size=32, max_size=32), label="key")
        payload = data.draw(st.binary(min_size=1, max_size=512), label="payload")

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "plain.bin"
            encrypted = Path(tmp) / "plain.bin.enc"
            source.write_bytes(payload)
            FileEncryptor(key).encrypt_file(str(source), str(encrypted))

            blob = bytearray(encrypted.read_bytes())
            # Skip the 4-byte length prefix and the JSON metadata: those have
            # their own error paths, covered in test_file_corruption.
            header_length = 4 + int.from_bytes(blob[:4], "big")
            position = data.draw(
                st.integers(min_value=header_length, max_value=len(blob) - 1),
                label="position",
            )
            blob[position] ^= data.draw(
                st.integers(min_value=1, max_value=255), label="mask"
            )
            encrypted.write_bytes(bytes(blob))

            with self.assertRaises(ValueError):
                FileEncryptor(key).decrypt_file(
                    str(encrypted), str(Path(tmp) / "restored.bin")
                )


@unittest.skipUnless(HAS_HYPOTHESIS, SKIP_REASON)
class TestEndToEndProperties(unittest.TestCase):
    """Split the key, throw shares away down to the threshold, decrypt anyway."""

    @EXAMPLES
    @given(st.data())
    def test_a_file_survives_losing_every_share_above_the_threshold(self, data):
        threshold = data.draw(st.integers(min_value=2, max_value=5), label="threshold")
        total = data.draw(
            st.integers(min_value=threshold, max_value=threshold + 3), label="total"
        )
        key = data.draw(st.binary(min_size=32, max_size=32), label="key")
        payload = data.draw(st.binary(min_size=1, max_size=1024), label="payload")

        manager = ShareManager(threshold, total)
        shares = manager.generate_shares(key, "property")
        survivors = data.draw(st.permutations(shares), label="survivors")[:threshold]
        recovered = manager.combine_shares(survivors)

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "plain.bin"
            encrypted = Path(tmp) / "plain.bin.enc"
            restored = Path(tmp) / "restored.bin"
            source.write_bytes(payload)

            FileEncryptor(key).encrypt_file(str(source), str(encrypted))
            FileEncryptor(recovered).decrypt_file(str(encrypted), str(restored))

            self.assertEqual(restored.read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
