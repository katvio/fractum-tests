#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the offline package set shipped in packages/.

Fractum is meant to be installed with no network access: every share archive
carries the wheels its holder needs, and packages/CHECKSUMS.sha256 is what a
share holder is told to verify before installing them. That file is therefore
part of the trust chain, and nothing in the suite covered it until now.

Two things are checked here:

  - the wheels on disk match the digests recorded in CHECKSUMS.sha256, in both
    directions (no listed wheel is missing, no unlisted wheel is present);
  - the detached GPG signature over CHECKSUMS.sha256 exists and verifies against
    the signing key shipped at the root of the repository.
"""

import hashlib
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGES_DIR = REPO_ROOT / "packages"
CHECKSUMS = PACKAGES_DIR / "CHECKSUMS.sha256"
SIGNATURE = PACKAGES_DIR / "CHECKSUMS.sha256.asc"
UNSIGNED_PLACEHOLDER = PACKAGES_DIR / "CHECKSUMS.sha256.asc.UNSIGNED"
SIGNING_KEY = REPO_ROOT / "fractum-signing-key.asc"

# "<64 hex>  <filename>", the output format of sha256sum.
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  (\S.*)$")


def _parse_checksums() -> dict:
    """Return {filename: digest} parsed from CHECKSUMS.sha256.

    Blank lines and '#' comments are tolerated; anything else must match the
    sha256sum output format, which is asserted separately.
    """
    entries = {}
    for line in CHECKSUMS.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = CHECKSUM_LINE.match(line)
        if match:
            entries[match.group(2)] = match.group(1)
    return entries


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class TestPackagesDirectory(unittest.TestCase):
    """The offline wheel set must be present and complete."""

    def test_packages_directory_exists(self):
        """packages/ ships with the repository and with every share archive."""
        self.assertTrue(
            PACKAGES_DIR.is_dir(), f"Missing offline package directory: {PACKAGES_DIR}"
        )

    def test_at_least_one_wheel_is_shipped(self):
        """An empty packages/ would silently turn an offline install into a
        network install."""
        wheels = list(PACKAGES_DIR.glob("*.whl"))
        self.assertGreater(len(wheels), 0, "No .whl file in packages/")

    def test_pycryptodome_is_shipped_for_the_three_supported_platforms(self):
        """The bootstrap scripts cover Linux, macOS and Windows, so the compiled
        dependency must be available for all three."""
        wheel_names = [w.name for w in PACKAGES_DIR.glob("pycryptodome-*.whl")]
        for platform_tag in ("manylinux", "macosx", "win_amd64"):
            self.assertTrue(
                any(platform_tag in name for name in wheel_names),
                f"No pycryptodome wheel for {platform_tag} in {wheel_names}",
            )


class TestChecksumsFile(unittest.TestCase):
    """CHECKSUMS.sha256 is what a share holder verifies. It must be readable by
    sha256sum -c and agree with the files on disk."""

    def test_checksums_file_exists(self):
        self.assertTrue(CHECKSUMS.is_file(), f"Missing {CHECKSUMS}")

    def test_every_line_matches_the_sha256sum_format(self):
        """A malformed line makes `sha256sum -c` skip it, which verifies nothing
        while still exiting 0."""
        for number, line in enumerate(
            CHECKSUMS.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            self.assertRegex(
                line,
                CHECKSUM_LINE,
                f"Line {number} is not in '<sha256>  <filename>' form: {line!r}",
            )

    def test_checksums_file_is_not_empty(self):
        self.assertGreater(len(_parse_checksums()), 0, "No entry in CHECKSUMS.sha256")

    def test_every_listed_file_exists_on_disk(self):
        for filename in _parse_checksums():
            with self.subTest(filename=filename):
                self.assertTrue(
                    (PACKAGES_DIR / filename).is_file(),
                    f"{filename} is listed in CHECKSUMS.sha256 but absent from "
                    "packages/",
                )

    def test_every_digest_matches_the_file_on_disk(self):
        """The check a share holder is told to run, run here so a wheel can never
        be swapped without the digest being updated too."""
        for filename, expected in _parse_checksums().items():
            path = PACKAGES_DIR / filename
            if not path.is_file():
                continue  # reported by test_every_listed_file_exists_on_disk
            with self.subTest(filename=filename):
                self.assertEqual(
                    _sha256(path),
                    expected,
                    f"Digest mismatch for {filename}. The wheel on disk is not the "
                    "one CHECKSUMS.sha256 vouches for.",
                )

    def test_no_wheel_is_missing_from_the_checksums(self):
        """A wheel dropped into packages/ without a matching digest line would be
        installed by the bootstrap scripts and verified by nothing."""
        listed = set(_parse_checksums())
        on_disk = {w.name for w in PACKAGES_DIR.glob("*.whl")}
        unlisted = sorted(on_disk - listed)
        self.assertEqual(
            unlisted,
            [],
            f"Wheels present in packages/ but absent from CHECKSUMS.sha256: {unlisted}",
        )

    def test_digests_are_lowercase_hex(self):
        """sha256sum -c is case sensitive on the digest field."""
        for filename, digest in _parse_checksums().items():
            with self.subTest(filename=filename):
                self.assertEqual(digest, digest.lower())


class TestReleaseSignature(unittest.TestCase):
    """CHECKSUMS.sha256 is only trustworthy if it is signed.

    Without a signature, an attacker who can modify the share archive edits both
    the wheel and its digest line, and the verification step a share holder is
    asked to perform confirms nothing.

    Until 1.4.2 the repository carried packages/CHECKSUMS.sha256.asc.UNSIGNED, a
    placeholder, in place of the signature (katvio/fractum#31). 1.4.2 ships a real
    detached signature and the public key that checks it (katvio/fractum#39).

    The presence of the .asc file is not the property that matters. In 1.4.1 the
    Docker build called gpg --verify in an image that had no gpg and no key, so a
    signature on disk verified nothing. test_signature_verifies_against_the_shipped_key
    runs the verification itself.
    """

    def test_checksums_are_gpg_signed(self):
        self.assertTrue(
            SIGNATURE.is_file(),
            "packages/CHECKSUMS.sha256.asc is missing: the offline package "
            "digests are unsigned (katvio/fractum#31).",
        )

    def test_the_signing_key_is_shipped(self):
        """A share holder offline has no keyserver. The key has to travel with
        the source, or the signature cannot be checked where it is needed."""
        self.assertTrue(SIGNING_KEY.is_file(), f"Missing {SIGNING_KEY.name}")
        self.assertIn(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            SIGNING_KEY.read_text(encoding="utf-8", errors="replace"),
        )

    @staticmethod
    def _gpg_in(workdir: str, *args: str) -> subprocess.CompletedProcess:
        """Run gpg inside workdir with relative paths only.

        Git for Windows ships an MSYS gpg that reads a native C:\\... path given
        to --homedir as relative and fails with "keyblock resource ... No such
        file or directory". Copying the inputs next to a relative homedir works
        the same on every platform."""
        return subprocess.run(
            ["gpg", "--batch", "--homedir", "gnupg", *args],
            cwd=workdir,
            capture_output=True,
            text=True,
        )

    def _prepare(self, workdir: str, checksums_text: str) -> None:
        Path(workdir, "gnupg").mkdir(mode=0o700)
        shutil.copy(SIGNING_KEY, Path(workdir, "key.asc"))
        shutil.copy(SIGNATURE, Path(workdir, "CHECKSUMS.sha256.asc"))
        Path(workdir, "CHECKSUMS.sha256").write_bytes(checksums_text.encode("utf-8"))

    @unittest.skipUnless(shutil.which("gpg"), "gpg is not installed")
    def test_signature_verifies_against_the_shipped_key(self):
        """Import the shipped key into a throwaway keyring and verify. A throwaway
        keyring, so that a key already trusted on the test machine cannot make a
        bad signature pass."""
        with tempfile.TemporaryDirectory() as workdir:
            self._prepare(workdir, CHECKSUMS.read_bytes().decode("utf-8"))
            imported = self._gpg_in(workdir, "--import", "key.asc")
            self.assertEqual(imported.returncode, 0, imported.stderr)
            verified = self._gpg_in(
                workdir, "--verify", "CHECKSUMS.sha256.asc", "CHECKSUMS.sha256"
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("Good signature", verified.stderr)

    @unittest.skipUnless(shutil.which("gpg"), "gpg is not installed")
    def test_a_modified_checksums_file_fails_verification(self):
        """The counterpart: one changed digest must break the signature. The
        import is asserted too, so that a keyring that never loaded the key
        cannot make this test pass for the wrong reason."""
        content = CHECKSUMS.read_bytes().decode("utf-8")
        tampered = ("0" if content[0] != "0" else "1") + content[1:]
        with tempfile.TemporaryDirectory() as workdir:
            self._prepare(workdir, tampered)
            imported = self._gpg_in(workdir, "--import", "key.asc")
            self.assertEqual(imported.returncode, 0, imported.stderr)
            verified = self._gpg_in(
                workdir, "--verify", "CHECKSUMS.sha256.asc", "CHECKSUMS.sha256"
            )
            self.assertNotEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("BAD signature", verified.stderr)

    def test_placeholder_is_not_mistaken_for_a_signature(self):
        """Whatever happens, the placeholder must never be named .asc, or tooling
        would treat a comment block as a signature."""
        if not SIGNATURE.is_file():
            self.skipTest("No signature file to distinguish from the placeholder")
        content = SIGNATURE.read_text(encoding="utf-8", errors="replace")
        self.assertIn(
            "-----BEGIN PGP SIGNATURE-----",
            content,
            "CHECKSUMS.sha256.asc exists but does not contain a PGP signature block.",
        )

    def test_placeholder_documents_how_to_produce_the_signature(self):
        """As long as the placeholder is there, it has to carry the signing
        procedure, otherwise the release step is undiscoverable."""
        if not UNSIGNED_PLACEHOLDER.is_file():
            self.skipTest("Placeholder removed, the release is presumably signed")
        content = UNSIGNED_PLACEHOLDER.read_text(encoding="utf-8")
        self.assertIn("gpg --detach-sign", content, "No signing command documented")
        self.assertRegex(
            content,
            r"[0-9A-F]{16}",
            "No signing key ID documented in the placeholder",
        )

    def test_exactly_one_of_signature_or_placeholder_is_present(self):
        """Keeping both would leave it ambiguous which one release tooling
        should read."""
        self.assertNotEqual(
            SIGNATURE.is_file(),
            UNSIGNED_PLACEHOLDER.is_file(),
            "packages/ must contain either CHECKSUMS.sha256.asc or "
            "CHECKSUMS.sha256.asc.UNSIGNED, not both and not neither. "
            f"Signature: {SIGNATURE.is_file()}, "
            f"placeholder: {UNSIGNED_PLACEHOLDER.is_file()}.",
        )


if __name__ == "__main__":
    unittest.main()
