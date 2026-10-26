"""Offline trust-boundary regression for the Docker image provisioner."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import docker_image_packages as packages


class DockerFixtureKeyTests(unittest.TestCase):
    def test_only_pinned_primary_certificate_is_trusted(self):
        with tempfile.TemporaryDirectory(prefix="chairlift-docker-keys-") as directory:
            root = Path(directory)
            home = root / "gnupg"
            home.mkdir(mode=0o700)
            env = dict(os.environ, GNUPGHOME=str(home))

            def gpg(*arguments):
                return subprocess.check_output(
                    ["gpg", "--no-options", "--batch", "--pinentry-mode", "loopback",
                     "--passphrase", "", *arguments], env=env, text=True,
                )

            trusted = "Trusted Docker fixture <trusted@example.invalid>"
            rogue = "Rogue Docker fixture <rogue@example.invalid>"
            gpg("--quick-generate-key", trusted, "ed25519", "cert", "0")
            listing = gpg("--with-colons", "--list-keys", trusted)
            fingerprint = next(line.split(":")[9] for line in listing.splitlines()
                               if line.startswith("fpr:"))
            gpg("--quick-add-key", fingerprint, "ed25519", "sign", "0")
            gpg("--quick-generate-key", rogue, "ed25519", "cert", "0")
            trusted_bundle = gpg("--armor", "--export", fingerprint).encode()
            rogue_bundle = gpg("--armor", "--export", rogue).encode()
            key = root / "docker.asc"

            with mock.patch.object(packages, "FINGERPRINT", fingerprint):
                key.write_bytes(trusted_bundle)
                packages.validate_key(key)

                key.write_bytes(trusted_bundle + rogue_bundle)
                with self.assertRaisesRegex(ValueError, "primary certificates"):
                    packages.validate_key(key)

                with mock.patch.object(packages, "fetch", return_value=key.read_bytes()) as fetch:
                    with mock.patch.object(packages.platform, "machine", return_value="x86_64"):
                        with self.assertRaisesRegex(ValueError, "primary certificates"):
                            packages.main()
                    fetch.assert_called_once_with("gpg")


if __name__ == "__main__":
    unittest.main()
