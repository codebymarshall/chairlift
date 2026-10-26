"""Build-only real Docker payload for the pinned Dakota live-test image.

The official image has no apt/dnf/rpm/dpkg. Verify Docker's signing key and
InRelease, then each index/package SHA256 before extracting native payloads.
The application never runs this provisioner or installs Docker packages.
"""

import gzip
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import urllib.request

BASE = "https://download.docker.com/linux/debian/"
FINGERPRINT = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
PACKAGES = ("containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli", "docker-compose-plugin")


def fetch(path):
    with urllib.request.urlopen(BASE + path, timeout=120) as response:
        return response.read()


def verified(data, expected):
    actual = hashlib.sha256(data).hexdigest()
    assert actual == expected, f"SHA256 mismatch: {actual} != {expected}"
    return data


def validate_key(key):
    keys = subprocess.check_output(
        ["gpg", "--no-options", "--batch", "--no-autostart", "--homedir", str(key.parent),
         "--with-colons", "--show-keys", str(key)], text=True,
    )
    fingerprints = []
    primary = False
    for line in keys.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            fingerprints.append(None)
            primary = True
        elif fields[0] == "sub":
            primary = False
        elif fields[0] == "fpr" and primary:
            fingerprints[-1] = fields[9]
            primary = False
    # Signing subkeys belong to the pinned certificate, not extra trust roots.
    if fingerprints != [FINGERPRINT]:
        raise ValueError(f"unexpected Docker signing primary certificates: {fingerprints}")


def main():
    assert platform.machine() == "x86_64", "the pinned Dakota fixture is amd64"
    with tempfile.TemporaryDirectory(prefix="chairlift-docker-packages-") as directory:
        root = Path(directory)
        key = root / "docker.asc"
        key.write_bytes(fetch("gpg"))
        validate_key(key)
        keyring = root / "docker.gpg"
        subprocess.run(["gpg", "--no-options", "--batch", "--homedir", str(root),
                        "--dearmor", "--output", str(keyring), str(key)], check=True)
        signed = root / "InRelease"
        signed.write_bytes(fetch("dists/bookworm/InRelease"))
        release = root / "Release"
        subprocess.run(["gpgv", "--keyring", str(keyring), "--output", str(release), str(signed)], check=True)
        checksum_lines = release.read_text().split("\nSHA256:\n", 1)[1].splitlines()
        index = "stable/binary-amd64/Packages.gz"
        expected = next(line.split()[0] for line in checksum_lines if len(line.split()) == 3 and line.split()[2] == index)
        data = verified(fetch("dists/bookworm/" + index), expected)
        candidates = {}
        for stanza in gzip.decompress(data).decode().split("\n\n"):
            fields = dict(line.split(": ", 1) for line in stanza.splitlines() if ": " in line and not line.startswith(" "))
            name = fields.get("Package")
            if name not in PACKAGES or fields.get("Architecture") != "amd64":
                continue
            # Docker's stable repository uses numeric upstream release versions.
            version = tuple(map(int, re.findall(r"\d+", fields["Version"])))
            if name not in candidates or version > candidates[name][0]:
                candidates[name] = version, fields
        assert set(candidates) == set(PACKAGES), f"missing Docker packages: {set(PACKAGES) - candidates.keys()}"
        manifest = []
        for name in PACKAGES:
            fields = candidates[name][1]
            package = root / (name + ".deb")
            package.write_bytes(verified(fetch(fields["Filename"]), fields["SHA256"]))
            members = subprocess.check_output(["ar", "t", str(package)], text=True).splitlines()
            payload = next(member for member in members if member.startswith("data.tar."))
            archive = root / payload
            with archive.open("wb") as stream:
                subprocess.run(["ar", "p", str(package), payload], stdout=stream, check=True)
            subprocess.run(["tar", "--extract", "--file", str(archive), "--directory", "/", "--keep-directory-symlink"], check=True)
            entry = {key: fields[key] for key in ("Package", "Version", "Filename", "SHA256")}
            names = subprocess.check_output(["tar", "--list", "--file", str(archive)], text=True).splitlines()
            entry["Files"] = ["/" + name.removeprefix("./") for name in names
                              if Path("/" + name.removeprefix("./")).is_file()]
            assert entry["Files"], f"empty package payload: {name}"
            manifest.append(entry)
        evidence = Path("/usr/share/chairlift-docker-fixture")
        evidence.mkdir(parents=True)
        (evidence / "packages.json").write_text(json.dumps(manifest, indent=2) + "\n")
        subprocess.run(["ldconfig"], check=True)


if __name__ == "__main__":
    main()
