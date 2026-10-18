#!/usr/bin/env python3
"""Validate the pinned resolver inputs consumed by the container build."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "container/resolver-runtime.lock.json"
RUNTIME_REQUIREMENTS = ROOT / "container/resolver-requirements.lock.txt"
REGISTRY_CONSTRAINTS = ROOT / "container/registry-lock-constraints.txt"
IDENTITY_SOURCE = ROOT / "container/identity-src"
REGISTRY_SOURCE = ROOT / "container/registry-src"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_download(url: str, expected_sha256: str, destination: Path) -> None:
    with urllib.request.urlopen(url, timeout=60) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)
    actual = sha256(destination)
    if actual != expected_sha256:
        raise RuntimeError(f"download checksum mismatch: {destination.name}")


def extract_pinned_archive(archive: Path, destination: Path, expected_commit: str) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members or any(member.issym() or member.islnk() for member in members):
            raise RuntimeError("source archive must contain regular files only")
        roots = {member.name.split("/", 1)[0] for member in members}
        expected_root = next(iter(roots))
        if len(roots) != 1 or expected_commit not in expected_root:
            raise RuntimeError("source archive root does not match locked revision")
        for member in members:
            relative = Path(member.name).relative_to(expected_root)
            target = (destination / relative).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise RuntimeError("source archive path escaped extraction root")
            if member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise RuntimeError("source archive member could not be read")
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode & 0o755)
            elif member.isdir():
                target.mkdir(parents=True, exist_ok=True)


def validate_repo_owned_lock() -> dict:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    checks = (
        (RUNTIME_REQUIREMENTS, lock["runtime_requirements"]["lock_sha256"]),
        (REGISTRY_CONSTRAINTS, lock["registry_dependency_lock"]["registry_lock_constraints_sha256"]),
    )
    for path, expected in checks:
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or sha256(path) != expected:
            raise RuntimeError(f"repository lock checksum mismatch: {path.name}")
    for source in lock["sources"].values():
        if not re.fullmatch(r"[0-9a-f]{40}", source["commit"]):
            raise RuntimeError("source revision is not a full immutable commit")
        if not source["url"].startswith("https://github.com/"):
            raise RuntimeError("source archive must use HTTPS GitHub URL")
    return lock


def materialize_sources(downloads: Path) -> None:
    lock = validate_repo_owned_lock()
    for name, destination in (("identity", IDENTITY_SOURCE), ("registry", REGISTRY_SOURCE)):
        source = lock["sources"][name]
        archive = downloads / f"{name}.tar.gz"
        if archive.exists() and sha256(archive) == source["archive_sha256"]:
            pass
        else:
            archive.unlink(missing_ok=True)
            checked_download(source["url"], source["archive_sha256"], archive)
        shutil.rmtree(destination, ignore_errors=True)
        extract_pinned_archive(archive, destination, source["commit"])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate pinned resolver source/dependency inputs used by container/Dockerfile")
    parser.add_argument("--materialize-sources", action="store_true",
        help="download checksum-verified pinned source archives into repository input directories")
    parser.add_argument("--downloads", type=Path, default=ROOT / ".cache/resolver-downloads",
        help="directory for pinned source archives (default: repository .cache/resolver-downloads)")
    parser.add_argument("--extract-source", nargs=3, metavar=("NAME", "ARCHIVE", "DESTINATION"),
        help="verify and extract one pinned Identity/Registry source archive")
    args = parser.parse_args()
    if args.extract_source is not None:
        name, archive, destination = args.extract_source
        lock = validate_repo_owned_lock()
        if name not in lock["sources"]:
            raise SystemExit("unknown pinned source name")
        entry = lock["sources"][name]
        if sha256(Path(archive)) != entry["archive_sha256"]:
            raise SystemExit("pinned source archive checksum mismatch")
        extract_pinned_archive(Path(archive), Path(destination), entry["commit"])
        return
    if args.materialize_sources:
        args.downloads.mkdir(parents=True, exist_ok=True)
        materialize_sources(args.downloads)
    lock = validate_repo_owned_lock()
    print(json.dumps({
        "status": "resolver_inputs_verified",
        "builder": "container/Dockerfile",
        "identity_commit": lock["sources"]["identity"]["commit"],
        "registry_commit": lock["sources"]["registry"]["commit"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
