#!/usr/bin/env python3
"""Verify source archives against the resolver runtime manifest before extraction."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path


def sha256(path: Path) -> str:
  digest = hashlib.sha256()
  with path.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(block)
  return digest.hexdigest()


def verify_source_archives(archive_directory: Path, manifest_path: Path) -> None:
  manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
  sources = manifest.get("sources")
  if not isinstance(sources, dict) or set(sources) != {"identity", "registry"}:
    raise RuntimeError("resolver manifest must lock Identity and Registry sources")

  for name in ("identity", "registry"):
    source = sources[name]
    commit = source.get("commit")
    expected_hash = source.get("archive_sha256")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
      raise RuntimeError(f"source commit is invalid: {name}")
    if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
      raise RuntimeError(f"source archive checksum is invalid: {name}")

    archive = archive_directory / f"{name}.tar.gz"
    if sha256(archive) != expected_hash:
      raise RuntimeError(f"source archive checksum mismatch: {name}")

    with tarfile.open(archive, "r:gz") as bundle:
      members = bundle.getmembers()
    if not members or any(member.issym() or member.islnk() for member in members):
      raise RuntimeError(f"source archive must contain regular files only: {name}")
    roots = {member.name.split("/", 1)[0] for member in members}
    if len(roots) != 1:
      raise RuntimeError(f"source archive contains multiple roots: {name}")
    root = next(iter(roots))
    if commit not in root:
      raise RuntimeError(f"source archive root does not match locked commit: {name}")
    for member in members:
      relative = Path(member.name).relative_to(root)
      if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"source archive path escaped extraction root: {name}")
      if not (member.isfile() or member.isdir()):
        raise RuntimeError(f"source archive contains an unsupported entry: {name}")


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--archives", type=Path, default=Path(__file__).resolve().parent,
      help="directory containing identity.tar.gz and registry.tar.gz")
  parser.add_argument("--manifest", type=Path,
      default=Path(__file__).resolve().with_name("resolver-runtime.lock.json"),
      help="resolver source and dependency lock manifest")
  args = parser.parse_args()
  verify_source_archives(args.archives, args.manifest)
  print("resolver_source_archives_verified")


if __name__ == "__main__":
  main()
