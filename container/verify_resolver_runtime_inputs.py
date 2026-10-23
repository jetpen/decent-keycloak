#!/usr/bin/env python3
"""Verify source archives against the resolver runtime manifest before extraction."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath


def sha256(path: Path) -> str:
  digest = hashlib.sha256()
  with path.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(block)
  return digest.hexdigest()


def verify_repo_overlays(directory: Path, manifest: dict) -> None:
  overlays = manifest.get("repo_overlays")
  if not isinstance(overlays, dict) or set(overlays) != {"pinned_lookup_outcomes", "runtime_patcher"}:
    raise RuntimeError("resolver manifest must lock the repository-owned runtime overlays")
  for name, entry in overlays.items():
    if not isinstance(entry, dict):
      raise RuntimeError(f"resolver overlay entry is invalid: {name}")
    filename = entry.get("file")
    expected_hash = entry.get("sha256")
    if not isinstance(filename, str) or Path(filename).name != filename:
      raise RuntimeError(f"resolver overlay filename is invalid: {name}")
    if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
      raise RuntimeError(f"resolver overlay checksum is invalid: {name}")
    overlay_path = directory / filename
    if not overlay_path.is_file() or sha256(overlay_path) != expected_hash:
      raise RuntimeError(f"resolver overlay checksum mismatch: {name}")


def verify_source_archives(archive_directory: Path, manifest_path: Path) -> None:
  manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
  verify_repo_overlays(manifest_path.parent, manifest)
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

  if "wheelhouse" in manifest:
    # --archives selects the Identity/Registry inputs; the wheelhouse is locked beside its manifest.
    verify_wheelhouse_archive(manifest_path.parent, manifest_path)


def verify_wheelhouse_archive(archive_directory: Path, manifest_path: Path) -> None:
  manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
  entry = manifest.get("wheelhouse")
  if not isinstance(entry, dict):
    raise RuntimeError("resolver manifest must lock the wheelhouse archive")
  archive_name = entry.get("archive")
  expected_hash = entry.get("archive_sha256")
  file_count = entry.get("file_count")
  if not isinstance(archive_name, str) or Path(archive_name).name != archive_name:
    raise RuntimeError("wheelhouse archive name is invalid")
  if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
    raise RuntimeError("wheelhouse archive checksum is invalid")
  if not isinstance(file_count, int) or isinstance(file_count, bool) or file_count < 1:
    raise RuntimeError("wheelhouse archive file count is invalid")

  archive = archive_directory / archive_name
  if not archive.is_file() or sha256(archive) != expected_hash:
    raise RuntimeError("wheelhouse archive checksum mismatch")
  try:
    with tarfile.open(archive, "r:gz") as bundle:
      members = bundle.getmembers()
  except (OSError, tarfile.TarError) as error:
    raise RuntimeError("wheelhouse archive is invalid") from error
  if not members or any(member.issym() or member.islnk() for member in members):
    raise RuntimeError("wheelhouse archive must contain regular files only")
  files = 0
  members_by_path = {}
  for member in members:
    relative = PurePosixPath(member.name)
    if relative.is_absolute() or ".." in relative.parts:
      raise RuntimeError("wheelhouse archive path escaped extraction root")
    parts = tuple(part for part in relative.parts if part not in ("", "."))
    if not parts:
      if not member.isdir() or "." in members_by_path:
        raise RuntimeError("wheelhouse archive contains a duplicate normalized path")
      members_by_path["."] = "directory"
      continue
    normalized = "/".join(parts)
    if normalized in members_by_path:
      raise RuntimeError("wheelhouse archive contains a duplicate normalized path")
    for parent_length in range(1, len(parts)):
      parent = "/".join(parts[:parent_length])
      if members_by_path.get(parent) == "file":
        raise RuntimeError("wheelhouse archive contains a file/directory path collision")
    if member.isfile():
      if any(path.startswith(normalized + "/") for path in members_by_path):
        raise RuntimeError("wheelhouse archive contains a file/directory path collision")
      members_by_path[normalized] = "file"
      files += 1
      if not (member.name.endswith(".whl") or member.name.endswith(".tar.gz")):
        raise RuntimeError("wheelhouse archive contains an unsupported artifact")
    elif member.isdir():
      members_by_path[normalized] = "directory"
    else:
      raise RuntimeError("wheelhouse archive contains an unsupported entry")
  if files != file_count:
    raise RuntimeError("wheelhouse archive file count mismatch")


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
  if "wheelhouse" in json.loads(args.manifest.read_text(encoding="utf-8")):
    print("resolver_wheelhouse_archive_verified")


if __name__ == "__main__":
  main()
