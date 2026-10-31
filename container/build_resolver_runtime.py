#!/usr/bin/env python3
"""Verify resolver locks and materialize temporary commit-pinned Git checkouts."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "container/resolver-runtime.lock.json"
RUNTIME_REQUIREMENTS = ROOT / "container/resolver-requirements.lock.txt"
REGISTRY_CONSTRAINTS = ROOT / "container/registry-lock-constraints.txt"
SOURCE_NAMES = ("identity", "registry")


def sha256(path: Path) -> str:
  digest = hashlib.sha256()
  with path.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(block)
  return digest.hexdigest()


def validate_repo_owned_lock() -> dict:
  lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
  checks = (
      (RUNTIME_REQUIREMENTS, lock["runtime_requirements"]["lock_sha256"]),
      (REGISTRY_CONSTRAINTS, lock["registry_dependency_lock"]["registry_lock_constraints_sha256"]),
  )
  for path, expected in checks:
    if (not isinstance(expected, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        or sha256(path) != expected):
      raise RuntimeError(f"repository lock checksum mismatch: {path.name}")
  sources = lock.get("sources")
  if not isinstance(sources, dict) or set(sources) != set(SOURCE_NAMES):
    raise RuntimeError("resolver manifest must lock Identity and Registry Git sources")

  from verify_resolver_runtime_inputs import (
      is_pinned_git_url,
      verify_repo_overlays,
      verify_binary_dependency_provenance,
      verify_wheelhouse_archive,
  )

  for name in SOURCE_NAMES:
    source = sources[name]
    if not isinstance(source, dict):
      raise RuntimeError(f"Git source lock is invalid: {name}")
    commit = source.get("commit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
      raise RuntimeError(f"source revision is not a full immutable commit: {name}")
    if not is_pinned_git_url(source.get("git_url")):
      raise RuntimeError(f"source URL is not an HTTPS GitHub repository: {name}")
    if "archive_sha256" in source or "url" in source:
      raise RuntimeError(f"source lock must pin a Git commit, not an archive: {name}")

  verify_repo_overlays(LOCK_PATH.parent, lock)
  verify_wheelhouse_archive(LOCK_PATH.parent, LOCK_PATH)
  verify_binary_dependency_provenance(LOCK_PATH.parent, LOCK_PATH)
  return lock


def _git(args: list[str], cwd: Path) -> str:
  result = subprocess.run(["git", *args], cwd=cwd, text=True,
      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  if result.returncode:
    raise RuntimeError("pinned resolver Git checkout failed")
  return result.stdout.strip()


def clone_pinned_source(git_url: str, commit: str, destination: Path) -> Path:
  """Create one fresh shallow checkout and retain only its source tree."""
  destination = Path(destination)
  if destination.is_symlink() or destination.exists():
    raise RuntimeError("source checkout destination must be new")
  if not re.fullmatch(r"[0-9a-f]{40}", commit):
    raise RuntimeError("source revision is not a full immutable commit")
  destination.parent.mkdir(parents=True, exist_ok=True)
  destination.mkdir(mode=0o700)
  try:
    _git(["init", "--quiet"], destination)
    _git(["remote", "add", "origin", git_url], destination)
    _git(["fetch", "--quiet", "--depth=1", "--filter=blob:none", "origin", commit], destination)
    _git(["checkout", "--quiet", "--detach", "FETCH_HEAD"], destination)
    actual = _git(["rev-parse", "HEAD"], destination)
    if actual != commit:
      raise RuntimeError("Git checkout did not resolve to the locked commit")
    tree = _git(["ls-tree", "-r", "HEAD"], destination)
    if any(line.startswith("160000 commit ") for line in tree.splitlines()):
      raise RuntimeError("pinned source commit must not require Git submodules")
    if _git(["status", "--porcelain", "--untracked-files=all"], destination):
      raise RuntimeError("pinned Git checkout is not clean")
    source_tree = destination / "src"
    if source_tree.is_symlink() or not source_tree.is_dir():
      raise RuntimeError("pinned Git checkout has no source tree")
    if any(path.is_symlink() for path in source_tree.rglob("*")):
      raise RuntimeError("pinned source tree must not contain symlinks")
    git_metadata = destination / ".git"
    if git_metadata.is_symlink() or not git_metadata.is_dir():
      raise RuntimeError("temporary Git clone metadata is invalid")
    shutil.rmtree(git_metadata)
    for entry in destination.iterdir():
      if entry.name == "src":
        continue
      if entry.is_symlink() or not entry.is_dir():
        entry.unlink()
      else:
        shutil.rmtree(entry)
    marker = destination / ".pinned-commit"
    if marker.exists() or marker.is_symlink():
      raise RuntimeError("source checkout contains a reserved commit marker")
    marker.write_text(commit + "\n", encoding="ascii")
    return destination
  except BaseException:
    shutil.rmtree(destination, ignore_errors=True)
    raise


def materialize_sources(source_directory: Path) -> Path:
  """Clone locked sources into a caller-owned temporary directory; never overwrite it."""
  requested = Path(source_directory).expanduser()
  if requested.is_symlink() or requested.exists():
    raise RuntimeError("source directory must be a new temporary directory")
  destination = requested.resolve()
  if destination == ROOT.resolve() or ROOT.resolve() in destination.parents:
    raise RuntimeError("temporary source directory must be outside the repository")
  lock = validate_repo_owned_lock()
  destination.parent.mkdir(parents=True, exist_ok=True)
  destination.mkdir(mode=0o700)
  try:
    for name in SOURCE_NAMES:
      source = lock["sources"][name]
      clone_pinned_source(source["git_url"], source["commit"], destination / name)
  except BaseException:
    shutil.rmtree(destination, ignore_errors=True)
    raise
  return destination


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--materialize-sources", action="store_true",
      help="shallow-clone the locked Identity and Registry commits into a new temporary directory")
  parser.add_argument("--sources-directory", type=Path,
      help="new temporary directory for source checkouts (required with --materialize-sources)")
  args = parser.parse_args()
  if args.materialize_sources:
    if args.sources_directory is None:
      parser.error("--sources-directory is required with --materialize-sources")
    source_directory = materialize_sources(args.sources_directory)
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    print(json.dumps({
        "status": "resolver_git_sources_materialized",
        "source_directory": str(source_directory),
        "identity_commit": lock["sources"]["identity"]["commit"],
        "registry_commit": lock["sources"]["registry"]["commit"],
    }, sort_keys=True))
    return
  if args.sources_directory is not None:
    parser.error("--sources-directory requires --materialize-sources")
  lock = validate_repo_owned_lock()
  print(json.dumps({
      "status": "resolver_inputs_verified",
      "builder": "container/Dockerfile",
      "identity_commit": lock["sources"]["identity"]["commit"],
      "registry_commit": lock["sources"]["registry"]["commit"],
  }, sort_keys=True))


if __name__ == "__main__":
  main()
