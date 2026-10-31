#!/usr/bin/env python3
"""Verify temporary commit-pinned resolver Git checkouts and runtime inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


def sha256(path: Path) -> str:
  digest = hashlib.sha256()
  with path.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(block)
  return digest.hexdigest()


def is_pinned_git_url(value: object) -> bool:
  return isinstance(value, str) and re.fullmatch(
      r"https://github\.com/[^/]+/[^/]+\.git", value) is not None


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


def verify_source_checkouts(source_directory: Path, manifest_path: Path) -> None:
  manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
  verify_repo_overlays(manifest_path.parent, manifest)
  sources = manifest.get("sources")
  if not isinstance(sources, dict) or set(sources) != {"identity", "registry"}:
    raise RuntimeError("resolver manifest must lock Identity and Registry Git sources")
  if source_directory.is_symlink() or not source_directory.is_dir():
    raise RuntimeError("temporary resolver source directory is unavailable")

  packages = {"identity": "decent_identity", "registry": "decent_registry"}
  for name in ("identity", "registry"):
    source = sources[name]
    if not isinstance(source, dict):
      raise RuntimeError(f"Git source entry is invalid: {name}")
    commit = source.get("commit")
    git_url = source.get("git_url")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
      raise RuntimeError(f"source commit is invalid: {name}")
    if not is_pinned_git_url(git_url):
      raise RuntimeError(f"source Git URL is invalid: {name}")
    archive = source.get("archive_sha256")
    if archive is not None or "url" in source:
      raise RuntimeError(f"source lock must pin a Git commit, not an archive: {name}")
    checkout = source_directory / name
    if checkout.is_symlink() or not checkout.is_dir():
      raise RuntimeError(f"pinned source checkout is unavailable: {name}")
    if (checkout / ".git").exists():
      raise RuntimeError(f"temporary source context contains Git metadata: {name}")
    marker = checkout / ".pinned-commit"
    if marker.is_symlink() or not marker.is_file() or marker.read_text(encoding="ascii") != commit + "\n":
      raise RuntimeError(f"pinned commit marker mismatch: {name}")
    source_root = checkout / "src"
    package_root = source_root / packages[name]
    if source_root.is_symlink() or not source_root.is_dir() or not package_root.is_dir():
      raise RuntimeError(f"pinned source checkout is missing package source: {name}")

  if "wheelhouse" in manifest:
    # The wheelhouse is a third-party dependency bundle, separate from source checkouts.
    verify_wheelhouse_archive(manifest_path.parent, manifest_path)
  if "binary_dependency_provenance" in manifest:
    verify_binary_dependency_provenance(manifest_path.parent, manifest_path)


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


def _valid_source_url(value: object, *, host: str, filename: str, path_prefix: str) -> bool:
  if not isinstance(value, str):
    return False
  parsed = urlsplit(value)
  return (parsed.scheme == "https" and parsed.hostname == host and parsed.port is None
      and parsed.username is None and parsed.password is None and not parsed.query
      and not parsed.fragment and parsed.path.startswith(path_prefix)
      and PurePosixPath(parsed.path).name == filename)


def _locked_package_hashes(lock_file: Path) -> dict[tuple[str, str], set[str]]:
  """Map each exact package pin to only the hashes listed in its own lock block."""
  from pip._vendor.packaging.requirements import Requirement

  result: dict[tuple[str, str], set[str]] = {}
  current_key: tuple[str, str] | None = None
  current_hashes: set[str] = set()

  def finish_block() -> None:
    if current_key is not None:
      result.setdefault(current_key, set()).update(current_hashes)

  for raw_line in lock_file.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
      continue
    if line.startswith("--hash=sha256:"):
      if current_key is None:
        raise RuntimeError(f"package lock hash has no requirement: {lock_file.name}")
      current_hashes.update(re.findall(r"--hash=sha256:([0-9a-f]{64})", line))
      continue
    if line.startswith("--"):
      continue

    finish_block()
    current_hashes = set()
    requirement_text = line.removesuffix("\\").strip()
    try:
      requirement = Requirement(requirement_text)
    except Exception as error:
      raise RuntimeError(f"package lock requirement is invalid: {lock_file.name}") from error
    specifiers = list(requirement.specifier)
    if requirement.url is not None or len(specifiers) != 1 or specifiers[0].operator != "==":
      raise RuntimeError(f"package lock requirement is not an exact version pin: {lock_file.name}")
    normalized_name = re.sub(r"[-_.]+", "-", requirement.name).lower()
    current_key = (normalized_name, specifiers[0].version)

  finish_block()
  return result


def verify_binary_dependency_provenance(directory: Path, runtime_manifest_path: Path) -> None:
  """Verify the locked upstream identity and digest of every bundled binary input."""
  runtime_manifest = json.loads(runtime_manifest_path.read_text(encoding="utf-8"))
  entry = runtime_manifest.get("binary_dependency_provenance")
  if not isinstance(entry, dict):
    raise RuntimeError("resolver manifest must pin binary dependency provenance")
  inventory_name = entry.get("manifest")
  inventory_sha256 = entry.get("sha256")
  if not isinstance(inventory_name, str) or Path(inventory_name).name != inventory_name:
    raise RuntimeError("binary dependency inventory filename is invalid")
  if not isinstance(inventory_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", inventory_sha256) is None:
    raise RuntimeError("binary dependency inventory checksum is invalid")
  inventory_path = directory / inventory_name
  if not inventory_path.is_file() or sha256(inventory_path) != inventory_sha256:
    raise RuntimeError("binary dependency inventory checksum mismatch")
  inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
  if inventory.get("schema_version") != 1:
    raise RuntimeError("binary dependency inventory schema is unsupported")
  if inventory.get("python_distribution_index") != "https://pypi.org/simple":
    raise RuntimeError("Python dependency source must be the pinned PyPI index")
  if inventory.get("target") != {
      "python_version": runtime_manifest["python"]["version"],
      "platform": runtime_manifest["python"]["platform"],
      "runtime_abi": runtime_manifest["python"]["runtime_abi"],
  }:
    raise RuntimeError("binary dependency target does not match the resolver runtime")

  wheelhouse = inventory.get("wheelhouse")
  if not isinstance(wheelhouse, dict):
    raise RuntimeError("binary dependency inventory must describe the wheelhouse")
  archive_name = wheelhouse.get("archive")
  archive_sha256 = wheelhouse.get("archive_sha256")
  artifact_count = wheelhouse.get("artifact_count")
  artifacts = wheelhouse.get("artifacts")
  main_wheelhouse = runtime_manifest.get("wheelhouse")
  if not isinstance(main_wheelhouse, dict) or archive_name != main_wheelhouse.get("archive"):
    raise RuntimeError("binary dependency inventory wheelhouse does not match runtime lock")
  if archive_sha256 != main_wheelhouse.get("archive_sha256"):
    raise RuntimeError("binary dependency inventory archive checksum does not match runtime lock")
  if not isinstance(archive_name, str) or Path(archive_name).name != archive_name:
    raise RuntimeError("binary dependency wheelhouse archive name is invalid")
  if not isinstance(archive_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", archive_sha256) is None:
    raise RuntimeError("binary dependency wheelhouse checksum is invalid")
  if not isinstance(artifacts, list) or not isinstance(artifact_count, int) \
      or isinstance(artifact_count, bool) or artifact_count != len(artifacts):
    raise RuntimeError("binary dependency artifact count is invalid")

  lock_files = (directory / runtime_manifest["runtime_requirements"]["lock"],
      directory / "resolver-build-requirements.lock.txt")
  package_hashes: dict[tuple[str, str], set[str]] = {}
  for lock_file in lock_files:
    for identity, hashes in _locked_package_hashes(lock_file).items():
      package_hashes.setdefault(identity, set()).update(hashes)
  archive = directory / archive_name
  if not archive.is_file() or sha256(archive) != archive_sha256:
    raise RuntimeError("wheelhouse archive checksum mismatch")
  verified_artifacts = {}
  try:
    with tarfile.open(archive, "r:gz") as bundle:
      for member in bundle.getmembers():
        if not member.isfile():
          continue
        filename = PurePosixPath(member.name).name
        if filename in verified_artifacts:
          raise RuntimeError("wheelhouse contains duplicate artifact filenames")
        stream = bundle.extractfile(member)
        if stream is None:
          raise RuntimeError("wheelhouse artifact could not be read")
        digest = hashlib.sha256(stream.read()).hexdigest()
        verified_artifacts[filename] = digest
  except (OSError, tarfile.TarError) as error:
    raise RuntimeError("wheelhouse archive is invalid") from error

  expected_artifacts = {}
  for artifact in artifacts:
    if not isinstance(artifact, dict):
      raise RuntimeError("binary dependency artifact entry is invalid")
    filename = artifact.get("filename")
    digest = artifact.get("sha256")
    package = artifact.get("package")
    version = artifact.get("version")
    if not isinstance(filename, str) or Path(filename).name != filename:
      raise RuntimeError("binary dependency artifact filename is invalid")
    if not isinstance(package, str) or not package or not isinstance(version, str) or not version:
      raise RuntimeError("binary dependency artifact identity is invalid")
    if filename.endswith(".whl"):
      wheel_parts = filename[:-4].split("-")
      actual_package = wheel_parts[0].replace("_", "-").lower() if len(wheel_parts) >= 5 else ""
      actual_version = wheel_parts[1] if len(wheel_parts) >= 5 else ""
    elif filename.endswith(".tar.gz"):
      stem = filename[:-7]
      actual_package, separator, actual_version = stem.rpartition("-")
      actual_package = actual_package.replace("_", "-").lower() if separator else ""
    else:
      actual_package = actual_version = ""
    if actual_package != re.sub(r"[-_.]+", "-", package).lower() or actual_version != version:
      raise RuntimeError(f"binary dependency filename does not match its locked package version: {filename}")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
      raise RuntimeError("binary dependency artifact checksum is invalid")
    identity = (re.sub(r"[-_.]+", "-", package).lower(), version)
    if digest not in package_hashes.get(identity, set()):
      raise RuntimeError(f"binary dependency checksum is not in the hash lock for {package}=={version}")
    if not _valid_source_url(artifact.get("url"), host="files.pythonhosted.org",
        filename=filename, path_prefix="/packages/"):
      raise RuntimeError(f"binary dependency source URL is invalid: {filename}")
    if filename in expected_artifacts:
      raise RuntimeError("binary dependency inventory contains duplicate filenames")
    expected_artifacts[filename] = digest
  if len(expected_artifacts) != artifact_count or verified_artifacts != expected_artifacts:
    raise RuntimeError("wheelhouse contents do not match the binary dependency inventory")

  rpms = inventory.get("rpms")
  if not isinstance(rpms, list) or len(rpms) != 2 or any(not isinstance(item, dict) for item in rpms):
    raise RuntimeError("binary dependency inventory must lock the cpio and gmp-devel RPMs")
  if {item.get("package") for item in rpms} != {"cpio", "gmp-devel"}:
    raise RuntimeError("binary dependency inventory must lock the cpio and gmp-devel RPMs")
  expected_rpms = {
      "cpio": ("cpio-2.13-16.el9.x86_64.rpm", "2.13-16.el9"),
      "gmp-devel": ("gmp-devel-6.2.0-13.el9.x86_64.rpm", "6.2.0-13.el9"),
  }
  for rpm in rpms:
    filename = rpm.get("filename")
    digest = rpm.get("sha256")
    package = rpm.get("package")
    if not isinstance(filename, str) or Path(filename).name != filename:
      raise RuntimeError("RPM filename is invalid")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
      raise RuntimeError(f"RPM checksum is invalid: {filename}")
    if not isinstance(rpm.get("version"), str) or not rpm["version"]:
      raise RuntimeError(f"RPM version is invalid: {filename}")
    if (not isinstance(package, str) or package not in expected_rpms
        or expected_rpms[package] != (filename, rpm["version"])):
      raise RuntimeError(f"RPM package/version does not match the supported dependency lock: {filename}")
    if not _valid_source_url(rpm.get("url"), host="cdn-ubi.redhat.com",
        filename=filename, path_prefix="/content/public/ubi/dist/ubi9/9/x86_64/"):
      raise RuntimeError(f"RPM source URL is invalid: {filename}")
    artifact_path = directory / filename
    if artifact_path.is_symlink() or not artifact_path.is_file() or sha256(artifact_path) != digest:
      raise RuntimeError(f"RPM checksum mismatch: {filename}")
    if package == "gmp-devel":
      gmp_lock = runtime_manifest.get("gmp")
      if not isinstance(gmp_lock, dict) or (gmp_lock.get("version"),
          gmp_lock.get("devel_rpm_url"), gmp_lock.get("devel_rpm_sha256")) != (
              rpm.get("version"), rpm.get("url"), digest):
        raise RuntimeError("gmp-devel provenance does not match the runtime lock")


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--sources", type=Path, required=True,
      help="temporary directory containing pinned identity and registry Git checkouts")
  parser.add_argument("--manifest", type=Path,
      default=Path(__file__).resolve().with_name("resolver-runtime.lock.json"),
      help="resolver source and dependency lock manifest")
  args = parser.parse_args()
  verify_source_checkouts(args.sources, args.manifest)
  print("resolver_git_sources_verified")
  if "wheelhouse" in json.loads(args.manifest.read_text(encoding="utf-8")):
    print("resolver_wheelhouse_archive_verified")


if __name__ == "__main__":
  main()
