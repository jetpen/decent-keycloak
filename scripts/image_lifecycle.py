"""Safe local retention for images built by decent-keycloak.

Repository-owned images are opt-in cleanup candidates only when their exact
repository label is present. Upstream bases and builder caches are never swept.
"""

from datetime import datetime, timedelta, timezone
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

REPOSITORY_LABELS = {
    "io.decent.image.repository": "https://github.com/jetpen/decent-keycloak",
    "io.decent.image.component": "decent-keycloak",
}
IMAGE_PREFIX = "localhost/decent-keycloak/wallet-provider"
DEFAULT_RETENTION_DAYS = 3
MAX_RETENTION_DAYS = 3650
IMAGE_ROLES = {
    "resolver-builder",
    "keycloak-with-resolver",
    "wallet-provider",
    "wallet-provider-issue7-user-readback-test",
    "wallet-provider-issue7-store-recovery-test",
    "wallet-provider-issue6-postconsume-test",
    "wallet-provider-issue6-callback-gate-test",
}


def _run(engine, *arguments, check=True):
  result = subprocess.run([engine, *arguments], text=True, capture_output=True, check=False)
  if check and result.returncode:
    raise RuntimeError("container_engine_command_failed")
  return result


def selected_engine(engine=None):
  engine = engine or os.environ.get("CONTAINER_ENGINE")
  if engine is None:
    engine = "podman" if shutil.which("podman") else "docker" if shutil.which("docker") else ""
  if engine not in {"podman", "docker"}:
    raise ValueError("select Podman or Docker as the container engine")
  return engine


def _normalize_id(value):
  value = value.strip()
  if re.fullmatch(r"[0-9a-f]{64}", value):
    return "sha256:" + value
  if re.fullmatch(r"sha256:[0-9a-f]{64}", value):
    return value
  return None


def _metadata(engine, image):
  result = _run(engine, "image", "inspect", image, check=False)
  if result.returncode:
    return None
  try:
    payload = json.loads(result.stdout)
  except json.JSONDecodeError as error:
    raise RuntimeError("image_inspect_invalid") from error
  if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
    raise RuntimeError("image_inspect_invalid")
  metadata = payload[0]
  image_id = _normalize_id(str(metadata.get("Id", "")))
  if image_id is None:
    raise RuntimeError("image_id_invalid")
  metadata["Id"] = image_id
  return metadata


def _labels(metadata):
  config = metadata.get("Config")
  labels = config.get("Labels") if isinstance(config, dict) else None
  return labels if isinstance(labels, dict) else {}


def _is_repository_image(metadata):
  labels = _labels(metadata)
  role = labels.get("io.decent.image.role")
  return (all(labels.get(key) == value for key, value in REPOSITORY_LABELS.items())
      and isinstance(role, str) and role in IMAGE_ROLES)


def _image_ids(engine):
  result = _run(engine, "image", "ls", "--all", "--no-trunc", "--quiet")
  ids = {_normalize_id(line.strip()) for line in result.stdout.splitlines() if line.strip()}
  if None in ids:
    raise RuntimeError("image_inventory_id_invalid")
  return ids


def image_inventory(engine):
  result = _run(engine, "image", "ls", "--all", "--no-trunc", "--quiet",
      "--filter", f"label=io.decent.image.repository={REPOSITORY_LABELS['io.decent.image.repository']}",
      "--filter", f"label=io.decent.image.component={REPOSITORY_LABELS['io.decent.image.component']}")
  ids = {_normalize_id(line.strip()) for line in result.stdout.splitlines() if line.strip()}
  if None in ids:
    raise RuntimeError("image_inventory_id_invalid")
  metadata = []
  for image_id in sorted(ids):
    item = _metadata(engine, image_id)
    if item is None:
      raise RuntimeError("image_inventory_inspect_unavailable")
    metadata.append(item)
  return metadata


def active_image_ids(engine):
  result = _run(engine, "ps", "--all", "--no-trunc", "--quiet")
  active = set()
  for container_id in result.stdout.splitlines():
    if not container_id.strip():
      continue
    inspected = _run(engine, "container", "inspect", container_id, check=False)
    if inspected.returncode:
      raise RuntimeError("active_container_inventory_unavailable")
    try:
      payload = json.loads(inspected.stdout)
      if (not isinstance(payload, list) or len(payload) != 1
          or not isinstance(payload[0], dict)):
        raise RuntimeError("active_container_inventory_invalid")
      image_id = _normalize_id(str(payload[0].get("Image", "")))
      if image_id is None:
        raise RuntimeError("active_container_inventory_invalid")
      active.add(image_id)
    except json.JSONDecodeError as error:
      raise RuntimeError("active_container_inventory_invalid") from error
  return active


def _created_at(metadata):
  raw = metadata.get("Created")
  if not isinstance(raw, str):
    raise RuntimeError("image_created_timestamp_missing")
  try:
    created = datetime.fromisoformat(raw.replace("Z", "+00:00"))
  except ValueError as error:
    raise RuntimeError("image_created_timestamp_invalid") from error
  if created.tzinfo is None:
    raise RuntimeError("image_created_timestamp_timezone_missing")
  return created.astimezone(timezone.utc)


def _tags(metadata):
  tags = metadata.get("RepoTags")
  return tags if isinstance(tags, list) else []


def _retained_until(metadata):
  result = None
  for tag in _tags(metadata):
    prefix = IMAGE_PREFIX + ":retain-until-"
    suffix = tag[len(prefix):] if isinstance(tag, str) and tag.startswith(prefix) else ""
    if not suffix:
      continue
    try:
      expiry = datetime.strptime(suffix, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
      continue
    result = max(result, expiry) if result else expiry
  return result


def _is_pinned(metadata):
  prefix = IMAGE_PREFIX + ":pin-"
  return any(isinstance(tag, str) and tag.startswith(prefix) for tag in _tags(metadata))


def cleanup_images(engine, *, max_age_days=DEFAULT_RETENTION_DAYS, now=None):
  if not isinstance(max_age_days, int) or not 1 <= max_age_days <= MAX_RETENTION_DAYS:
    raise ValueError(f"retention days must be between 1 and {MAX_RETENTION_DAYS}")
  now = now or datetime.now(timezone.utc)
  if now.tzinfo is None:
    raise ValueError("now must include a timezone")
  now = now.astimezone(timezone.utc)
  active = active_image_ids(engine)
  cutoff = now - timedelta(days=max_age_days)
  removed = []
  kept_recent = kept_pinned = kept_extended = kept_active = 0
  for metadata in image_inventory(engine):
    if not _is_repository_image(metadata):
      continue
    image_id = metadata["Id"]
    if image_id in active:
      kept_active += 1
      continue
    if _is_pinned(metadata):
      kept_pinned += 1
      continue
    expires = _retained_until(metadata)
    if expires and expires > now:
      kept_extended += 1
      continue
    created = _created_at(metadata)
    if created > cutoff:
      kept_recent += 1
      continue
    # Re-read the exact immutable ID and its owner label immediately before
    # deletion; never delete by a mutable tag or from a broad engine prune.
    current = _metadata(engine, image_id)
    if current is None or current["Id"] != image_id or not _is_repository_image(current):
      raise RuntimeError("image_ownership_readback_failed")
    if image_id in active_image_ids(engine):
      kept_active += 1
      continue
    if _is_pinned(current) or (_retained_until(current) and _retained_until(current) > now):
      kept_pinned += 1
      continue
    if _created_at(current) > cutoff:
      kept_recent += 1
      continue
    if not remove_image(engine, image_id, now=now, cutoff=cutoff):
      raise RuntimeError("image_removal_failed")
    removed.append(image_id)
  return {"removed_ids": removed, "kept_recent": kept_recent,
      "kept_pinned": kept_pinned, "kept_extended": kept_extended,
      "kept_active": kept_active}


def resolve_image_id(engine, image):
  metadata = _metadata(engine, image)
  if metadata is None:
    raise ValueError("image does not exist")
  if not _is_repository_image(metadata):
    raise ValueError("image is not labeled as a decent-keycloak provider image")
  return metadata["Id"]


def tag_image(engine, image_id, tag):
  _run(engine, "image", "tag", image_id, tag)
  expected_id = _normalize_id(str(image_id))
  current = _metadata(engine, expected_id) if expected_id else None
  if current is None or current["Id"] != expected_id or tag not in _tags(current):
    raise RuntimeError("retention_tag_readback_failed")


def remove_image(engine, image_id, *, now=None, cutoff=None):
  current = _metadata(engine, image_id)
  if current is None or current["Id"] != image_id or not _is_repository_image(current):
    raise RuntimeError("image_ownership_readback_failed")
  now = now or datetime.now(timezone.utc)
  cutoff = cutoff or (now - timedelta(days=DEFAULT_RETENTION_DAYS))
  expiry = _retained_until(current)
  if _is_pinned(current) or (expiry is not None and expiry > now) or _created_at(current) > cutoff:
    return False
  if image_id in active_image_ids(engine):
    raise RuntimeError("image_became_active")
  result = _run(engine, "image", "rm", image_id, check=False)
  if result.returncode:
    return False
  return image_id not in _image_ids(engine)


def _pin_name(name):
  if not isinstance(name, str) or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", name) is None:
    raise ValueError("pin name must contain only letters, digits, dot, underscore, or hyphen")
  return name


def pin_image(engine, image, name):
  name = _pin_name(name)
  image_id = resolve_image_id(engine, image)
  tag_image(engine, image_id, f"{IMAGE_PREFIX}:pin-{name}")


def unpin_image(engine, image, name):
  name = _pin_name(name)
  image_id = resolve_image_id(engine, image)
  tag = f"{IMAGE_PREFIX}:pin-{name}"
  metadata = _metadata(engine, tag)
  if metadata is None:
    raise ValueError("pin does not exist")
  if metadata["Id"] != image_id:
    raise ValueError("pin references a different immutable image")
  _run(engine, "image", "rm", tag)
  current = _metadata(engine, image_id)
  if current is None or tag in _tags(current):
    raise RuntimeError("retention_tag_removal_readback_failed")


def extend_image(engine, image, days, *, now=None):
  if not isinstance(days, int) or not 1 <= days <= MAX_RETENTION_DAYS:
    raise ValueError(f"extension days must be between 1 and {MAX_RETENTION_DAYS}")
  now = now or datetime.now(timezone.utc)
  if now.tzinfo is None:
    raise ValueError("now must include a timezone")
  expiry = now.astimezone(timezone.utc) + timedelta(days=days)
  image_id = resolve_image_id(engine, image)
  tag_image(engine, image_id, f"{IMAGE_PREFIX}:retain-until-{expiry:%Y%m%dT%H%M%SZ}")


def main(argv=None):
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--engine", choices=("podman", "docker"), help="container engine (default: CONTAINER_ENGINE, then Podman/Docker)")
  actions = parser.add_subparsers(dest="action", required=True)
  cleanup = actions.add_parser("cleanup", help="remove expired, inactive repository-built images only")
  cleanup.add_argument("--max-age-days", type=int,
      default=os.environ.get("DECENT_IMAGE_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS)))
  pin = actions.add_parser("pin", help="create a named local retention pin")
  pin.add_argument("image")
  pin.add_argument("name")
  unpin = actions.add_parser("unpin", help="remove a named local retention pin")
  unpin.add_argument("image")
  unpin.add_argument("name")
  extend = actions.add_parser("extend", help="extend local retention for a bounded number of days")
  extend.add_argument("image")
  extend.add_argument("days", type=int)
  args = parser.parse_args(argv)
  try:
    engine = selected_engine(args.engine)
    if args.action == "cleanup":
      result = cleanup_images(engine, max_age_days=args.max_age_days)
      print(json.dumps({"status": "pass", **result}, sort_keys=True))
    elif args.action == "pin":
      pin_image(engine, args.image, args.name)
      print("pin=created")
    elif args.action == "unpin":
      unpin_image(engine, args.image, args.name)
      print("pin=removed")
    else:
      extend_image(engine, args.image, args.days)
      print("retention=extended")
    return 0
  except (OSError, RuntimeError, ValueError) as error:
    print(f"image lifecycle failed: {type(error).__name__}: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(main())
