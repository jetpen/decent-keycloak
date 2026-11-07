#!/usr/bin/env python3
"""Transfer the newest local qualification candidate to the configured remote test host."""

import os
import re
import subprocess
import sys

IMAGE_REPOSITORY = 'localhost/decent-keycloak-wallet-authenticator-spike'
IMAGE_TAG_RE = re.compile(r'qualification-candidate-([0-9]{8}T[0-9]{6}Z)')
TARGET_HOST = os.environ.get("REMOTE_TEST_HOST", "ben-x260.tailca8b51.ts.net").strip()
TARGET_USER = os.environ.get("REMOTE_TEST_USER", "ben").strip()
TARGET = f"{TARGET_USER}@{TARGET_HOST}"
TARGET_IMAGE = 'decent-keycloak:latest'
IMAGE_ID_RE = re.compile(r'sha256:[0-9a-f]{64}')
HOST_RE = re.compile(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?')
USER_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}')


def validate_target():
  if HOST_RE.fullmatch(TARGET_HOST.rstrip('.')) is None or USER_RE.fullmatch(TARGET_USER) is None:
    raise ValueError('invalid remote test-host configuration')


def select_latest_candidate(rows):
  """Select by the repository's unique UTC candidate tag, not a moving alias."""
  matches = []
  for repository, tag in rows:
    stamp = IMAGE_TAG_RE.fullmatch(tag)
    if repository == IMAGE_REPOSITORY and stamp is not None:
      matches.append((stamp.group(1), f'{repository}:{tag}'))
  if not matches:
    raise RuntimeError('no qualification candidate image with a UTC build tag was found')
  latest_stamp = max(stamp for stamp, _ in matches)
  latest_refs = [image_ref for stamp, image_ref in matches if stamp == latest_stamp]
  if len(latest_refs) != 1:
    raise RuntimeError('ambiguous latest candidate timestamp; refusing to publish')
  return latest_refs[0]


def run(args, *, capture=False):
  result = subprocess.run(args, check=False, text=True,
      stdout=subprocess.PIPE if capture else None,
      stderr=subprocess.PIPE if capture else None)
  if result.returncode != 0:
    detail = (result.stderr or '').strip() if capture else ''
    raise RuntimeError(f'command failed ({result.returncode}): {args[0]} {detail}')
  return result.stdout if capture else ''


def normalize_image_id(value):
  value = value.strip()
  if re.fullmatch(r'[0-9a-f]{64}', value):
    return f'sha256:{value}'
  if IMAGE_ID_RE.fullmatch(value):
    return value
  raise RuntimeError('image inspection did not return a full SHA-256 image ID')


def image_id_on_host(host, image_ref):
  image_id = run(['tailscale', 'ssh', host, 'podman', 'image', 'inspect',
      '--format', '{{.Id}}', image_ref], capture=True)
  return normalize_image_id(image_id)


def remote_image_exists(host, image_ref):
  result = subprocess.run(['tailscale', 'ssh', host, 'podman', 'image', 'exists',
      image_ref], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  if result.returncode == 0:
    return True
  if result.returncode == 1:
    return False
  raise RuntimeError(f'target image-presence check failed with exit {result.returncode}')


def main():
  try:
    validate_target()
    inventory = run(['podman', 'images', '--no-trunc', '--format',
        '{{.Repository}}|{{.Tag}}'], capture=True)
    rows = []
    for line in inventory.splitlines():
      parts = line.split('|')
      if len(parts) == 2 and parts[0] and parts[1] != '<none>':
        rows.append((parts[0], parts[1]))

    image_ref = select_latest_candidate(rows)
    local_id = normalize_image_id(run(['podman', 'image', 'inspect', '--format', '{{.Id}}',
        image_ref], capture=True))

    print(f'Selected latest candidate: {image_ref}')
    print(f'Target tag: {TARGET_IMAGE}')
    print(f'Immutable image ID: {local_id}')
    print('Transfer: Podman OCI archive streamed over Tailscale SSH; no registry is exposed.')

    source_exists = remote_image_exists(TARGET, image_ref)
    if source_exists and image_id_on_host(TARGET, image_ref) != local_id:
      raise RuntimeError('target source tag exists with a different image ID; refusing to overwrite')

    target_exists = remote_image_exists(TARGET, TARGET_IMAGE)
    target_id = image_id_on_host(TARGET, TARGET_IMAGE) if target_exists else None
    if source_exists and target_id == local_id:
      print(f'Target already has {TARGET_IMAGE} -> {local_id}; nothing to do.')
      return 0
    if target_exists and target_id != local_id:
      print(f'Publishing will move {TARGET_IMAGE} from {target_id} to {local_id}.')

    if not sys.stdin.isatty():
      raise RuntimeError('interactive confirmation is required; run this script in a terminal')
    source_tag = image_ref.rsplit(':', 1)[1]
    confirmation = f'PUBLISH {source_tag} AS {TARGET_IMAGE}'
    if input(f'Type exactly: {confirmation} : ') != confirmation:
      print('Not confirmed; no image was transferred or tagged.')
      return 1

    if not source_exists:
      save = subprocess.Popen(['podman', 'save', '--format', 'oci-archive', image_ref],
          stdout=subprocess.PIPE)
      if save.stdout is None:
        save.kill()
        raise RuntimeError('podman save did not provide an archive stream')
      try:
        load = subprocess.Popen(['tailscale', 'ssh', TARGET, 'podman', 'load'],
            stdin=save.stdout)
      except BaseException:
        save.kill()
        save.wait()
        raise
      save.stdout.close()
      load_status = load.wait()
      save_status = save.wait()
      if save_status != 0 or load_status != 0:
        raise RuntimeError(f'transfer failed (podman save={save_status}, remote load={load_status})')

    if image_id_on_host(TARGET, image_ref) != local_id:
      raise RuntimeError('post-transfer source image ID mismatch; do not tag it')
    if target_id != local_id:
      run(['tailscale', 'ssh', TARGET, 'podman', 'tag', image_ref, TARGET_IMAGE])

    verified_id = image_id_on_host(TARGET, TARGET_IMAGE)
    if verified_id != local_id:
      raise RuntimeError('target alias image ID mismatch; do not use the target tag')
    print(f'Verified on {TARGET_HOST}: {TARGET_IMAGE} -> {verified_id}')
    return 0
  except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
    print(f'ERROR: {error}', file=sys.stderr)
    return 1


if __name__ == '__main__':
  raise SystemExit(main())
