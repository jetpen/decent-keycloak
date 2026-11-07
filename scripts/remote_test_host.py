"""Tailnet-only transfer and target-side lifecycle for remote Keycloak smoke runs."""

import base64
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

RUN_ID_RE = re.compile(r"[0-9a-f]{32}")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
HOST_RE = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
TARGET_ARGUMENTS = ("operation", "run_id", "image_id")
USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}")
TARGET_IMAGE_PREFIX = "decent-keycloak:lifecycle-"
SOURCE_IMAGE_PREFIX = "localhost/decent-keycloak/wallet-provider:lifecycle-"


class TargetOperationRejected(RuntimeError):
  def __init__(self, category: str):
    safe_category = category if re.fullmatch(r"[a-z0-9_]+", category) else "target_operation_failed"
    super().__init__(safe_category)
    self.category = safe_category


def normalize_podman_image_id(value: str) -> str | None:
  candidate = value.strip()
  if re.fullmatch(r"[0-9a-f]{64}", candidate):
    return "sha256:" + candidate
  if IMAGE_ID_RE.fullmatch(candidate):
    return candidate
  return None


def validate_host(host: str) -> None:
  if not isinstance(host, str) or HOST_RE.fullmatch(host.rstrip(".")) is None:
    raise ValueError("invalid configured test host")


def validate_target(target: str, expected_host: str) -> None:
  validate_host(expected_host)
  if not isinstance(target, str) or target.count("@") != 1:
    raise ValueError("invalid configured test target")
  user, host = target.split("@", 1)
  if USER_RE.fullmatch(user) is None or host.rstrip(".").lower() != expected_host.rstrip(".").lower():
    raise ValueError("configured test target does not match host")


def validate_identity(run_id: str, image_id: str) -> None:
  if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
    raise ValueError("invalid lifecycle run ID")
  if not isinstance(image_id, str) or IMAGE_ID_RE.fullmatch(image_id) is None:
    raise ValueError("invalid immutable image ID")


def target_tag(run_id: str) -> str:
  if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
    raise ValueError("invalid lifecycle run ID")
  return TARGET_IMAGE_PREFIX + run_id


def source_tag(run_id: str) -> str:
  if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
    raise ValueError("invalid lifecycle run ID")
  return SOURCE_IMAGE_PREFIX + run_id


def operation_plan(run_id: str, image_id: str) -> list[dict]:
  validate_identity(run_id, image_id)
  return [{"operation": name, "run_id": run_id, "image_id": image_id,
      "tailnet_only": True} for name in ("transfer", "deploy", "probe", "teardown")]


def target_helper_command(target: str, operation: str, run_id: str,
    image_id: str, *, host: str, source_ref: str | None = None) -> list[str]:
  validate_identity(run_id, image_id)
  validate_target(target, host)
  if operation not in {"preflight", "transfer", "deploy", "teardown"}:
    raise ValueError("invalid target helper operation")
  if operation == "transfer" and source_ref != source_tag(run_id):
    raise ValueError("invalid source image reference")
  if operation != "transfer" and source_ref is not None:
    raise ValueError("unexpected source image reference")
  source = Path(__file__).read_text(encoding="utf-8")
  payload = base64.b64encode(source.encode("utf-8")).decode("ascii")
  command = "exec(__import__('base64').b64decode('" + payload + "'))"
  # The helper source is sent as a non-secret command argument; stdin stays free for image data.
  arguments = [operation, run_id, image_id, host.rstrip(".")]
  if source_ref is not None:
    arguments.append(source_ref)
  return ["tailscale", "ssh", target,
      shlex.join(["python3", "-c", command, *arguments])]


def run_target(target: str, operation: str, run_id: str, image_id: str,
    *, host: str, source_ref: str | None = None, input_stream=None) -> dict:
  command = target_helper_command(target, operation, run_id, image_id,
      host=host, source_ref=source_ref)
  result = subprocess.run(command, input=input_stream, text=False,
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=180)
  try:
    value = json.loads(result.stdout.decode("utf-8").strip().splitlines()[-1])
  except (UnicodeDecodeError, json.JSONDecodeError, IndexError) as error:
    raise RuntimeError(f"target_{operation}_response_invalid") from error
  if not isinstance(value, dict):
    raise RuntimeError(f"target_{operation}_response_invalid")
  if value.get("ok") is False:
    raise TargetOperationRejected(str(value.get("category", "target_operation_failed")))
  if result.returncode:
    raise RuntimeError(f"target_{operation}_failed")
  if value.get("ok") is not True:
    raise RuntimeError(f"target_{operation}_rejected")
  if operation == "teardown" and any(value.get(key) is not True for key in
      ("container_absent", "serve_absent", "run_image_refs_absent")):
    raise RuntimeError("target_teardown_readback_incomplete")
  return value


def transfer_image(target: str, host: str, image_id: str, run_id: str) -> dict:
  validate_identity(run_id, image_id)
  validate_target(target, host)
  source_ref = source_tag(run_id)
  command = target_helper_command(target, "transfer", run_id, image_id,
      host=host, source_ref=source_ref)
  save = subprocess.Popen(["podman", "save", "--format", "oci-archive", image_id],
      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
  if save.stdout is None:
    save.kill()
    save.wait()
    raise RuntimeError("image_archive_unavailable")
  remote = None
  try:
    remote = subprocess.Popen(command, stdin=save.stdout, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    save.stdout.close()
    remote_out, _remote_err = remote.communicate(timeout=900)
    save.wait(timeout=30)
    try:
      response = json.loads(remote_out.decode("utf-8").strip().splitlines()[-1])
    except (UnicodeDecodeError, json.JSONDecodeError, IndexError) as error:
      raise RuntimeError("target_transfer_response_invalid") from error
    expected_response = {"ok": True, "image_id": image_id,
        "tag": target_tag(run_id), "source_ref": source_ref}
    if response != expected_response:
      raise RuntimeError("image_transfer_failed")
    return response
  except BaseException:
    if remote is not None and remote.poll() is None:
      remote.kill()
      remote.communicate()
    if save.poll() is None:
      save.kill()
      save.wait()
    raise
  finally:
    if save.poll() is None:
      save.kill()
      save.wait()


def probe_discovery(host: str, *, attempts: int = 40, interval: float = 3.0) -> dict:
  validate_host(host)
  host = host.rstrip(".")
  if type(attempts) is not int or attempts < 1 or attempts > 120:
    raise ValueError("discovery retry count is outside its bound")
  if type(interval) not in (int, float) or interval < 0 or interval > 10:
    raise ValueError("discovery retry interval is outside its bound")
  url = f"https://{host}/realms/master/.well-known/openid-configuration"
  issuer = f"https://{host}/realms/master"
  last_category = "oidc_discovery_unavailable"
  for attempt in range(attempts):
    try:
      with urllib.request.urlopen(url, timeout=10) as response:
        if response.status != 200:
          last_category = "oidc_discovery_http_failure"
        else:
          document = json.loads(response.read())
          if not isinstance(document, dict) or document.get("issuer") != issuer:
            raise RuntimeError("oidc_discovery_issuer_mismatch")
          return {"http_status": 200, "issuer_matches": True}
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
      last_category = "oidc_discovery_unavailable"
    if attempt + 1 < attempts:
      time.sleep(interval)
  raise RuntimeError(last_category)


def _target_run(args, *, input_stream=None, env=None, timeout=60, text=True):
  return subprocess.run(args, input=input_stream, text=text, capture_output=True,
      check=False, timeout=timeout, env=env)


def _target_json_command(args) -> dict:
  result = _target_run(args)
  if result.returncode:
    raise RuntimeError("target_command_failed")
  return json.loads(result.stdout)


def _assert_target_identity(expected_host: str) -> str:
  validate_host(expected_host)
  status = _target_json_command(["tailscale", "status", "--json"])
  dns = status.get("Self", {}).get("DNSName", "").rstrip(".")
  if dns.lower() != expected_host.rstrip(".").lower():
    raise RuntimeError("target_identity_mismatch")
  return dns


def _target_image_ref_id(ref: str) -> str | None:
  exists = _target_run(["podman", "image", "exists", ref])
  if exists.returncode == 1:
    return None
  if exists.returncode:
    raise RuntimeError("image_presence_check_failed")
  result = _target_run(["podman", "image", "inspect", "--format", "{{.Id}}", ref])
  if result.returncode:
    raise RuntimeError("image_inspection_failed")
  image_id = normalize_podman_image_id(result.stdout)
  if image_id is None:
    raise RuntimeError("image_inspection_invalid")
  return image_id


def _target_inspect_image(image_id: str) -> bool:
  return _target_image_ref_id(image_id) == image_id


def _target_container(run_id: str):
  name = f"decent-keycloak-test-{run_id}"
  exists = _target_run(["podman", "container", "exists", name])
  if exists.returncode == 1:
    return None
  if exists.returncode:
    raise RuntimeError("container_presence_check_failed")
  result = _target_run(["podman", "container", "inspect", name])
  if result.returncode:
    raise RuntimeError("container_inspection_failed")
  records = json.loads(result.stdout)
  if not isinstance(records, list) or len(records) != 1:
    raise RuntimeError("container_inspection_invalid")
  return records[0]


def _target_is_owned(record: dict, run_id: str, image_id: str) -> bool:
  config = record.get("Config", {})
  labels = config.get("Labels", {}) or {}
  actual_image = normalize_podman_image_id(
      str(record.get("Image", record.get("ImageID", ""))))
  return (labels.get("io.decent.lifecycle.run-id") == run_id
      and labels.get("io.decent.lifecycle.image-id") == image_id
      and actual_image == image_id)


def _target_serve_status() -> str:
  result = _target_run(["tailscale", "serve", "status"])
  if result.returncode:
    raise RuntimeError("serve_status_failed")
  return result.stdout.strip()


def _target_serve_owned_only(status: str, expected_host: str) -> bool:
  route_lines = [line.strip() for line in status.splitlines()
      if line.strip().startswith(("https://", "|--"))]
  if len(route_lines) != 2:
    return False
  host_pattern = re.compile(
      r"https://" + re.escape(expected_host.rstrip(".").lower())
      + r"(?::443)?/?(?:\s+\(tailnet only\))?")
  backend_pattern = re.compile(
      r"\|--\s+(?:/\s+)?proxy\s+http://127\.0\.0\.1:8080")
  return bool(host_pattern.fullmatch(route_lines[0].lower())
      and backend_pattern.fullmatch(route_lines[1].lower()))


def _target_remove_run_image_refs(run_id: str, image_id: str) -> list[str]:
  removed_refs = []
  for ref in (target_tag(run_id), source_tag(run_id)):
    actual_image = _target_image_ref_id(ref)
    if actual_image is None:
      continue
    if actual_image != image_id:
      raise RuntimeError("run_image_tag_ownership_mismatch")
    removed = _target_run(["podman", "image", "rm", ref])
    if removed.returncode or _target_image_ref_id(ref) is not None:
      raise RuntimeError("run_image_tag_removal_unverified")
    removed_refs.append(ref)
  return removed_refs


def _target_operation(operation: str, run_id: str, image_id: str,
    expected_host: str | None = None, source_ref: str | None = None) -> dict:
  validate_identity(run_id, image_id)
  if operation not in {"preflight", "transfer", "deploy", "teardown"}:
    raise RuntimeError("unknown_target_operation")
  if not expected_host:
    raise RuntimeError("target_identity_required")
  target_dns = _assert_target_identity(expected_host)
  if operation == "preflight":
    info = _target_json_command(["podman", "info", "--format", "json"])
    host_info = info.get("host", info.get("Host", {}))
    security = host_info.get("security", host_info.get("Security", {}))
    if security.get("rootless", security.get("Rootless")) is not True:
      raise RuntimeError("target_podman_not_rootless")
    sock = socket.socket()
    try:
      if sock.connect_ex(("127.0.0.1", 8080)) == 0:
        raise RuntimeError("target_port_unavailable")
    finally:
      sock.close()
    serve = _target_serve_status().lower()
    if serve not in ("no serve config", ""):
      raise RuntimeError("target_serve_in_use")
    target_tag_available = _target_image_ref_id(target_tag(run_id)) is None
    source_tag_available = _target_image_ref_id(source_tag(run_id)) is None
    if not target_tag_available or not source_tag_available:
      raise RuntimeError("run_image_tag_collision")
    return {"ok": True, "host_matches": target_dns.lower() == expected_host.rstrip(".").lower(),
        "rootless_podman": True, "port_free": True, "serve_unused": True,
        "run_image_tags_available": True}
  if operation == "transfer":
    image_tag = target_tag(run_id)
    expected_source_ref = source_tag(run_id)
    if source_ref != expected_source_ref:
      raise RuntimeError("invalid_source_image_reference")
    source_ref = expected_source_ref
    if (_target_image_ref_id(image_tag) is not None
        or _target_image_ref_id(source_ref) is not None):
      raise RuntimeError("run_tag_collision")
    try:
      load = _target_run(["podman", "load"], input_stream=sys.stdin.buffer, text=False)
      if load.returncode or not _target_inspect_image(image_id):
        raise RuntimeError("loaded_image_identity_mismatch")
      for ref in (source_ref, image_tag):
        current = _target_image_ref_id(ref)
        if current is None:
          tagged = _target_run(["podman", "tag", image_id, ref])
          if tagged.returncode:
            raise RuntimeError("run_tag_failed")
        elif current != image_id:
          raise RuntimeError("run_tag_collision")
        if _target_image_ref_id(ref) != image_id:
          raise RuntimeError("run_tag_identity_mismatch")
    except Exception as transfer_error:
      for ref in reversed((source_ref, image_tag)):
        if _target_image_ref_id(ref) == image_id:
          removed = _target_run(["podman", "image", "rm", ref])
          if removed.returncode or _target_image_ref_id(ref) is not None:
            raise RuntimeError("transfer_cleanup_unverified") from transfer_error
      raise
    return {"ok": True, "image_id": image_id, "tag": image_tag,
        "source_ref": source_ref}
  if operation == "deploy":
    if _target_image_ref_id(target_tag(run_id)) != image_id:
      raise RuntimeError("run_scoped_image_missing")
    if _target_container(run_id) is not None:
      raise RuntimeError("container_name_collision")
    if _target_run(["podman", "container", "exists", f"decent-keycloak-test-{run_id}"]).returncode == 0:
      raise RuntimeError("container_name_collision")
    if _target_serve_status().lower() not in ("no serve config", ""):
      raise RuntimeError("target_serve_in_use")
    password = secrets.token_urlsafe(36)
    container_name = f"decent-keycloak-test-{run_id}"
    command = ["podman", "run", "--detach", "--name", container_name,
        "--label", f"io.decent.lifecycle.run-id={run_id}",
        "--label", f"io.decent.lifecycle.image-id={image_id}",
        "--publish", "127.0.0.1:8080:8080", image_id,
        "start-dev", "--http-enabled=true", "--proxy-headers=xforwarded",
        "--hostname-strict=false"]
    environment = dict(os.environ)
    environment.update({"KC_BOOTSTRAP_ADMIN_USERNAME": "remote-smoke",
        "KC_BOOTSTRAP_ADMIN_PASSWORD": password,
        "KC_HOSTNAME": "https://" + expected_host.rstrip(".")})
    try:
      started = _target_run(command, env=environment)
    finally:
      environment.pop("KC_BOOTSTRAP_ADMIN_PASSWORD", None)
      del password
    if started.returncode:
      raise RuntimeError("container_start_failed")
    record = _target_container(run_id)
    if record is None or not _target_is_owned(record, run_id, image_id):
      raise RuntimeError("container_ownership_readback_failed")
    serve = _target_run(["tailscale", "serve", "--bg", "--https=443", "http://127.0.0.1:8080"])
    if serve.returncode:
      raise RuntimeError("serve_start_failed")
    return {"ok": True, "run_id": run_id, "image_id": image_id}
  if operation == "teardown":
    record = _target_container(run_id)
    if record is not None and not _target_is_owned(record, run_id, image_id):
      raise RuntimeError("container_ownership_mismatch")
    serve = _target_serve_status()
    normalized_serve = serve.lower()
    no_serve = normalized_serve in ("no serve config", "")
    route_is_owned = _target_serve_owned_only(serve, expected_host)
    if record is None:
      if not no_serve:
        raise RuntimeError("serve_ownership_unverified")
    else:
      if not no_serve and not route_is_owned:
        raise RuntimeError("serve_ownership_unverified")
      if not no_serve:
        disabled = _target_run(["tailscale", "serve", "--https=443", "off"])
        if disabled.returncode or _target_serve_status().lower() not in ("no serve config", ""):
          raise RuntimeError("serve_removal_unverified")
      container_id = record.get("Id")
      if not isinstance(container_id, str) or not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise RuntimeError("container_id_invalid")
      removed = _target_run(["podman", "rm", "--force", container_id])
      exact_presence = _target_run(["podman", "container", "exists", container_id])
      if (removed.returncode or exact_presence.returncode != 1
          or _target_container(run_id) is not None):
        raise RuntimeError("container_removal_unverified")
    removed_refs = _target_remove_run_image_refs(run_id, image_id)
    return {"ok": True, "container_absent": True, "serve_absent": True,
        "run_image_refs_absent": True, "removed_image_refs": removed_refs}
  raise RuntimeError("unknown_target_operation")


def target_main(argv=None) -> int:
  args = sys.argv[1:] if argv is None else argv
  try:
    if len(args) not in (4, 5):
      raise RuntimeError("target_arguments_invalid")
    operation, run_id, image_id, expected_host = args[:4]
    source_ref = args[4] if len(args) == 5 else None
    if (operation == "transfer") != (source_ref is not None):
      raise RuntimeError("target_arguments_invalid")
    result = _target_operation(operation, run_id, image_id, expected_host, source_ref)
    print(json.dumps(result, sort_keys=True))
    return 0
  except Exception as error:
    category = str(error)
    if not re.fullmatch(r"[a-z0-9_]+", category):
      category = "target_operation_failed"
    print(json.dumps({"ok": False, "category": category}), flush=True)
    return 2


def remote_lifecycle(target: str, host: str, run_id: str, image_id: str,
    *, on_step=None) -> dict:
  validate_identity(run_id, image_id)
  validate_target(target, host)
  facts = {}
  transferred = False
  failure = None
  current_step = "remote-image-transfer"
  try:
    transfer_image(target, host, image_id, run_id)
    transferred = True
    facts["transfer"] = {"status": "pass"}
    if on_step:
      on_step(current_step, "pass", None)

    current_step = "remote-deploy"
    run_target(target, "deploy", run_id, image_id, host=host)
    facts["deploy"] = {"status": "pass"}
    if on_step:
      on_step(current_step, "pass", None)

    current_step = "remote-oidc-discovery"
    facts["discovery"] = probe_discovery(host)
    if on_step:
      on_step(current_step, "pass", None)
  except Exception as error:
    failure = error
    if on_step:
      detail = {
          "remote-image-transfer": "image_transfer_failed",
          "remote-deploy": "remote_deploy_failed",
          "remote-oidc-discovery": "oidc_discovery_failed",
      }[current_step]
      on_step(current_step, "fail", detail)
    raise
  finally:
    if transferred:
      try:
        run_target(target, "teardown", run_id, image_id, host=host)
        facts["teardown"] = {"status": "pass"}
        if on_step:
          on_step("remote-teardown", "pass", None)
      except Exception as cleanup_error:
        facts["teardown"] = {"status": "fail",
            "category": type(cleanup_error).__name__}
        if on_step:
          on_step("remote-teardown", "fail", "remote_teardown_unverified")
        if failure is None:
          raise RuntimeError("remote_teardown_unverified") from cleanup_error
  return facts


if __name__ == "__main__":
  raise SystemExit(target_main())
