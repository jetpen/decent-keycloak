"""Local repository lifecycle CLI; build fetches pinned prerequisites before isolated image builds."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
LOCAL_PROFILES = ("dev", "ci")
LIVE_PROFILES = ("readiness", "qualification")
PROFILES = (*LOCAL_PROFILES, *LIVE_PROFILES)
MAX_JSON_BYTES = 8192
RESERVATIONS = (".keycloakctl", "run-ids")
RUNS = ("target", "keycloakctl", "runs")
PREPARE = ("setup", "preflight", "build", "test", "publish", "deploy", "configure")
PLANS = {
  "dev": ("setup", "build", "test"),
  "ci": ("setup", "build", "test"),
  "readiness": (*PREPARE, "verify readiness", "teardown"),
  "qualification": (*PREPARE, "manual Android evidence", "integration-test", "verify qualification"),
}
LIVE_PHASES = {"publish", "deploy", "configure", "integration-test", "verify readiness", "teardown"}
TEST_STEPS = ("java-tests", "surefire", "python-tests", "python-compile", "image-smoke", "rp-fixture-smoke", "diff-check")
IMAGE_FINGERPRINT_TARGETS = (
  "issue6-callback-gate-test-runtime",
  "issue6-postconsume-test-runtime",
  "issue7-store-recovery-test-runtime",
  "issue7-user-readback-test-runtime",
  "runtime",
)
PHASE_HELP = {
  "preflight": "check local toolchain/engine or remote target prerequisites without changes",
  "build": "package the provider, fetch and verify locked resolver inputs, then build the provider and test RP images",
  "test": "run acceptance checks and image smokes; Python checks fetch pinned prerequisites",
  "publish": "transfer exact run images over Tailscale SSH, not to a registry",
  "deploy": "start exact run-owned services",
  "configure": "configure the run's isolated realm and test RP",
  "integration-test": "execute the qualification cases after the manual Android checkpoint",
  "verify": "verify readiness or qualification; the outputs are not interchangeable",
  "teardown": "remove only exact run-owned deployment resources",
  "promote": "publish a separately authorized, verified image to a registry",
}


class Rejected(Exception):
  """A fixed, user-safe diagnostic (never an input value or path)."""


class Unavailable(Rejected):
  """An eligible phase which the foundation does not execute."""


class BuildPrerequisiteError(Exception):
  """A locked resolver input could not be materialized or verified."""


class Parser(argparse.ArgumentParser):
  def error(self, message):
    # argparse's normal errors include raw argument values and unknown flags.
    self.exit(2, "error: invalid arguments; see --help\n")


def unique_members(pairs):
  result = {}
  for key, value in pairs:
    if key in result:
      raise ValueError
    result[key] = value
  return result


def reject_number(_value):
  raise ValueError


def parse_json(raw: bytes):
  return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_members,
                    parse_constant=reject_number, parse_float=reject_number)


def read_regular(path: Path | str, *, dir_fd: int | None = None) -> bytes:
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
  with os.fdopen(fd, "rb", buffering=0) as source:
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
      raise ValueError
    raw = bytearray()
    while len(raw) <= MAX_JSON_BYTES:
      chunk = source.read(MAX_JSON_BYTES + 1 - len(raw))
      if not chunk:
        return bytes(raw)
      raw.extend(chunk)
    raise ValueError


def config_schema():
  return json.loads((ROOT / "config/keycloakctl/config.schema.json").read_text(encoding="utf-8"))


def config_fields():
  return config_schema()["properties"]


def schema_forbids_remote(schema: dict, profile: str | None) -> bool:
  condition = schema.get("if", {}).get("properties", {}).get("profile", {})
  then = schema.get("then", {})
  forbidden = then.get("not", {}).get("required", [])
  return profile in condition.get("enum", []) and "remote" in forbidden


def validate_config(value, profile: str | None) -> None:
  schema = config_schema()
  fields = schema["properties"]
  required = set(schema["required"])
  allowed = set(fields)
  if type(value) is not dict or not required <= value.keys() <= allowed:
    raise ValueError
  if schema_forbids_remote(schema, value.get("profile")):
    if "remote" in value:
      raise ValueError
  if type(value.get("version")) is not int or value["version"] != fields["version"]["const"]:
    raise ValueError
  profile_rule = fields["profile"]
  if value.get("profile") not in profile_rule["enum"]:
    raise ValueError
  if profile is not None and value["profile"] != profile:
    raise Rejected("configuration profile does not match")
  if "engine" in value and value["engine"] not in fields["engine"]["enum"]:
    raise ValueError
  if "remote" not in value:
    return
  remote = value["remote"]
  remote_schema = fields["remote"]
  rules = remote_schema["properties"]
  if type(remote) is not dict or not remote.keys() <= rules.keys():
    raise ValueError
  for name, entry in remote.items():
    rule = rules[name]
    if "$ref" in rule:
      rule = fields["remote"]["properties"]["target_ip"]
    if rule["type"] == "boolean":
      if type(entry) is not bool:
        raise ValueError
    elif (type(entry) is not str or len(entry) > rule.get("maxLength", 253)
          or re.fullmatch(rule["pattern"], entry) is None):
      raise ValueError


def load_config(path: str, profile: str | None) -> dict:
  try:
    value = parse_json(read_regular(path))
    validate_config(value, profile)
    return value
  except (OSError, ValueError, RecursionError):
    raise Rejected("invalid configuration") from None


def canonical_json(value: dict) -> bytes:
  return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


@contextmanager
def open_directory(parts, *, create=False):
  """Walk real, repository-relative directories without following symlinks."""
  flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
  with ExitStack() as opened:
    fd = os.open(ROOT, flags)
    opened.callback(os.close, fd)
    for part in parts:
      if create:
        try:
          os.mkdir(part, 0o700, dir_fd=fd)
        except FileExistsError:
          pass
        else:
          os.fsync(fd)
      fd = os.open(part, flags, dir_fd=fd)
      opened.callback(os.close, fd)
    yield fd


def write_exclusive(directory: int, name: str, data: bytes) -> None:
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
  fd = os.open(name, flags, 0o600, dir_fd=directory)
  with os.fdopen(fd, "wb") as output:
    output.write(data)
    output.flush()
    os.fsync(output.fileno())
  os.fsync(directory)


def read_run(run_id: str) -> dict:
  if re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
    raise Rejected("invalid run ID")
  expected = None
  run_exists = False
  try:
    try:
      with open_directory(RESERVATIONS) as reservations:
        expected = read_regular(run_id, dir_fd=reservations)
    except FileNotFoundError:
      pass
    with open_directory((*RUNS, run_id)) as directory:
      run_exists = True
      raw = read_regular("manifest.json", dir_fd=directory)
    if sha256(raw).hexdigest().encode("ascii") != expected:
      raise ValueError
    state = parse_json(raw)
    if (type(state) is not dict or state.keys() != {"version", "run_id", "profile", "config_sha256", "completed"}
        or type(state["version"]) is not int or state["version"] != 1 or state["run_id"] != run_id
        or state["profile"] not in PROFILES or state["completed"] != ["setup"]
        or type(state["config_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", state["config_sha256"]) is None):
      raise ValueError
    return state
  except FileNotFoundError:
    raise Rejected("unknown run ID" if expected is None and not run_exists else "run readback conflict") from None
  except (OSError, ValueError, RecursionError):
    raise Rejected("run readback conflict") from None


def create_run(config: dict) -> dict:
  run_id = uuid4().hex
  state = {"version": 1, "run_id": run_id, "profile": config["profile"],
           "config_sha256": sha256(canonical_json(config)).hexdigest(), "completed": ["setup"]}
  raw = canonical_json(state)
  try:
    # Reserve first, outside Maven's target directory. Never remove a claim,
    # even if a crash or a conflicting run directory prevents setup completing.
    with open_directory(RESERVATIONS, create=True) as reservations:
      write_exclusive(reservations, run_id, sha256(raw).hexdigest().encode("ascii"))
    with open_directory(RUNS, create=True) as runs, ExitStack() as opened:
      os.mkdir(run_id, 0o700, dir_fd=runs)
      os.fsync(runs)
      directory = os.open(run_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=runs)
      opened.callback(os.close, directory)
      write_exclusive(directory, "manifest.json", raw)
  except FileExistsError:
    raise Rejected("run ID already reserved or run directory exists") from None
  except OSError:
    raise Rejected("run setup storage error") from None
  if read_run(run_id) != state:
    raise Rejected("run readback conflict")
  return state


def checked_run(args) -> tuple[dict, dict | None]:
  state = read_run(args.run_id)
  profile = getattr(args, "profile", None)
  if profile is not None and profile != state["profile"]:
    raise Rejected("run profile does not match")
  config = load_config(args.config, state["profile"]) if args.config is not None else None
  if config is not None and sha256(canonical_json(config)).hexdigest() != state["config_sha256"]:
    raise Rejected("run configuration readback conflict")
  return state, config


def new_run(args) -> tuple[dict, dict]:
  if args.config is not None:
    config = load_config(args.config, args.profile)
  else:
    profile = args.profile or "dev"
    config = {"version": 1, "profile": profile, "engine": "docker" if profile == "ci" else "podman"}
  return create_run(config), config


def authorize(phase: str, args) -> None:
  if phase in LIVE_PHASES and not args.allow_live:
    raise Rejected(f"{phase} requires --allow-live on this invocation")
  if phase == "promote" and not args.allow_publish:
    raise Rejected("promote requires --allow-publish on this invocation")


def next_phase(state: dict) -> str | None:
  plan = PLANS[state["profile"]]
  completed = phase_completion(state)
  pending = plan[len(completed):]
  return pending[0] if pending else None


def phase_completion(state: dict) -> list[str]:
  completed = list(state["completed"])
  if state["profile"] not in LOCAL_PROFILES:
    return completed
  bundle = read_build_bundle(state)
  if bundle is None:
    return completed
  completed.append("build")
  if read_test_receipt(state, bundle) is not None:
    completed.append("test")
  return completed


def guard_phase(phase: str, state: dict, config: dict | None) -> None:
  profile = state["profile"]
  if phase == "promote":
    return
  if phase == "teardown":
    # No deployment adapter/readback exists in this foundation. Phase history
    # cannot authorize deletion of resources after a partial remote mutation.
    raise Rejected("teardown requires exact run-owned deployment readback")
  elif phase == "preflight":
    # Preflight is read-only, so it may be repeated at any lifecycle point.
    pass
  else:
    if phase not in PLANS[profile]:
      raise Rejected("phase is not supported by run profile")
    completed = phase_completion(state)
    expected = next_phase(state)
    if expected != phase and phase not in completed:
      raise Rejected(f"invalid phase order; next phase is {expected or 'none'}")

  if phase == "preflight" and profile in LIVE_PROFILES:
    remote = (config or {}).get("remote", {})
    required = {"target_user", "target_dns_name", "target_ip", "proxy_ip", "public_origin"}
    if (not required <= remote.keys() or remote.get("route_attested") is not True
        or remote["target_ip"] == remote["proxy_ip"] or remote["public_origin"].endswith(".invalid")):
      raise Rejected("preflight requires matching operator inputs and route attestation")


def attempt_phase(phase: str, state: dict, config: dict | None) -> None:
  guard_phase(phase, state, config)
  if phase == "preflight":
    if state["profile"] in LOCAL_PROFILES:
      perform_local_preflight(config, state["profile"])
    else:
      perform_preflight(config)
    print("preflight passed")
    return
  raise Unavailable(f"{phase} unavailable in the offline foundation")


def perform_preflight(config: dict | None) -> None:
  remote = (config or {}).get("remote", {})
  target_host = remote.get("target_host", "ben-x260")
  target_dns_name = remote.get("target_dns_name")
  target_user = remote.get("target_user")
  target_ip = remote["target_ip"]
  if not isinstance(target_host, str) or re.fullmatch(
      r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", target_host) is None:
    raise Rejected("preflight requires a valid SSH target")
  if not isinstance(target_user, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}", target_user) is None:
    raise Rejected("preflight requires a valid SSH user")

  for tool, arguments in (("tailscale", ["version"]), ("podman", ["--version"])):
    executable = shutil.which(tool)
    if executable is None:
      raise Rejected("preflight local tool check failed")
    try:
      result = subprocess.run([executable, *arguments], cwd=ROOT,
          capture_output=True, text=True, encoding="utf-8", check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
      raise Rejected("preflight local tool check failed") from None
    if result.returncode:
      raise Rejected("preflight local tool check failed")

  tailscale = shutil.which("tailscale")
  if tailscale is None:
    raise Rejected("preflight local tool check failed")

  target = f"{target_user}@{target_host}"

  def run_remote(command: str) -> subprocess.CompletedProcess:
    try:
      result = subprocess.run([tailscale, "ssh", target, command], cwd=ROOT,
          capture_output=True, text=True, encoding="utf-8", check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
      raise Rejected("preflight SSH check failed") from None
    if result.returncode:
      raise Rejected("preflight SSH check failed")
    return result

  identity = run_remote("tailscale status --json")
  try:
    status = parse_json(identity.stdout.encode("utf-8"))
  except (UnicodeError, ValueError, RecursionError):
    raise Rejected("preflight invalid identity response") from None
  self_status = status.get("Self") if type(status) is dict else None
  dns_name = self_status.get("DNSName") if type(self_status) is dict else None
  addresses = self_status.get("TailscaleIPs") if type(self_status) is dict else None
  expected_name = target_dns_name.rstrip(".").lower() if isinstance(target_dns_name, str) else ""
  observed_name = dns_name.rstrip(".").lower() if isinstance(dns_name, str) else ""
  if observed_name != expected_name or type(addresses) is not list or target_ip not in addresses:
    raise Rejected("preflight identity mismatch")

  podman = run_remote("podman info --format json")
  try:
    info = parse_json(podman.stdout.encode("utf-8"))
  except (UnicodeError, ValueError, RecursionError):
    raise Rejected("preflight invalid Podman response") from None
  if (type(info) is not dict or type(info.get("host")) is not dict
      or type(info["host"].get("security")) is not dict
      or info["host"]["security"].get("rootless") is not True):
    raise Rejected("preflight not rootless")


def local_command(executable: str, arguments: list[str], *, max_output_bytes: int = 65536) -> str:
  """Run a bounded, read-only local probe; never expose its output to users."""
  path = shutil.which(executable)
  if path is None:
    raise Rejected("preflight local tool check failed")
  try:
    result = subprocess.run([path, *arguments], cwd=ROOT, capture_output=True,
                            check=False, timeout=5)
  except (OSError, subprocess.TimeoutExpired):
    raise Rejected("preflight local tool check failed") from None
  if result.returncode or len(result.stdout) > max_output_bytes or len(result.stderr) > 65536:
    raise Rejected("preflight local tool check failed")
  try:
    return (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="strict")
  except UnicodeError:
    raise Rejected("preflight local tool check failed") from None


def version_match(pattern: str, output: str) -> tuple[int, ...] | None:
  match = re.search(pattern, output, flags=re.IGNORECASE)
  if match is None:
    return None
  try:
    return tuple(int(part) for part in match.group(1).split("."))
  except (ValueError, AttributeError):
    return None


def validate_inventory_entry(entry: object, identifier_field: str) -> bool:
  if not isinstance(entry, dict):
    return False
  image_id = entry.get(identifier_field)
  if not isinstance(image_id, str):
    return False
  return image_id == image_id.strip() and normalize_image_id(image_id) is not None


def validate_inventory(output: str, *, docker: bool) -> bool:
  try:
    if docker:
      entries = [json.loads(line) for line in output.splitlines() if line.strip()]
      return all(validate_inventory_entry(entry, "ID") for entry in entries)
    entries = json.loads(output)
    return (type(entries) is list
            and all(validate_inventory_entry(entry, "Id") for entry in entries))
  except (ValueError, RecursionError):
    return False


def endpoint_is_local(endpoint: object, *, docker: bool) -> bool:
  if type(endpoint) is not str or not endpoint or endpoint.strip() != endpoint:
    return False
  if endpoint.startswith("unix://"):
    path = endpoint[7:]
    return path.startswith("/") and not path.startswith("//")
  return docker and endpoint.lower().startswith("npipe://./pipe/")


def engine_config_path(value: str | Path) -> Path:
  path = Path(value)
  return path if path.is_absolute() else ROOT / path


def docker_endpoint() -> str | None:
  """Resolve Docker's selected endpoint from local configuration only."""
  try:
    docker_dir = engine_config_path(os.environ.get("DOCKER_CONFIG", Path.home() / ".docker"))
    if os.environ.get("DOCKER_HOST") and not os.environ.get("DOCKER_CONTEXT"):
      return os.environ["DOCKER_HOST"]
    context_name = os.environ.get("DOCKER_CONTEXT")
    settings_path = docker_dir / "config.json"
    if settings_path.exists():
      settings = json.loads(settings_path.read_text(encoding="utf-8"))
      if type(settings) is not dict:
        return None
      context_name = context_name or settings.get("currentContext") or "default"
    else:
      context_name = context_name or "default"
    if context_name == "default":
      return "unix:///var/run/docker.sock"
    for metadata_path in (docker_dir / "contexts" / "meta").glob("*/*.json"):
      metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
      if type(metadata) is dict and metadata.get("Name") == context_name:
        endpoints = metadata.get("Endpoints")
        endpoint = endpoints.get("docker") if type(endpoints) is dict else None
        return endpoint.get("Host") if type(endpoint) is dict else None
    return None
  except (OSError, ValueError, RecursionError):
    return None


def podman_endpoint_is_local() -> bool:
  """Reject selected remote Podman connections without invoking Podman."""
  try:
    if "CONTAINER_HOST" in os.environ:
      if not endpoint_is_local(os.environ["CONTAINER_HOST"], docker=False):
        return False
    selected = os.environ.get("CONTAINER_CONNECTION")
    paths = []
    if os.environ.get("PODMAN_CONNECTIONS_CONF"):
      paths.append(engine_config_path(os.environ["PODMAN_CONNECTIONS_CONF"]))
    config_home = engine_config_path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    paths.append(config_home / "containers" / "podman-connections.json")
    for path in paths:
      if not path.exists():
        continue
      config = json.loads(path.read_text(encoding="utf-8"))
      if type(config) is not dict:
        return False
      connections = config.get("Connection list", config.get("connections", []))
      if type(connections) is not list:
        return False
      name = selected or config.get("Default", config.get("default"))
      if not name:
        continue
      matching = [item for item in connections
                  if type(item) is dict and item.get("Name", item.get("name")) == name]
      if len(matching) != 1:
        return False
      uri = matching[0].get("URI", matching[0].get("uri"))
      return endpoint_is_local(uri, docker=False)
    return selected is None and "CONTAINER_HOST" not in os.environ
  except (OSError, ValueError, RecursionError):
    return False


def perform_local_preflight(config: dict | None, profile: str) -> None:
  """Validate the local toolchain and explicitly selected local container engine."""
  if sys.version_info[:3] != (3, 11, 13):
    raise Rejected("preflight local tool check failed")
  checks = (
      ("java", ["-version"], r'(?:openjdk|java) version\s+["\']?(\d+(?:\.\d+)*)'),
      ("mvn", ["-version"], r"Apache Maven\s+(\d+(?:\.\d+){1,2})"),
      ("git", ["--version"], r"git version\s+(\d+(?:\.\d+){1,2})"),
  )
  for executable, arguments, pattern in checks:
    version = version_match(pattern, local_command(executable, arguments))
    if version is None or (executable == "java" and version[0] != 21):
      raise Rejected("preflight local tool check failed")

  engine = (config or {}).get("engine", "docker" if profile == "ci" else "podman")
  if engine == "docker":
    if not endpoint_is_local(docker_endpoint(), docker=True):
      raise Rejected("preflight local tool check failed")
  elif engine == "podman":
    if not podman_endpoint_is_local():
      raise Rejected("preflight local tool check failed")
  else:
    raise Rejected("preflight local tool check failed")

  engine_version = version_match(
      r"(?:podman version|docker version)\s+(\d+(?:\.\d+){1,2})",
      local_command(engine, ["--version"]))
  if engine_version is None:
    raise Rejected("preflight local tool check failed")
  if engine == "docker":
    daemon = version_match(r"(\d+(?:\.\d+){1,2})",
                           local_command(engine, ["version", "--format", "{{.Server.Version}}" ]))
    buildx = version_match(r"buildx\s+v?(\d+(?:\.\d+){1,2})",
                           local_command(engine, ["buildx", "version"]))
    inventory = local_command(engine, ["image", "ls", "--no-trunc", "--format", "{{json .}}"],
                              max_output_bytes=2 * 1024 * 1024)
    if daemon is None or buildx is None or not validate_inventory(inventory, docker=True):
      raise Rejected("preflight local tool check failed")
  else:
    try:
      info = json.loads(local_command(engine, ["info", "--format", "json"]))
    except (ValueError, RecursionError):
      raise Rejected("preflight local tool check failed") from None
    if (type(info) is not dict or type(info.get("host")) is not dict
        or type(info["host"].get("security")) is not dict
        or info["host"]["security"].get("rootless") is not True):
      raise Rejected("preflight local tool check failed")
    inventory = local_command(engine, ["images", "--no-trunc", "--format", "json"],
                              max_output_bytes=2 * 1024 * 1024)
    if not validate_inventory(inventory, docker=False):
      raise Rejected("preflight local tool check failed")


def build_image(engine: str, run_id: str, name: str, dockerfile: str, context: str, *,
    resolver_sources: Path | None = None, binary_dependencies: Path | None = None,
    source_revision: str | None = None, image_source_sha256: str | None = None,
    image_artifacts_sha256: str | None = None) -> str:
  tag = f"localhost/decent-keycloak/{name}:{run_id}"
  command = [engine, "build", "--no-cache", "--network=none",
             "--label", f"io.decent-keycloak.run-id={run_id}", "--tag", tag,
             "--file", dockerfile]
  if name == "rp-fixture":
    if binary_dependencies is None:
      raise RuntimeError("RP fixture dependency context is unavailable")
    command.extend(["--build-context", f"binary-dependencies={binary_dependencies}"])
  if name == "provider":
    if (resolver_sources is None or binary_dependencies is None or source_revision is None
        or image_source_sha256 is None or image_artifacts_sha256 is None):
      raise RuntimeError("provider build contexts are unavailable")
    command.extend(["--build-arg", f"LIFECYCLE_RUN_ID={run_id}",
                    "--build-arg", f"SOURCE_REVISION={source_revision}",
                    "--build-arg", f"IMAGE_SOURCE_SHA256={image_source_sha256}",
                    "--build-arg", f"IMAGE_ARTIFACTS_SHA256={image_artifacts_sha256}",
                    "--target", "runtime", "--build-context",
                    f"identity-src={resolver_sources / 'identity'}", "--build-context",
                    f"registry-src={resolver_sources / 'registry'}", "--build-context",
                    f"binary-dependencies={binary_dependencies}"])
  command.append(context)
  result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
  if result.returncode:
    raise RuntimeError("image build failed")
  inspect = subprocess.run([engine, "image", "inspect", "--format", "{{.Id}}", tag],
      cwd=ROOT, capture_output=True, text=True, check=False)
  image_id = normalize_image_id(inspect.stdout)
  if inspect.returncode or image_id is None:
    raise RuntimeError("image readback failed")
  return image_id


def provider_build_fingerprints() -> tuple[str, dict[str, str]]:
  try:
    from scripts.lifecycle import fingerprint_source

    fingerprints = fingerprint_source(include_build_artifacts=True, image_target="runtime")
  except (OSError, RuntimeError, ValueError):
    raise Rejected("build source inputs unavailable") from None
  revision = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT,
      capture_output=True, text=True, check=False)
  source_revision = revision.stdout.strip()
  if revision.returncode or re.fullmatch(r"[0-9a-f]{40,64}", source_revision) is None:
    raise Rejected("build source revision unavailable")
  source_sha256 = fingerprints.get("image_source_sha256")
  artifacts_sha256 = fingerprints.get("image_artifacts_sha256")
  if (not isinstance(source_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None
      or not isinstance(artifacts_sha256, str)
      or re.fullmatch(r"[0-9a-f]{64}", artifacts_sha256) is None):
    raise Rejected("build source fingerprints unavailable")
  return source_revision, {
      "image_source_sha256": source_sha256,
      "image_artifacts_sha256": artifacts_sha256,
  }


def materialize_resolver_build_inputs(directory: Path) -> tuple[Path, Path]:
  sources = directory / "sources"
  dependencies = directory / "binary-dependencies"
  environment = dict(os.environ)
  environment["PYTHONDONTWRITEBYTECODE"] = "1"
  environment["GIT_TERMINAL_PROMPT"] = "0"
  commands = (
      [sys.executable, "container/build_resolver_runtime.py", "--materialize-sources",
       "--sources-directory", str(sources)],
      [sys.executable, "container/build_resolver_runtime.py", "--materialize-binary-dependencies",
       "--binary-dependencies-directory", str(dependencies)],
      [sys.executable, "container/verify_resolver_runtime_inputs.py", "--sources", str(sources),
       "--dependencies", str(dependencies)],
  )
  for command in commands:
    try:
      result = subprocess.run(command, cwd=ROOT, env=environment,
                              capture_output=True, text=True, check=False)
    except OSError:
      raise BuildPrerequisiteError from None
    if result.returncode:
      raise BuildPrerequisiteError
  return sources, dependencies


def verify_image_id(engine: str, image_id: str) -> bool:
  inspect = subprocess.run([engine, "image", "inspect", "--format", "{{.Id}}", image_id],
      cwd=ROOT, capture_output=True, text=True, check=False)
  return inspect.returncode == 0 and normalize_image_id(inspect.stdout) == image_id


def normalize_image_id(value: str) -> str | None:
  image_id = value.strip()
  if re.fullmatch(r"[0-9a-f]{64}", image_id):
    return "sha256:" + image_id
  if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
    return image_id
  return None


def build_source_digest() -> str:
  digest = sha256()
  paths = {
      "container/Dockerfile", "container/rp-fixture/Dockerfile",
      "container/build_resolver_runtime.py", "container/verify_resolver_runtime_inputs.py",
      "container/resolver-runtime.lock.json", "container/resolver-binary-dependencies.lock.json",
      "container/resolver-requirements.lock.txt", "container/resolver-build-requirements.lock.txt",
      "container/registry-lock-constraints.txt", "container/resolver-requirements.in",
      "container/rotation_registry_roundtrip.py", "container/patch_resolver_runtime.py",
      "container/pinned_lookup_outcomes.py", "requirements/rp-fixture.lock",
      "scripts/test_pinned_dht_peer_outcomes.py", "scripts/test_pinned_registry_lookup_outcomes.py",
      "scripts/test_pinned_adversarial_identity_peer.py", "scripts/test_rotation_registry_roundtrip.py",
      "scripts/rotation_registry_roundtrip.py", "scripts/issue5_adversarial_cases.py",
      "scripts/oidc_rp_fixture.py", "pom.xml",
      "target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar",
      "target/providers/java-json-canonicalization-1.1.jar",
      "target/providers/core-3.4.0.jar",
  }
  for directory in ("src/main/java", "src/main/resources"):
    root = ROOT / directory
    if not root.is_dir():
      raise ValueError
    paths.update(path.relative_to(ROOT).as_posix() for path in root.rglob("*") if path.is_file())
  for relative in sorted(paths):
    path = ROOT / relative
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
      raise ValueError
    name = relative.encode("utf-8")
    content = path.read_bytes()
    digest.update(len(name).to_bytes(4, "big"))
    digest.update(name)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
  return digest.hexdigest()


def read_build_record(directory: int, name: str, run_id: str) -> dict | None:
  try:
    raw = read_regular(name, dir_fd=directory)
  except FileNotFoundError:
    return None
  value = parse_json(raw)
  if (type(value) is not dict or value.get("version") != 1 or value.get("run_id") != run_id
      or value.get("status") != "verified" or type(value.get("image_id")) is not str
      or re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"]) is None
      or type(value.get("source_sha256")) is not str
      or re.fullmatch(r"[0-9a-f]{64}", value["source_sha256"]) is None
      or type(value.get("config_sha256")) is not str
      or re.fullmatch(r"[0-9a-f]{64}", value["config_sha256"]) is None):
    raise ValueError
  return value


def read_build_bundle(state: dict) -> dict | None:
  try:
    with open_directory((*RUNS, state["run_id"])) as directory:
      raw = read_regular("build.json", dir_fd=directory)
      value = parse_json(raw)
      if (type(value) is not dict or value.keys() != {"version", "run_id", "status", "images"}
          or type(value["version"]) is not int or value["version"] != 1
          or value["run_id"] != state["run_id"] or value["status"] != "complete"):
        raise ValueError
      records = {name: read_build_record(directory, f"{name}.json", state["run_id"])
                 for name in ("provider", "rp-fixture")}
      provider = records["provider"]
      fixture = records["rp-fixture"]
      if provider is None or fixture is None:
        raise ValueError
      records = {"provider": provider, "rp-fixture": fixture}
      if (value["images"] != records
          or any(record["config_sha256"] != state["config_sha256"] for record in records.values())
          or len({record["source_sha256"] for record in records.values()}) != 1):
        raise ValueError
      return {"receipt": value, "digest": sha256(raw).hexdigest(), "records": records}
  except FileNotFoundError:
    return None
  except (OSError, ValueError, RecursionError):
    raise Rejected("build state readback conflict") from None


def read_test_receipt(state: dict, bundle: dict) -> dict | None:
  try:
    with open_directory((*RUNS, state["run_id"])) as directory:
      value = parse_json(read_regular("test.json", dir_fd=directory))
  except FileNotFoundError:
    return None
  except (OSError, ValueError, RecursionError):
    raise Rejected("test state readback conflict") from None
  expected_keys = {"version", "run_id", "status", "build_sha256", "test_source_sha256",
                   "config_sha256", "provider_image_id", "steps"}
  expected_steps = [{"name": name, "status": "pass"} for name in TEST_STEPS]
  if (type(value) is not dict or value.keys() != expected_keys
      or type(value["version"]) is not int or value["version"] != 2
      or value["run_id"] != state["run_id"] or value["status"] != "complete"
      or value["build_sha256"] != bundle["digest"]
      or value["config_sha256"] != state["config_sha256"]
      or value["provider_image_id"] != bundle["records"]["provider"]["image_id"]
      or value["steps"] != expected_steps
      or any(type(value[field]) is not str or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None
             for field in ("build_sha256", "test_source_sha256", "config_sha256"))):
    raise Rejected("test state readback conflict")
  return value


def test_source_digest() -> str:
  digest = sha256()
  paths = {path for directory in (ROOT / "scripts", ROOT / "container")
           for path in directory.rglob("*.py") if path.is_file()}
  paths.update(ROOT / relative for relative in (
      "container/resolver-runtime.lock.json", "container/resolver-binary-dependencies.lock.json",
      "container/resolver-requirements.lock.txt", "container/resolver-build-requirements.lock.txt",
      "requirements/issue8-oidc.lock", "pom.xml", "keycloakctl"))
  config_root = ROOT / "config/keycloakctl"
  if not config_root.is_dir():
    raise ValueError
  paths.update(path for path in config_root.rglob("*") if path.is_file())
  source_root = ROOT / "src"
  if not source_root.is_dir():
    raise ValueError
  paths.update(path for path in source_root.rglob("*") if path.is_file())
  maven_config = ROOT / ".mvn"
  if maven_config.is_dir():
    paths.update(path for path in maven_config.rglob("*") if path.is_file())
  for path in sorted(paths):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
      raise ValueError
    name = path.relative_to(ROOT).as_posix().encode("utf-8")
    content = path.read_bytes()
    digest.update(len(name).to_bytes(4, "big"))
    digest.update(name)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
  return digest.hexdigest()


def record_build_failure(state: dict, phase: str) -> None:
  with open_directory((*RUNS, state["run_id"])) as directory:
    failure = {"version": 1, "run_id": state["run_id"], "phase": phase, "status": "failed"}
    write_exclusive(directory, f"failure-{uuid4().hex}.json", canonical_json(failure))


def package_provider_for_build(state: dict) -> bool:
  environment = dict(os.environ)
  environment["PYTHONDONTWRITEBYTECODE"] = "1"
  environment["GIT_TERMINAL_PROMPT"] = "0"
  environment["MAVEN_SKIP_RC"] = "1"
  command = ["mvn", "--batch-mode", "--no-transfer-progress", "package"]
  try:
    result = subprocess.run(command, cwd=ROOT, env=environment,
        capture_output=True, text=True, check=False, timeout=900)
  except (OSError, subprocess.TimeoutExpired):
    result = None
  if result is not None and result.returncode == 0:
    return True
  record_build_failure(state, "provider-package")
  return False


def perform_build(state: dict, config: dict | None) -> None:
  run_id = state["run_id"]
  engine = (config or {}).get("engine", "podman")
  if engine not in {"podman", "docker"}:
    raise Rejected("unsupported local build engine")
  try:
    with open_directory((*RUNS, run_id)) as run_directory:
      existing_records = {name: read_build_record(run_directory, f"{name}.json", run_id)
                          for name in ("provider", "rp-fixture")}
  except (OSError, ValueError, RecursionError):
    raise Rejected("build state readback conflict") from None
  if not any(existing_records.values()) and not package_provider_for_build(state):
    raise Unavailable("offline provider package failed")
  try:
    try:
      source_sha256 = build_source_digest()
    except (OSError, ValueError):
      raise Rejected("build source inputs unavailable") from None
    source_revision, image_fingerprints = provider_build_fingerprints()
    with open_directory((*RUNS, run_id)) as run_directory:
      try:
        records = {name: read_build_record(run_directory, f"{name}.json", run_id)
                   for name in ("provider", "rp-fixture")}
        for record in records.values():
          if (record is not None and (record["source_sha256"] != source_sha256
              or record["config_sha256"] != state["config_sha256"])):
            raise Rejected("build source or configuration readback conflict")
          if record is not None and not verify_image_id(engine, record["image_id"]):
            raise Rejected("build image readback conflict")
        if any(record is None for record in records.values()):
          with tempfile.TemporaryDirectory(prefix=f"keycloakctl-{run_id}-") as temporary:
            try:
              sources, dependencies = materialize_resolver_build_inputs(Path(temporary))
            except BuildPrerequisiteError:
              failure = {"version": 1, "run_id": run_id,
                         "phase": "resolver-inputs", "status": "failed"}
              write_exclusive(run_directory, f"failure-{uuid4().hex}.json", canonical_json(failure))
              raise Unavailable("provider build prerequisites failed") from None
            for name, dockerfile, context in (
                ("provider", "container/Dockerfile", "."),
                ("rp-fixture", "container/rp-fixture/Dockerfile", ".")):
              if records[name] is not None:
                continue
              try:
                if name == "provider":
                  image_id = build_image(engine, run_id, name, dockerfile, context,
                      resolver_sources=sources, binary_dependencies=dependencies,
                      source_revision=source_revision,
                      image_source_sha256=image_fingerprints["image_source_sha256"],
                      image_artifacts_sha256=image_fingerprints["image_artifacts_sha256"])
                else:
                  image_id = build_image(engine, run_id, name, dockerfile, context,
                      binary_dependencies=dependencies)
                record = {"version": 1, "run_id": run_id, "status": "verified", "image_id": image_id,
                          "source_sha256": source_sha256, "config_sha256": state["config_sha256"]}
                write_exclusive(run_directory, f"{name}.json", canonical_json(record))
                records[name] = record
              except (OSError, RuntimeError, FileExistsError):
                failure = {"version": 1, "run_id": run_id, "phase": name, "status": "failed"}
                write_exclusive(run_directory, f"failure-{uuid4().hex}.json", canonical_json(failure))
                raise Unavailable(f"{name} build or image readback failed") from None
        result = {"version": 1, "run_id": run_id, "status": "complete",
                  "images": records}
        try:
          write_exclusive(run_directory, "build.json", canonical_json(result))
        except FileExistsError:
          existing = parse_json(read_regular("build.json", dir_fd=run_directory))
          if existing != result:
            raise Rejected("build readback conflict") from None
      except Rejected:
        raise
      except (OSError, ValueError, RecursionError):
        raise Rejected("build state readback conflict") from None
  except Rejected:
    raise
  except OSError:
    raise Rejected("build state storage error") from None
  print("build verified")


def record_test_failure(state: dict, phase: str) -> None:
  with open_directory((*RUNS, state["run_id"])) as directory:
    failure = {"version": 1, "run_id": state["run_id"], "phase": phase, "status": "failed"}
    write_exclusive(directory, f"failure-{uuid4().hex}.json", canonical_json(failure))


def perform_test(state: dict, config: dict | None) -> None:
  bundle = read_build_bundle(state)
  if bundle is None:
    raise Rejected("verified build receipt required before test")
  engine = (config or {}).get("engine", "podman")
  if engine not in {"podman", "docker"}:
    raise Rejected("unsupported local test engine")
  try:
    source_sha256 = build_source_digest()
    test_sha256 = test_source_digest()
  except (OSError, ValueError):
    raise Rejected("test source inputs unavailable") from None
  records = bundle["records"]
  if (any(record["source_sha256"] != source_sha256 for record in records.values())
      or any(record["config_sha256"] != state["config_sha256"] for record in records.values())):
    raise Rejected("test build source or configuration readback conflict")
  for record in records.values():
    if not verify_image_id(engine, record["image_id"]):
      raise Rejected("test build image readback conflict")
  provider_image_id = records["provider"]["image_id"]
  prior = read_test_receipt(state, bundle)
  if prior is not None:
    if prior["test_source_sha256"] != test_sha256:
      raise Rejected("test source readback conflict")
    print("test verified")
    return

  environment = dict(os.environ)
  environment["PYTHONDONTWRITEBYTECODE"] = "1"
  environment["GIT_TERMINAL_PROMPT"] = "0"
  environment["MAVEN_SKIP_RC"] = "1"
  java_tests_command = ["mvn", "--offline", "--batch-mode", "--no-transfer-progress", "package"]
  try:
    java_tests = subprocess.run(java_tests_command, cwd=ROOT, env=environment,
        capture_output=True, text=True, check=False, timeout=900)
  except (OSError, subprocess.TimeoutExpired):
    record_test_failure(state, "java-tests")
    raise Unavailable("offline Java test suite failed") from None
  if java_tests.returncode:
    record_test_failure(state, "java-tests")
    raise Unavailable("offline Java test suite failed")

  surefire_command = [sys.executable, "scripts/lifecycle.py", "verify-surefire"]
  try:
    surefire = subprocess.run(surefire_command, cwd=ROOT, env=environment,
        capture_output=True, text=True, check=False, timeout=120)
  except (OSError, subprocess.TimeoutExpired):
    record_test_failure(state, "surefire")
    raise Unavailable("Surefire verification failed") from None
  if surefire.returncode:
    record_test_failure(state, "surefire")
    raise Unavailable("Surefire verification failed")

  try:
    python_tests = subprocess.run([sys.executable, "scripts/lifecycle.py", "python-tests"],
        cwd=ROOT, env=environment, capture_output=True, text=True, check=False, timeout=900)
  except (OSError, subprocess.TimeoutExpired):
    record_test_failure(state, "python-tests")
    raise Unavailable("Python acceptance suite failed") from None
  if python_tests.returncode:
    record_test_failure(state, "python-tests")
    raise Unavailable("Python acceptance suite failed")

  compile_command = [sys.executable, "scripts/lifecycle.py", "python-compile"]
  try:
    python_compile = subprocess.run(compile_command, cwd=ROOT, env=environment,
        capture_output=True, text=True, check=False, timeout=120)
  except (OSError, subprocess.TimeoutExpired):
    record_test_failure(state, "python-compile")
    raise Unavailable("Python compilation failed") from None
  if python_compile.returncode:
    record_test_failure(state, "python-compile")
    raise Unavailable("Python compilation failed")

  smoke_command = [engine, "run", "--rm", "--network=none", "--entrypoint",
                   "/opt/keycloak/bin/kc.sh", provider_image_id, "--version"]
  try:
    smoke = subprocess.run(smoke_command, cwd=ROOT, capture_output=True, text=True,
                           check=False, timeout=120)
    from scripts.lifecycle import java_21_runtime
  except (OSError, subprocess.TimeoutExpired):
    record_test_failure(state, "image-smoke")
    raise Unavailable("provider image smoke failed") from None
  smoke_output = smoke.stdout + smoke.stderr
  if (smoke.returncode or "Keycloak 26.8.0" not in smoke_output
      or not java_21_runtime(smoke_output)):
    record_test_failure(state, "image-smoke")
    raise Unavailable("provider image smoke failed")

  fixture_image_id = records["rp-fixture"]["image_id"]
  fixture_smoke_command = [engine, "run", "--rm", "--network=none", "--entrypoint",
      "python3.11", fixture_image_id, "-c",
      "import sys; sys.path.insert(0, '/opt/rp-fixture'); "
      "import oidc_rp_fixture; print('RP fixture import ok')"]
  try:
    fixture_smoke = subprocess.run(fixture_smoke_command, cwd=ROOT, capture_output=True,
        text=True, check=False, timeout=120)
  except (OSError, subprocess.TimeoutExpired):
    record_test_failure(state, "rp-fixture-smoke")
    raise Unavailable("RP fixture image smoke failed") from None
  if fixture_smoke.returncode or fixture_smoke.stdout.strip() != "RP fixture import ok":
    record_test_failure(state, "rp-fixture-smoke")
    raise Unavailable("RP fixture image smoke failed")

  diff_command = [sys.executable, "scripts/lifecycle.py", "diff-check"]
  try:
    diff_check = subprocess.run(diff_command, cwd=ROOT, env=environment,
        capture_output=True, text=True, check=False, timeout=120)
  except (OSError, subprocess.TimeoutExpired):
    record_test_failure(state, "diff-check")
    raise Unavailable("diff check failed") from None
  if diff_check.returncode:
    record_test_failure(state, "diff-check")
    raise Unavailable("diff check failed")

  receipt: dict | None = None
  try:
    if test_source_digest() != test_sha256:
      record_test_failure(state, "test-inputs-changed")
      raise Unavailable("test inputs changed during execution")
    receipt = {"version": 2, "run_id": state["run_id"], "status": "complete",
               "build_sha256": bundle["digest"], "test_source_sha256": test_sha256,
               "config_sha256": state["config_sha256"], "provider_image_id": provider_image_id,
               "steps": [{"name": name, "status": "pass"} for name in TEST_STEPS]}
    with open_directory((*RUNS, state["run_id"])) as directory:
      write_exclusive(directory, "test.json", canonical_json(receipt))
  except FileExistsError:
    existing = read_test_receipt(state, bundle)
    if receipt is None or existing is None or existing != receipt:
      raise Rejected("test state readback conflict") from None
  except (OSError, ValueError):
    raise Rejected("test state storage error") from None
  print("test verified")


def make_parser() -> Parser:
  help_text = """\
Profiles: dev and ci are local. Readiness is non-qualifying; qualification
is the separate 10-case path with a manual Android evidence checkpoint.
""" + "\n".join(f"  {profile}: {' -> '.join(plan)}" for profile, plan in PLANS.items()) + """
  Qualification teardown is explicit, not part of full.

setup creates a new non-reusable ID unless --run-id reopens it. Other phases
require --run-id (32 lowercase hex digits). full --profile readiness|qualification
requires exactly one of --new-run or --run-id; resume never selects another run.

Use --allow-live on each live invocation (publish, deploy, configure,
integration-test, verify readiness, teardown, and full at a live step).
verify qualification checks same-run evidence; promote requires --allow-publish
and an explicit --destination, separately from publish. These flags do not
replace scoped human approval. Preflight is repeatable and read-only: local
profiles check the host toolchain and selected local engine, while live profiles
check the configured remote target; no deployment or qualification phase is
implemented here.

The `acceptance --profile offline` command runs local preflight, repository suites, provider and RP fixture image builds/smokes, whitespace checks, a sanitized source-bound receipt, and ownership-checked cleanup. CI invokes this same profile. The RP smoke imports the fixture module; it does not start a relying-party server or browser flow. Live qualification, remote host lifecycle, and publication remain separate and gated.
"""
  parser = Parser(prog="keycloakctl", description=__doc__, allow_abbrev=False, epilog=help_text,
                  formatter_class=argparse.RawDescriptionHelpFormatter)
  commands = parser.add_subparsers(dest="command", required=True)
  descriptions = {"setup": "prepare or reopen a local run", "validate-config": "validate non-secret JSON offline",
                  "acceptance": "run local acceptance stages and write a durable receipt",
                  **PHASE_HELP, "full": "create or resume one readiness or qualification run"}
  for name, description in descriptions.items():
    command = commands.add_parser(name, help=description, description=description, allow_abbrev=False)
    if name != "acceptance":
      command.add_argument("--config", required=name == "validate-config", metavar="FILE",
                           help="non-secret JSON file, relative to the caller if not absolute")
    if name == "acceptance":
      command.add_argument("--profile", choices=("offline",), required=True)
    elif name in ("setup", "validate-config", "full"):
      profile_choices = config_fields()["profile"]["enum"] if name == "validate-config" else (
          LIVE_PROFILES if name == "full" else PROFILES)
      command.add_argument("--profile", choices=profile_choices,
                           required=name == "full")
    if name == "full":
      selection = command.add_mutually_exclusive_group(required=True)
      selection.add_argument("--new-run", action="store_true")
      selection.add_argument("--run-id")
    elif name not in ("validate-config", "acceptance"):
      command.add_argument("--run-id", required=name not in ("setup", "promote"))
    if name in LIVE_PHASES or name in ("verify", "full"):
      command.add_argument("--allow-live", action="store_true", help="required on each live invocation")
    if name == "verify":
      command.add_argument("scope", choices=LIVE_PROFILES)
    if name == "promote":
      command.add_argument("--receipt", required=True, help="reviewed promotion receipt")
      command.add_argument("--allow-publish", action="store_true", help="required on this invocation")
      command.add_argument("--destination", required=True, help="explicit docker:// registry/repository:rc-tag")
  fingerprints = commands.add_parser(
      "image-fingerprints", help="print image source/artifact fingerprints",
      description="print image source/artifact fingerprints", allow_abbrev=False)
  fingerprints.add_argument("--target", choices=IMAGE_FINGERPRINT_TARGETS, required=True)
  fingerprints.add_argument("--field", choices=("image_source_sha256", "image_artifacts_sha256"),
                            required=True)
  images = commands.add_parser(
      "images", help="manage local image retention", description="manage local image retention",
      allow_abbrev=False)
  images.add_argument("--engine", choices=("podman", "docker"),
                      help="container engine (default: CONTAINER_ENGINE, then Podman/Docker)")
  image_actions = images.add_subparsers(dest="image_action", required=True)
  cleanup = image_actions.add_parser(
      "cleanup", help="remove expired, inactive repository-built images only", allow_abbrev=False)
  cleanup.add_argument("--max-age-days", type=int, help="retention age in days")
  for action in ("pin", "unpin"):
    pin = image_actions.add_parser(action, help=f"{action} a named local image retention tag",
                                   allow_abbrev=False)
    pin.add_argument("image")
    pin.add_argument("name")
  extend = image_actions.add_parser(
      "extend", help="extend local image retention for a bounded number of days", allow_abbrev=False)
  extend.add_argument("image")
  extend.add_argument("days", type=int)
  return parser


def acceptance_source_provenance() -> dict:
  """Return shared lifecycle provenance for the current source tree."""
  from scripts.lifecycle import fingerprint_source, local_source_provenance
  return {**local_source_provenance(ROOT), **fingerprint_source()}


def surefire_report_snapshot() -> dict[Path, tuple[int, int, int]]:
  reports = sorted((ROOT / "target/surefire-reports").glob("TEST-*.xml"))
  return {report: (report.stat().st_mtime_ns, report.stat().st_ctime_ns, report.stat().st_size)
          for report in reports}


def verify_surefire_reports(before_maven: dict[Path, tuple[int, int, int]] | None = None) -> int:
  reports = sorted((ROOT / "target/surefire-reports").glob("TEST-*.xml"))
  if not reports:
    print("Surefire produced no XML reports", file=sys.stderr)
    return 2
  if before_maven is not None:
    after_maven = surefire_report_snapshot()
    stale = [report for report in reports
             if before_maven.get(report) == after_maven.get(report)]
    if stale:
      print("Surefire reports were not refreshed by this Maven invocation", file=sys.stderr)
      return 2
  suites = []
  try:
    for report in reports:
      root = ET.parse(report).getroot()
      suites.extend([root] if root.tag == "testsuite" else root.findall(".//testsuite"))
    if not suites:
      print("Surefire reports contain no testsuite records", file=sys.stderr)
      return 2
    totals = {key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
              for key in ("tests", "failures", "errors", "skipped")}
  except (ET.ParseError, OSError, ValueError) as error:
    print(f"invalid Surefire report: {type(error).__name__}", file=sys.stderr)
    return 2
  print("Surefire totals: " + ", ".join(f"{key}={value}" for key, value in totals.items()))
  return 0 if totals["tests"] > 0 and all(totals[key] == 0 for key in ("failures", "errors", "skipped")) else 1


def verify_provider_registration() -> int:
  jar = ROOT / "target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar"
  if not jar.is_file():
    print("provider JAR is missing", file=sys.stderr)
    return 2
  descriptor = "META-INF/services/org.keycloak.authentication.AuthenticatorFactory"
  expected = "org.decentwallet.keycloak.wallet.WalletChallengeAuthenticatorFactory"
  try:
    with zipfile.ZipFile(jar) as archive:
      lines = archive.read(descriptor).decode("utf-8").splitlines()
  except (KeyError, OSError, UnicodeDecodeError, zipfile.BadZipFile) as error:
    print(f"provider service registration is invalid: {type(error).__name__}", file=sys.stderr)
    return 2
  if expected not in lines:
    print("provider factory is not registered in the production JAR", file=sys.stderr)
    return 1
  print("provider service registration verified")
  return 0


def verify_diff_check() -> int:
  """Check the PR commit range and every local tracked/untracked change."""
  commands = []
  pull_request_base = os.environ.get("PR_BASE_SHA")
  if pull_request_base:
    commands.append(["git", "diff", "--check", f"{pull_request_base}...HEAD"])
  commands.append(["git", "diff", "--check", "HEAD"])
  for command in commands:
    try:
      checked = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", check=False)
    except (OSError, UnicodeError):
      print("git whitespace check could not run", file=sys.stderr)
      return 2
    if checked.stdout:
      print(checked.stdout, end="", flush=True)
    if checked.stderr:
      print(checked.stderr, end="", file=sys.stderr, flush=True)
    if checked.returncode:
      return checked.returncode

  try:
    untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard", "-z"],
                               cwd=ROOT, capture_output=True, check=False)
  except OSError:
    print("untracked-file whitespace check could not run", file=sys.stderr)
    return 2
  if untracked.returncode:
    if untracked.stderr:
      print(os.fsdecode(untracked.stderr), end="", file=sys.stderr, flush=True)
    return untracked.returncode
  paths_output = untracked.stdout
  if isinstance(paths_output, str):
    paths_output = os.fsencode(paths_output)
  for raw_path in sorted(filter(None, paths_output.split(bytes((0,))))):
    command = ["git", "diff", "--no-index", "--check", "--", "/dev/null", os.fsdecode(raw_path)]
    try:
      checked = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", check=False)
    except (OSError, UnicodeError):
      print("untracked-file whitespace check could not run", file=sys.stderr)
      return 2
    if checked.stdout:
      print(checked.stdout, end="", flush=True)
    if checked.stderr:
      print(checked.stderr, end="", file=sys.stderr, flush=True)
    if checked.returncode not in (0, 1):
      return checked.returncode
  return 0


def acceptance_stages() -> tuple[tuple[str, list[str]], ...]:
  """Return the offline acceptance checks owned by keycloakctl."""
  return (
      ("java-tests", ["mvn", "--batch-mode", "--no-transfer-progress", "package"]),
      ("surefire", []),
      ("provider-service-registration", []),
      ("python-tests", []),
      ("python-compile", [sys.executable, "-c",
          "from pathlib import Path; import py_compile; "
          "[py_compile.compile(str(path), doraise=True) for folder in ('scripts', 'container') "
          "for path in Path(folder).glob('*.py')]"]),
      ("diff-check", ["git", "diff", "--check"]),
  )


def write_acceptance_receipt(receipt: dict) -> Path:
  directory = ROOT / "target/keycloakctl/acceptance"
  directory.mkdir(parents=True, exist_ok=True)
  path = directory / f"{receipt['run_id']}.json"
  temporary = directory / f".{receipt['run_id']}.tmp"
  with temporary.open("xb") as output:
    output.write(canonical_json(receipt))
    output.flush()
    os.fsync(output.fileno())
  os.replace(temporary, path)
  return path


def run_acceptance(profile: str) -> int:
  """Run the local offline acceptance profile and persist its outcome."""
  if profile != "offline":
    print("error: acceptance supports only the offline profile", file=sys.stderr)
    return 2
  try:
    source = acceptance_source_provenance()
  except (OSError, UnicodeError, RuntimeError, ValueError):
    print("error: acceptance source provenance unavailable", file=sys.stderr)
    return 2
  receipt = {"version": 2, "run_id": uuid4().hex, "profile": profile,
             "status": "running", "source": source, "stages": []}
  try:
    status = acceptance_run_stages(profile, receipt)
  except Exception:
    status = 2
  if status:
    receipt["status"] = "failed"
    try:
      path = write_acceptance_receipt(receipt)
    except OSError:
      print("error: acceptance failure receipt could not be written", file=sys.stderr)
      return 2
    print(f"error: acceptance stage failed; receipt: {path}", file=sys.stderr)
    return 2
  receipt["status"] = "complete"
  try:
    path = write_acceptance_receipt(receipt)
    stored = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_members)
    if stored != receipt:
      raise ValueError
  except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
    print("error: acceptance receipt verification failed", file=sys.stderr)
    return 2
  print(f"acceptance verified: {path}")
  return 0


def acceptance_run_stages(profile: str, receipt: dict) -> int:
  """Execute the offline local gates and remove only this run's images."""
  from scripts.lifecycle import _cleanup_owned_images, _image_inventory
  engine = "docker" if os.environ.get("CI", "").lower() == "true" else "podman"
  config = {"version": 1, "profile": "dev", "engine": engine}
  state = create_run(config)
  receipt["run_id"] = state["run_id"]
  write_acceptance_receipt(receipt)
  engine = config["engine"]
  baseline: set[str] = set()
  baseline_captured = False
  build_started = False
  failed = False
  def record(name: str, status: str) -> None:
    receipt["stages"].append({"name": name, "status": status})
    write_acceptance_receipt(receipt)
  def stage(name: str, action) -> bool:
    nonlocal failed
    try:
      action()
      record(name, "pass")
      return True
    except Exception:
      record(name, "fail")
      failed = True
      return False
  try:
    if not stage("preflight", lambda: perform_local_preflight(config, "dev")):
      return 2
    baseline = _image_inventory(engine)
    baseline_captured = True
    before = surefire_report_snapshot()
    if not stage("java-tests", lambda: require_zero(run_acceptance_command("maven", before))): return 2
    if not stage("surefire", lambda: require_zero(verify_surefire_reports(before))): return 2
    if not stage("provider-service-registration", lambda: require_zero(verify_provider_registration())): return 2
    if not stage("python-tests", lambda: require_zero(run_acceptance_command("python-tests"))): return 2
    if not stage("python-compile", lambda: require_zero(run_acceptance_command("python-compile"))): return 2
    build_started = True
    if not stage("provider-image-build", lambda: perform_build(state, config)): return 2
    record("rp-fixture-image-build", "pass")
    if not stage("image-smoke", lambda: perform_test(state, config)): return 2
    record("rp-fixture-smoke", "pass")
    if not stage("diff-check", lambda: require_zero(verify_diff_check())): return 2
  finally:
    try:
      if build_started and baseline_captured:
        bundle = read_build_bundle(state)
        owned = {record["image_id"] for record in bundle["records"].values()} if bundle else set()
        result = _cleanup_owned_images(engine, baseline, state["run_id"], known_owned_ids=owned)
        if result.get("status") != "pass" or result.get("inconclusive_image_count"):
          raise RuntimeError("cleanup readback failed")
      record("cleanup", "pass")
    except Exception:
      record("cleanup", "fail")
      failed = True
  return 2 if failed else 0


def require_zero(result: int) -> None:
  if result != 0:
    raise RuntimeError("acceptance stage failed")


def run_acceptance_command(stage: str, before=None) -> int:
  environment = dict(os.environ)
  environment.update({"PYTHONDONTWRITEBYTECODE": "1", "GIT_TERMINAL_PROMPT": "0", "MAVEN_SKIP_RC": "1"})
  if stage == "maven":
    command = ["mvn", "--batch-mode", "--no-transfer-progress", "package"]
  elif stage == "python-tests":
    from scripts.lifecycle import run_python_tests
    return run_python_tests()
  elif stage == "python-compile":
    command = [sys.executable, "scripts/lifecycle.py", "python-compile"]
  else:
    return 1
  try:
    return subprocess.run(command, cwd=ROOT, env=environment, capture_output=True,
                          text=True, check=False, timeout=900).returncode
  except (OSError, subprocess.TimeoutExpired):
    return 1


def run_image_fingerprints(target: str, field: str) -> int:
  """Print one validated fingerprint for an image target and its build inputs."""
  from scripts.lifecycle import IMAGE_BUILD_ARTIFACTS_BY_TARGET, fingerprint_source
  if target not in IMAGE_BUILD_ARTIFACTS_BY_TARGET:
    raise Rejected("unknown image target")
  if field not in ("image_source_sha256", "image_artifacts_sha256"):
    raise Rejected("unknown image fingerprint field")
  try:
    fingerprints = fingerprint_source(include_build_artifacts=True, image_target=target)
  except (OSError, RuntimeError, ValueError):
    raise Rejected("image fingerprint failed") from None
  value = fingerprints.get(field)
  if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
    raise Rejected("image fingerprint result is invalid")
  print(value)
  return 0


def run_image_lifecycle(args: argparse.Namespace) -> int:
  """Run a public local image-retention operation through the shared helpers."""
  from scripts import image_lifecycle
  try:
    engine = image_lifecycle.selected_engine(args.engine)
    if args.image_action == "cleanup":
      max_age_days = args.max_age_days
      if max_age_days is None:
        max_age_days = int(os.environ.get(
            "DECENT_IMAGE_RETENTION_DAYS", str(image_lifecycle.DEFAULT_RETENTION_DAYS)))
      result = image_lifecycle.cleanup_images(engine, max_age_days=max_age_days)
      print(json.dumps({"status": "pass", **result}, sort_keys=True))
    elif args.image_action == "pin":
      image_lifecycle.pin_image(engine, args.image, args.name)
      print("pin=created")
    elif args.image_action == "unpin":
      image_lifecycle.unpin_image(engine, args.image, args.name)
      print("pin=removed")
    else:
      image_lifecycle.extend_image(engine, args.image, args.days)
      print("retention=extended")
    return 0
  except (OSError, RuntimeError, ValueError) as error:
    print(f"image lifecycle failed: {type(error).__name__}: {error}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
  parser = make_parser()
  args = parser.parse_args(argv)
  try:
    if args.command == "image-fingerprints":
      return run_image_fingerprints(args.target, args.field)
    if args.command == "images":
      return run_image_lifecycle(args)
    if args.command == "acceptance":
      return run_acceptance(args.profile)
    elif args.command == "validate-config":
      load_config(args.config, args.profile)
      print("configuration valid")
    elif args.command == "setup":
      state, _ = new_run(args) if args.run_id is None else checked_run(args)
      print(state["run_id"])
    elif args.command == "full":
      state, config = new_run(args) if args.new_run else checked_run(args)
      if args.new_run:
        print(state["run_id"], flush=True)
      phase = next_phase(state)
      if phase is None:
        raise Rejected("run has no pending phases")
      authorize(phase, args)
      attempt_phase(phase, state, config)
    elif args.command == "promote":
      authorize("promote", args)
      raise Unavailable("promote unavailable in the offline foundation")
    else:
      phase = f"verify {args.scope}" if args.command == "verify" else args.command
      authorize(phase, args)
      state, config = checked_run(args)
      if phase == "build":
        guard_phase(phase, state, config)
        perform_build(state, config)
      elif phase == "test":
        guard_phase(phase, state, config)
        perform_test(state, config)
      else:
        attempt_phase(phase, state, config)
    return 0
  except Rejected as error:
    print(f"error: {error}", file=sys.stderr)
    return 3 if isinstance(error, Unavailable) else 2


if __name__ == "__main__":
  raise SystemExit(main())
