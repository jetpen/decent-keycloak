#!/usr/bin/env python3
"""Canonical local/CI lifecycle entry point for this repository."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PYTHON_TESTS = (
  "scripts.test_wallet_login_result",
  "scripts.test_wallet_login_transport_e2e",
  "scripts.test_owner_rotation_probe",
  "scripts.test_signup_intent_probe",
  "scripts.test_self_contained_resolver_runtime",
  "scripts.test_owner_rotation_envelope",
  "scripts.test_live_gate_order",
  "scripts.test_registry_acceptance_matrix",
  "scripts.test_issue7_user_readback_profile",
  "scripts.test_issue7_store_recovery_profile",
  "scripts.test_acceptance_ledger",
  "scripts.test_acceptance_workflow",
  "scripts.test_issue6_single_node_profile",
  "scripts.test_lifecycle",
)
PROFILES = {
  "offline": {
    "description": "Preflight, unit/acceptance suites, pinned resolver image build, smoke, evidence and teardown.",
    "live": False,
  },
  "ci": {
    "description": "The same deterministic offline lifecycle used locally, run by CI.",
    "live": False,
  },
  "issue5-live": {
    "description": "Offline lifecycle followed by explicitly authorized Issue #5 loopback qualification.",
    "live": True,
  },
}
ISSUE5_GATES = {
  "current_identity": "not_run",
  "exact_missing_identity": "not_run",
  "registry_unavailable": "not_run",
  "malformed_result": "not_run",
  "history_incomplete": "not_run",
  "ambiguous_registry_result": "not_run",
  "valid_current_key_proof": "not_run",
  "stale_key_denial": "not_run",
  "owner_key_rotation": "not_run",
  "independent_rotation_readback": "not_run",
}
PYTHON_TEST_MODULES = tuple(name.rsplit(".", 1)[-1] for name in PYTHON_TESTS)


def python_suite_command() -> list[str]:
  return [sys.executable, "scripts/lifecycle.py", "python-tests"]


def compile_sources_command() -> list[str]:
  return [
    sys.executable,
    "-c",
    "from pathlib import Path; import py_compile; "
    "[py_compile.compile(str(path), doraise=True) for folder in ('scripts', 'container') "
    "for path in Path(folder).glob('*.py')]",
  ]


def core_test_stages() -> list[tuple[str, list[str] | None]]:
  return [
    ("java-tests", ["mvn", "--batch-mode", "--no-transfer-progress", "clean", "package"]),
    ("surefire", [sys.executable, "scripts/lifecycle.py", "verify-surefire"]),
    ("python-tests", python_suite_command()),
    ("python-compile", compile_sources_command()),
  ]


def plan(profile: str) -> dict:
  steps: list[dict] = [
    {"name": "preflight", "command": [sys.executable, "scripts/lifecycle.py", "preflight"]},
  ]
  steps.extend({"name": name, "command": command} for name, command in core_test_stages())
  steps.extend([
    {"name": "resolver-sources", "action": "materialize and verify pinned Identity/Registry commits in a run-owned temporary directory"},
    {"name": "resolver-dependencies", "action": "download and hash-verify locked PyPI/UBI artifacts in a run-owned temporary directory"},
    {"name": "provider-service-registration", "command": [sys.executable, "scripts/lifecycle.py", "verify-provider"]},
    {"name": "provider-image", "action": "build runtime image with named resolver contexts, no-cache, and network-isolated RUN steps"},
    {"name": "image-smoke", "action": "run pinned Keycloak/JVM version smoke against the immutable built image"},
    {"name": "diff-check", "command": [sys.executable, "scripts/lifecycle.py", "diff-check"]},
  ])
  if profile == "issue5-live":
    steps.append({"name": "issue5-live-matrix", "command": [sys.executable, "scripts/wallet_login_live_e2e.py"],
                  "env": {"WALLET_IT_PROFILE": "full", "WALLET_IT_IMAGE": "<run-built immutable ID>"},
                  "requires": ["--allow-live"]})
  steps.extend([
    {"name": "evidence", "action": "retain the finalized sanitized lifecycle receipt"},
    {"name": "teardown", "action": "remove only the run-owned immutable image tag and temporary source/dependency inputs"},
  ])
  return {"profile": profile, "steps": steps}


def run(command: list[str], *, env: dict[str, str] | None = None) -> int:
  print("+ " + shlex.join(command), flush=True)
  return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


def capture_command(command: list[str]) -> subprocess.CompletedProcess[str]:
  print("+ " + shlex.join(command), flush=True)
  return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)


def diff_check() -> int:
  pull_request_base = os.environ.get("PR_BASE_SHA")
  if pull_request_base:
    return run(["git", "diff", "--check", f"{pull_request_base}...HEAD"])

  result = run(["git", "diff", "--check", "HEAD"])
  if result:
    return result
  untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard", "-z"],
                             cwd=ROOT, capture_output=True, check=False)
  if untracked.returncode:
    return untracked.returncode
  for raw_path in sorted(filter(None, untracked.stdout.split(bytes((0,))))):
    path = os.fsdecode(raw_path)
    command = ["git", "diff", "--no-index", "--check", "--", "/dev/null", path]
    print("+ " + shlex.join(command), flush=True)
    checked = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if checked.stdout:
      print(checked.stdout, end="", flush=True)
    if checked.stderr:
      print(checked.stderr, end="", file=sys.stderr, flush=True)
    if checked.returncode not in (0, 1):
      return checked.returncode
  return 0


def check_tool(name: str, command: list[str], expected: str) -> bool:
  try:
    result = capture_command(command)
  except FileNotFoundError:
    print(f"preflight: missing required tool: {name}", file=sys.stderr)
    return False
  if result.returncode:
    print(f"preflight: missing or failed required tool: {name}", file=sys.stderr)
    return False
  output = (result.stdout + result.stderr).strip()
  print(f"preflight: {name}: {output.splitlines()[0] if output else 'no version output'}")
  if expected not in output:
    print(f"preflight: expected {name} version containing {expected!r}", file=sys.stderr)
    return False
  return True


def container_engine() -> str:
  selected = os.environ.get("CONTAINER_ENGINE")
  if selected:
    return selected
  if shutil.which("podman"):
    return "podman"
  if shutil.which("docker"):
    return "docker"
  return ""


def preflight(*, live: bool = False) -> int:
  checks = [
    check_tool("Python", [sys.executable, "--version"], "3.11.13"),
    check_tool("Java", ["java", "-version"], "21."),
    check_tool("Maven", ["mvn", "--version"], "Apache Maven"),
    check_tool("Git", ["git", "--version"], "git version"),
  ]
  engine = container_engine()
  if engine not in {"podman", "docker"}:
    print("preflight: missing supported container engine (Podman or Docker Buildx)", file=sys.stderr)
    checks.append(False)
  else:
    checks.append(check_tool("container engine", [engine, "--version"], "version"))
    info_command = ([engine, "info", "--format", "{{json .}}"] if engine == "docker"
                    else [engine, "info", "--format", "json"])
    try:
      info = subprocess.run(info_command, cwd=ROOT, text=True, capture_output=True, check=False)
    except FileNotFoundError:
      info = None
    if info is None or info.returncode:
      print("preflight: container engine daemon is unavailable", file=sys.stderr)
      checks.append(False)
    else:
      print("preflight: container engine daemon is ready")
      checks.append(True)
    if engine == "docker":
      checks.append(check_tool("Docker Buildx", ["docker", "buildx", "version"], "github.com/docker/buildx"))
  if live:
    checks.append(check_tool("OpenSSL", ["openssl", "version"], "OpenSSL"))
  return 0 if all(checks) else 2


def verify_surefire() -> int:
  reports = sorted((ROOT / "target/surefire-reports").glob("TEST-*.xml"))
  if not reports:
    print("Surefire produced no XML reports", file=sys.stderr)
    return 2
  suites = []
  try:
    for report in reports:
      root = ET.parse(report).getroot()
      suites.extend([root] if root.tag == "testsuite" else root.findall(".//testsuite"))
  except (ET.ParseError, OSError) as error:
    print(f"invalid Surefire report: {type(error).__name__}", file=sys.stderr)
    return 2
  if not suites:
    print("Surefire reports contain no testsuite records", file=sys.stderr)
    return 2
  totals = {key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
            for key in ("tests", "failures", "errors", "skipped")}
  print("Surefire totals: " + ", ".join(f"{key}={value}" for key, value in totals.items()))
  return 0 if totals["tests"] > 0 and all(totals[key] == 0 for key in ("failures", "errors", "skipped")) else 1


def verify_provider() -> int:
  jar = ROOT / "target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar"
  if not jar.is_file():
    print("provider JAR is missing", file=sys.stderr)
    return 2
  import zipfile
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


def digest_file(path: Path) -> str:
  return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint_source() -> dict:
  revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                            capture_output=True, check=False)
  diff = subprocess.run(["git", "diff", "--binary", "HEAD"], cwd=ROOT,
                        capture_output=True, check=False)
  untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard", "-z"],
                             cwd=ROOT, capture_output=True, check=False)
  if revision.returncode or diff.returncode or untracked.returncode:
    raise RuntimeError("unable to fingerprint source snapshot")
  untracked_hash = hashlib.sha256()
  path_separator = bytes((0,))
  for raw_path in sorted(filter(None, untracked.stdout.split(path_separator))):
    path = Path(os.fsdecode(raw_path))
    try:
      payload = (ROOT / path).read_bytes()
    except OSError as error:
      raise RuntimeError("unable to fingerprint untracked source input") from error
    untracked_hash.update(raw_path + path_separator + hashlib.sha256(payload).digest())
  return {
    "revision": revision.stdout.strip(),
    "worktree_diff_sha256": hashlib.sha256(diff.stdout).hexdigest(),
    "untracked_inputs_sha256": untracked_hash.hexdigest(),
    "harness_sha256": digest_file(ROOT / "scripts/wallet_login_live_e2e.py"),
    "resolver_manifest_sha256": digest_file(ROOT / "container/resolver-runtime.lock.json"),
    "resolver_dependency_provenance_sha256": digest_file(ROOT / "container/resolver-binary-dependencies.lock.json"),
    "resolver_requirements_sha256": digest_file(ROOT / "container/resolver-requirements.lock.txt"),
  }


def write_receipt(receipt_path: Path, receipt: dict) -> None:
  receipt_path.parent.mkdir(parents=True, exist_ok=True)
  temporary_path = receipt_path.with_suffix(".json.tmp")
  temporary_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
  temporary_path.replace(receipt_path)


def run_python_tests() -> int:
  with tempfile.TemporaryDirectory(prefix="decent-keycloak-tests-") as temporary:
    run_dir = Path(temporary)
    install_dir = run_dir / "site-packages"
    sources = run_dir / "resolver-sources"
    env = dict(os.environ)
    env["PIP_CACHE_DIR"] = str(run_dir / "pip-cache")
    commands = (
      [sys.executable, "container/build_resolver_runtime.py", "--materialize-sources",
       "--sources-directory", str(sources)],
      [sys.executable, "container/verify_resolver_runtime_inputs.py", "--sources", str(sources)],
      [sys.executable, "-m", "pip", "install", "--require-hashes", "--no-compile",
       "--target", str(install_dir), "-r", "container/resolver-requirements.lock.txt"],
    )
    for command in commands:
      result = run(command, env=env)
      if result:
        return result
    registry_file = sources / "registry/src/decent_registry/dht/libp2p_dht.py"
    result = run([
      sys.executable, "container/patch_resolver_runtime.py", "--site-packages",
      str(install_dir), "--registry-file", str(registry_file),
    ])
    if result:
      return result
    env = dict(os.environ)
    source_paths = [str(install_dir), str(sources / "identity/src"), str(sources / "registry/src")]
    env["PYTHONPATH"] = os.pathsep.join(source_paths + [env.get("PYTHONPATH", "")])
    suite = [sys.executable, "-m", "unittest", *PYTHON_TESTS, "-q"]
    return run(suite, env=env)


def compile_sources() -> int:
  return run(compile_sources_command())


def _record_step(receipt: dict, path: Path, name: str, status: str, *, detail: str | None = None) -> None:
  receipt["steps"][name] = {"status": status}
  if detail:
    receipt["steps"][name]["detail"] = detail
  receipt["updated_at"] = datetime.now(timezone.utc).isoformat()
  write_receipt(path, receipt)


def _engine_command(engine: str, tag: str, sources: Path, dependencies: Path) -> list[str]:
  identity = str(sources / "identity")
  registry = str(sources / "registry")
  if engine == "docker":
    return ["docker", "buildx", "build", "--platform", "linux/amd64", "--pull",
            "--no-cache", "--load", "--network=none", "--build-context",
            f"identity-src={identity}", "--build-context", f"registry-src={registry}",
            "--build-context", f"binary-dependencies={dependencies}",
            "--file", "container/Dockerfile", "--target", "runtime", "--tag", tag, "."]
  return ["podman", "build", "--no-cache", "--pull=never", "--network=none",
          "--build-context", f"identity-src={identity}", "--build-context",
          f"registry-src={registry}", "--build-context", f"binary-dependencies={dependencies}",
          "--file", "container/Dockerfile", "--target",
          "runtime", "--tag", tag, "."]


def normalize_image_id(value: str) -> str | None:
  image_id = value.strip()
  if re.fullmatch(r"[0-9a-f]{64}", image_id):
    return f"sha256:{image_id}"
  if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
    return image_id
  return None


def image_smoke_command(engine: str, image_id: str) -> list[str]:
  return [engine, "run", "--rm", "--entrypoint", "/opt/keycloak/bin/kc.sh", image_id, "--version"]


def _image_inspect_command(engine: str, image: str) -> list[str]:
  return [engine, "image", "inspect", "--format", "{{.Id}}", image]


def _image_remove(engine: str, tag: str, expected_id: str) -> int:
  exists = capture_command(_image_inspect_command(engine, tag))
  if exists.returncode:
    return 0
  actual_id = normalize_image_id(exists.stdout)
  if actual_id != expected_id:
    print("cleanup: refusing to remove a tag whose immutable ID changed", file=sys.stderr)
    return 2
  result = run([engine, "image", "rm", tag])
  if result:
    return result
  remaining = capture_command(_image_inspect_command(engine, tag))
  return 1 if remaining.returncode == 0 else 0


def _cleanup_run_image(engine: str, tag: str, expected_id: str | None) -> int:
  inspected = capture_command(_image_inspect_command(engine, tag))
  if inspected.returncode:
    return 0
  actual_id = normalize_image_id(inspected.stdout)
  if actual_id is None or (expected_id is not None and actual_id != expected_id):
    print("cleanup: refusing to remove a run tag with an unknown or changed immutable ID", file=sys.stderr)
    return 2
  return _image_remove(engine, tag, actual_id)


def _run_capture(command: list[str], *, env: dict[str, str] | None = None) -> tuple[int, str]:
  result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
  if result.stdout:
    print(result.stdout, end="", flush=True)
  if result.stderr:
    print(result.stderr, end="", file=sys.stderr, flush=True)
  return result.returncode, result.stdout + result.stderr


def run_profile(profile: str, *, pull_base: bool = False) -> int:
  run_id = uuid.uuid4().hex
  preflight_status = preflight(live=profile == "issue5-live")
  receipt_path = ROOT / "target/lifecycle/evidence" / f"{run_id}.json"
  profile_steps = [step["name"] for step in plan(profile)["steps"]]
  receipt = {
    "schema_version": 1,
    "run_id": run_id,
    "profile": profile,
    "started_at": datetime.now(timezone.utc).isoformat(),
    "source": fingerprint_source(),
    "steps": {name: {"status": "not_run"} for name in profile_steps},
    "issue5_acceptance_gates": dict(ISSUE5_GATES),
    "image": {"status": "not_built"},
    "cleanup": {"status": "not_run"},
  }
  write_receipt(receipt_path, receipt)
  engine = container_engine()
  tag = f"decent-keycloak-wallet-provider:lifecycle-{run_id}"
  built_image_id: str | None = None
  image_build_started = False
  source_parent: tempfile.TemporaryDirectory[str] | None = None
  failure_code = 0
  current_step: str | None = None
  try:
    if preflight_status:
      failure_code = 2
      _record_step(receipt, receipt_path, "preflight", "fail", detail="tool_or_version_mismatch")
      return failure_code
    _record_step(receipt, receipt_path, "preflight", "pass")

    for name, command in core_test_stages():
      current_step = name
      if name == "surefire":
        result = verify_surefire()
      elif name == "python-tests":
        result = run_python_tests()
      elif name == "python-compile":
        result = compile_sources()
      else:
        assert command is not None
        result = run(command)
      if result:
        _record_step(receipt, receipt_path, name, "fail", detail=f"exit_{result}")
        failure_code = result
        return failure_code
      _record_step(receipt, receipt_path, name, "pass")
      current_step = None

    current_step = "resolver-sources"
    source_parent = tempfile.TemporaryDirectory(prefix=f"decent-resolver-{run_id}-")
    run_inputs = Path(source_parent.name)
    sources = run_inputs / "sources"
    result = run([sys.executable, "container/build_resolver_runtime.py", "--materialize-sources",
                  "--sources-directory", str(sources)])
    if result:
      _record_step(receipt, receipt_path, "resolver-sources", "fail", detail=f"exit_{result}")
      return result
    _record_step(receipt, receipt_path, "resolver-sources", "pass")
    current_step = None
    dependencies = run_inputs / "binary-dependencies"
    current_step = "resolver-dependencies"
    result = run([sys.executable, "container/build_resolver_runtime.py",
        "--materialize-binary-dependencies", "--binary-dependencies-directory", str(dependencies)])
    if result:
      _record_step(receipt, receipt_path, "resolver-dependencies", "fail", detail=f"exit_{result}")
      return result
    result = run([sys.executable, "container/verify_resolver_runtime_inputs.py", "--sources", str(sources),
                  "--dependencies", str(dependencies)])
    if result:
      _record_step(receipt, receipt_path, "resolver-dependencies", "fail", detail=f"exit_{result}")
      return result
    _record_step(receipt, receipt_path, "resolver-dependencies", "pass")
    current_step = None

    current_step = "provider-service-registration"
    result = verify_provider()
    if result:
      _record_step(receipt, receipt_path, "provider-service-registration", "fail", detail=f"exit_{result}")
      return result
    _record_step(receipt, receipt_path, "provider-service-registration", "pass")
    current_step = None

    current_step = "provider-image"
    before = capture_command(_image_inspect_command(engine, tag))
    if before.returncode == 0:
      _record_step(receipt, receipt_path, "provider-image", "fail", detail="run_owned_tag_collision")
      return 2
    build_command = _engine_command(engine, tag, sources, dependencies)
    if engine == "podman" and pull_base:
      build_command[build_command.index("--pull=never")] = "--pull=always"
    image_build_started = True
    result = run(build_command)
    if result:
      _record_step(receipt, receipt_path, "provider-image", "fail", detail=f"exit_{result}")
      return result
    _record_step(receipt, receipt_path, "provider-image", "pass")
    inspected = capture_command(_image_inspect_command(engine, tag))
    if inspected.returncode or not inspected.stdout.strip():
      _record_step(receipt, receipt_path, "provider-image", "fail", detail="immutable_id_unavailable")
      return 2
    built_image_id = normalize_image_id(inspected.stdout)
    if built_image_id is None:
      _record_step(receipt, receipt_path, "provider-image", "fail", detail="immutable_id_invalid")
      return 2
    receipt["image"] = {"status": "built", "engine": engine, "run_owned_tag": tag,
                        "immutable_id": built_image_id}
    write_receipt(receipt_path, receipt)

    current_step = None
    current_step = "image-smoke"
    smoke_command = image_smoke_command(engine, built_image_id)
    smoke_status, smoke_output = _run_capture(smoke_command)
    if smoke_status or "Keycloak 26.8.0" not in smoke_output or "JVM: 21.0.12.1" not in smoke_output:
      _record_step(receipt, receipt_path, "image-smoke", "fail", detail="runtime_version_mismatch")
      return smoke_status or 1
    _record_step(receipt, receipt_path, "image-smoke", "pass")
    current_step = "diff-check"
    result = diff_check()
    if result:
      _record_step(receipt, receipt_path, "diff-check", "fail", detail=f"exit_{result}")
      return result
    _record_step(receipt, receipt_path, "diff-check", "pass")
    current_step = None

    if profile == "issue5-live":
      current_step = "issue5-live-matrix"
      assert built_image_id is not None
      live_env = dict(os.environ)
      live_env["WALLET_IT_IMAGE"] = built_image_id
      live_env["WALLET_IT_PROFILE"] = "full"
      live_status, live_output = _run_capture(
          [sys.executable, "scripts/wallet_login_live_e2e.py"], env=live_env)
      evidence_prefix = "evidence="
      if live_status:
        _record_step(receipt, receipt_path, "issue5-live-matrix", "fail",
                     detail=f"exit_{live_status}")
        return live_status
      evidence_lines = [line[len(evidence_prefix):]
                        for line in live_output.splitlines() if line.startswith(evidence_prefix)]
      if len(evidence_lines) != 1:
        _record_step(receipt, receipt_path, "issue5-live-matrix", "fail",
                     detail="sanitized_evidence_missing_or_ambiguous")
        return 2
      try:
        live_evidence = json.loads(evidence_lines[0])
      except json.JSONDecodeError:
        _record_step(receipt, receipt_path, "issue5-live-matrix", "fail",
                     detail="sanitized_evidence_invalid")
        return 2
      if not isinstance(live_evidence, dict):
        _record_step(receipt, receipt_path, "issue5-live-matrix", "fail",
                     detail="sanitized_evidence_invalid")
        return 2
      receipt["issue5_live_evidence"] = live_evidence
      _record_step(receipt, receipt_path, "issue5-live-matrix", "pass",
                   detail="harness_completed_evidence_retained_gates_unmapped")
      current_step = None
    return 0
  except KeyboardInterrupt:
    failure_code = 130
    receipt["interrupted"] = True
    if current_step and receipt["steps"][current_step]["status"] == "not_run":
      _record_step(receipt, receipt_path, current_step, "interrupted", detail="keyboard_interrupt")
    return failure_code
  except Exception as error:
    failure_code = 2
    receipt["failure_category"] = type(error).__name__
    if current_step and receipt["steps"][current_step]["status"] == "not_run":
      _record_step(receipt, receipt_path, current_step, "fail", detail=f"exception_{type(error).__name__}")
    print(f"lifecycle failed: {type(error).__name__}", file=sys.stderr)
    return failure_code
  finally:
    cleanup_failures: list[str] = []
    if source_parent is not None:
      try:
        source_parent.cleanup()
      except OSError:
        cleanup_failures.append("temporary_source_cleanup_failed")
    if image_build_started:
      image_cleanup = _cleanup_run_image(engine, tag, built_image_id)
      if image_cleanup:
        cleanup_failures.append("image_cleanup_failed")
    cleanup_code = 2 if cleanup_failures else 0
    receipt["cleanup"] = {"status": "pass" if cleanup_code == 0 else "fail"}
    if cleanup_failures:
      failure_code = cleanup_code
      receipt["cleanup"]["detail"] = ",".join(cleanup_failures)
    for item in receipt["steps"].values():
      if item["status"] != "fail" or failure_code:
        continue
      detail = item.get("detail", "")
      failure_code = int(detail[5:]) if detail.startswith("exit_") and detail[5:].isdigit() else 1
    receipt["steps"]["evidence"] = {"status": "pass"}
    receipt["steps"]["teardown"] = {"status": "pass" if cleanup_code == 0 else "fail"}
    receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
    receipt["exit_code"] = failure_code
    write_receipt(receipt_path, receipt)
    print(f"lifecycle receipt: {receipt_path}")
    if cleanup_code:
      raise SystemExit(cleanup_code)


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description=__doc__)
  subparsers = parser.add_subparsers(dest="action", required=True)
  profiles_parser = subparsers.add_parser("profiles", help="list named lifecycle profiles")
  profiles_parser.add_argument("--json", action="store_true")
  subparsers.add_parser("preflight", help="check required pinned tools")
  subparsers.add_parser("python-tests", help="run the canonical Python acceptance suite")
  subparsers.add_parser("python-compile", help="compile all lifecycle Python sources")
  subparsers.add_parser("verify-surefire", help="require nonempty passing Surefire reports")
  subparsers.add_parser("verify-provider", help="verify production provider SPI registration")
  subparsers.add_parser("diff-check", help="validate committed-base, staged, unstaged and untracked whitespace")
  run_parser = subparsers.add_parser("run", help="run a named lifecycle profile")
  run_parser.add_argument("profile", choices=sorted(PROFILES))
  run_parser.add_argument("--plan", action="store_true", help="print the plan without running it")
  run_parser.add_argument("--json", action="store_true", help="emit plan as JSON")
  run_parser.add_argument("--allow-live", action="store_true", help="authorize live loopback qualification")
  run_parser.add_argument("--pull-base-images", action="store_true",
                          help="allow the Podman engine to pull pinned base images")
  args = parser.parse_args(argv)

  if args.action == "profiles":
    print(json.dumps(PROFILES, sort_keys=True) if args.json else "\n".join(
      f"{name}: {details['description']}" for name, details in PROFILES.items()))
    return 0
  if args.action == "preflight":
    return preflight()
  if args.action == "python-tests":
    return run_python_tests()
  if args.action == "python-compile":
    return compile_sources()
  if args.action == "verify-surefire":
    return verify_surefire()
  if args.action == "verify-provider":
    return verify_provider()
  if args.action == "diff-check":
    return diff_check()
  if args.profile == "issue5-live" and not args.allow_live:
    parser.error("issue5-live requires explicit --allow-live authorization")
  execution_plan = plan(args.profile)
  if args.plan:
    print(json.dumps(execution_plan, sort_keys=True) if args.json else "\n".join(
      f"{step['name']}: {shlex.join(step['command']) if 'command' in step else step['action']}"
      for step in execution_plan["steps"]))
    return 0
  if args.json:
    parser.error("--json is only valid with --plan")
  return run_profile(args.profile, pull_base=args.pull_base_images)


if __name__ == "__main__":
  raise SystemExit(main())
