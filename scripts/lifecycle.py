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
  "mixed_legacy_rotated_head": "not_run",
  "valid_current_key_proof": "not_run",
  "stale_key_denial": "not_run",
  "owner_key_rotation": "not_run",
  "independent_rotation_readback": "not_run",
  "account_denial_concurrency": "not_run",
  "runtime_provider": "not_run",
}
ISSUE5_ADVERSARIAL_CASES = {
  "malformed_result": "hostile-peer-malformed",
  "history_incomplete": "hostile-peer-history-incomplete",
  "ambiguous_registry_result": "hostile-peer-ambiguous",
  "mixed_legacy_rotated_head": "hostile-peer-mixed-head",
}
ISSUE5_LIVE_MATRIX_PROFILE = "default"


def issue5_acceptance_gate_set_complete(gates: object) -> bool:
  if not isinstance(gates, dict):
    return False
  expected = {
      name: ("unavailable" if name in ISSUE5_ADVERSARIAL_CASES else "pass")
      for name in ISSUE5_GATES
  }
  return gates == expected


def issue5_adversarial_gate_statuses(evidence: object) -> dict[str, str]:
  """Map only two complete fail-closed attempts per hostile fixture to unavailable."""
  matrix = evidence.get("registry_matrix") if isinstance(evidence, dict) else None
  statuses: dict[str, str] = {}
  for case_name, fixture_label in ISSUE5_ADVERSARIAL_CASES.items():
    case = matrix.get(case_name) if isinstance(matrix, dict) else None
    attempts = case.get("attempts") if isinstance(case, dict) else None
    attempt_items = attempts if isinstance(attempts, list) and len(attempts) == 2 else []
    qualified = len(attempt_items) == 2
    for attempt in attempt_items:
      if not isinstance(attempt, dict):
        qualified = False
        break
      digests_valid = all(
          isinstance(attempt.get(field), str)
          and re.fullmatch(r"[0-9a-f]{64}", attempt[field]) is not None
          for field in ("fixture_source_sha256", "fixture_case_constants_sha256"))
      if not (
          attempt.get("fixture_evidence") == "test-only-hostile-peer"
          and attempt.get("fixture") == fixture_label
          and digests_valid
          and attempt.get("direct_resolution") == "unavailable"
          and attempt.get("provider_http") == 503
          and attempt.get("status_http") == 200
          and attempt.get("status_pending") is True
          and attempt.get("no_acceptance_or_callback") is True
          and attempt.get("no_authorization_code") is True
          and attempt.get("fixture_cli_key_observed") is True
          and attempt.get("fixture_provider_key_observed") is True
          and attempt.get("fixture_all_provider_peers_observed") is True
      ):
        qualified = False
        break
    statuses[case_name] = "unavailable" if qualified else "inconclusive"
  return statuses


def _issue5_two_attempt_status(evidence: object, case_name: str,
    required_fields: set[str], predicate) -> str:
  matrix = evidence.get("registry_matrix") if isinstance(evidence, dict) else None
  case = matrix.get(case_name) if isinstance(matrix, dict) else None
  attempts = case.get("attempts") if isinstance(case, dict) else None
  if (not isinstance(attempts, list) or len(attempts) != 2
      or any(not isinstance(attempt, dict) or not required_fields.issubset(attempt)
          for attempt in attempts)):
    return "inconclusive"
  return "pass" if all(predicate(attempt) for attempt in attempts) else "fail"


def issue5_account_denial_gate_status(evidence: object) -> str:
  concurrency = evidence.get('account_denial_concurrency') if isinstance(evidence, dict) else None
  if not isinstance(concurrency, dict):
    return 'inconclusive'
  required = {'case_count', 'max_concurrent_flows', 'overlap_observed',
      'all_policy_denied', 'all_request_correlated'}
  if not required.issubset(concurrency):
    return 'inconclusive'
  count = concurrency['case_count']
  maximum = concurrency['max_concurrent_flows']
  overlap = concurrency['overlap_observed']
  if (type(count) is not int or count != 3
      or type(maximum) is not int or not 2 <= maximum <= 3
      or overlap is not True
      or type(concurrency['all_policy_denied']) is not bool
      or type(concurrency['all_request_correlated']) is not bool):
    return 'inconclusive'
  if concurrency['all_policy_denied'] is not True or concurrency['all_request_correlated'] is not True:
    return 'fail'
  cases = evidence.get('account_denial_cases')
  expected_cases = {'unmapped-account', 'disabled-account', 'ambiguous-account'}
  if not isinstance(cases, dict) or set(cases) != expected_cases:
    return 'inconclusive'
  required_case_facts = (
      'local_account_mapping_decision_observed', 'request_correlated_denial',
      'status_pending', 'no_acceptance_or_callback', 'no_authorization_code',
      'response_body_safe', 'headers_safe', 'location_safe', 'redirects_safe',
  )
  for case in cases.values():
    if not isinstance(case, dict):
      return 'inconclusive'
    if any(field not in case for field in required_case_facts) or 'outcome' not in case:
      return 'inconclusive'
    if (case.get('outcome') != 'policy_denied'
        or case.get('current_registry_proof_http') != 403
        or any(case.get(field) is not True for field in required_case_facts)):
      return 'fail'
  return 'pass'


def issue5_runtime_provider_gate_status(evidence: object) -> str:
  runtime = evidence.get('resolver_runtime') if isinstance(evidence, dict) else None
  if not isinstance(runtime, dict):
    return 'inconclusive'
  if (runtime.get('runtime_qualification_status') != 'runtime_facts_verified'
      or runtime.get('single_use_object_provider_path') != 'infinispan'
      or runtime.get('single_use_object_provider_evidence') != 'request_correlated_consumed_transaction'
      or type(runtime.get('transaction_consume_witness_count')) is not int
      or not 1 <= runtime['transaction_consume_witness_count'] <= 2
      or runtime.get('database_mode_effective') in (None, 'unavailable')
      or runtime.get('cache_mode_effective') in (None, 'unavailable')):
    return 'inconclusive'
  if (runtime.get('database_mode_effective') != 'dev-file'
      or runtime.get('cache_mode_effective') != 'local'):
    return 'fail'
  return 'pass'


def issue5_live_matrix_gate_statuses(evidence: object) -> dict[str, str]:
  """Map the ordinary two-attempt Registry matrix to explicit receipt gates."""
  matrix = evidence.get("registry_matrix") if isinstance(evidence, dict) else None
  current_fields = {"direct_resolution", "exact_readback", "provider_http",
      "status_http", "status_pending", "outcome"}
  missing_fields = {"direct_resolution", "provider_http", "status_http", "status_pending",
      "no_acceptance_or_callback", "no_authorization_code", "provider_identity_log_read",
      "provider_identity_not_found_observed", "provider_identity_not_found_marker_count", "outcome"}
  unavailable_fields = {"direct_resolution", "provider_http", "status_http", "status_pending",
      "no_acceptance_or_callback", "no_authorization_code", "outcome"}
  rotation_fields = {"direct_resolution", "exact_readback", "provider_http", "rotation_publish",
      "current_sequence", "stale_key_proof_http", "current_key_proof_http",
      "stale_transaction_remains_pending", "current_transaction_accepted", "outcome"}
  current = _issue5_two_attempt_status(evidence, "current_identity", current_fields,
      lambda attempt: attempt["direct_resolution"] == "resolved"
          and attempt["exact_readback"] is True and attempt["provider_http"] == 202
          and attempt["status_http"] == 200 and attempt["status_pending"] is False
          and attempt["outcome"] == "current_accepted")
  missing = _issue5_two_attempt_status(evidence, "missing_identity", missing_fields,
      lambda attempt: attempt["direct_resolution"] == "not_found"
          and attempt["provider_http"] == 401 and attempt["status_http"] == 200
          and attempt["status_pending"] is True
          and attempt["no_acceptance_or_callback"] is True
          and attempt["no_authorization_code"] is True
          and attempt["provider_identity_log_read"] is True
          and attempt["provider_identity_not_found_observed"] is True
          and attempt["provider_identity_not_found_marker_count"] == 1
          and attempt["outcome"] == "provider_not_found")
  unavailable = _issue5_two_attempt_status(evidence, "unavailable_registry", unavailable_fields,
      lambda attempt: attempt["direct_resolution"] == "unavailable"
          and attempt["provider_http"] == 503 and attempt["status_http"] == 200
          and attempt["status_pending"] is True
          and attempt["no_acceptance_or_callback"] is True
          and attempt["no_authorization_code"] is True
          and attempt["outcome"] == "registry_unavailable")
  unavailable_case = matrix.get("unavailable_registry") if isinstance(matrix, dict) else None
  if unavailable == "pass":
    if not isinstance(unavailable_case, dict) or any(
        field not in unavailable_case for field in
            ("bootstrap_override_readback", "bootstrap_restore_readback")):
      unavailable = "inconclusive"
    elif any(unavailable_case[field] is not True for field in
        ("bootstrap_override_readback", "bootstrap_restore_readback")):
      unavailable = "fail"
  rotation = _issue5_two_attempt_status(evidence, "rotation", rotation_fields,
      lambda attempt: attempt["direct_resolution"] == "resolved"
          and attempt["exact_readback"] is True and attempt["provider_http"] == 202
          and attempt["rotation_publish"] == "passed"
          and attempt["stale_key_proof_http"] == 401
          and attempt["current_key_proof_http"] == 202
          and attempt["stale_transaction_remains_pending"] is True
          and attempt["current_transaction_accepted"] is True
          and attempt["outcome"] == "current_accepted")
  rotation_case = matrix.get("rotation") if isinstance(matrix, dict) else None
  rotation_attempts = rotation_case.get("attempts") if isinstance(rotation_case, dict) else None
  rotation_attempts = rotation_attempts if isinstance(rotation_attempts, list) else []
  sequences = [attempt.get("current_sequence") if isinstance(attempt, dict) else None
      for attempt in rotation_attempts]
  independent_readback = _issue5_two_attempt_status(evidence, "rotation",
      {"rotation_publish", "current_sequence", "independent_rotation_readback"},
      lambda attempt: attempt["rotation_publish"] == "passed"
          and type(attempt["current_sequence"]) is int
          and attempt["independent_rotation_readback"] is True)
  if (independent_readback == "pass" and sequences != [2, 3]):
    independent_readback = "fail"
  rotated_identity = evidence.get("rotated_identity_case") if isinstance(evidence, dict) else None
  owner_rotation = rotation
  if rotation == "pass":
    if independent_readback != "pass":
      owner_rotation = "inconclusive" if independent_readback == "inconclusive" else "fail"
    elif not isinstance(rotated_identity, dict) or "local_mapping_persisted" not in rotated_identity:
      owner_rotation = "inconclusive"
    elif rotated_identity["local_mapping_persisted"] is not True:
      owner_rotation = "fail"
  runtime_provider = issue5_runtime_provider_gate_status(evidence)
  account_denial = issue5_account_denial_gate_status(evidence)
  return {
      "current_identity": current,
      "exact_missing_identity": missing,
      "registry_unavailable": unavailable,
      "valid_current_key_proof": rotation,
      "stale_key_denial": rotation,
      "owner_key_rotation": owner_rotation,
      "independent_rotation_readback": independent_readback,
      "account_denial_concurrency": account_denial,
      "runtime_provider": runtime_provider,
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


def plan(profile: str, *, retain_image: bool = False) -> dict:
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
                  "env": {"WALLET_IT_PROFILE": ISSUE5_LIVE_MATRIX_PROFILE, "WALLET_IT_IMAGE": "<run-built immutable ID>"},
                  "requires": ["--allow-live"]})
    steps.append({"name": "issue5-adversarial", "command": [sys.executable, "scripts/wallet_login_live_e2e.py"],
                  "env": {"WALLET_IT_PROFILE": "issue5-adversarial", "WALLET_IT_IMAGE": "<run-built immutable ID>"},
                  "requires": ["--allow-live"]})
  teardown_action = (
      "remove run-owned immutable image and temporary source/dependency inputs unless explicitly retained"
      if not retain_image else
      "retain run-owned immutable image by explicit opt-in; remove temporary source/dependency inputs")
  steps.extend([
    {"name": "evidence", "action": "retain the finalized sanitized lifecycle receipt"},
    {"name": "teardown", "action": teardown_action},
  ])
  return {"profile": profile, "steps": steps, "retain_image_requested": retain_image}


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
    image_list_command = _image_inventory_command(engine)
    image_list_result = subprocess.run(image_list_command, cwd=ROOT, text=True,
        capture_output=True, check=False)
    if image_list_result.returncode:
      print("preflight: container image inventory is unavailable", file=sys.stderr)
      checks.append(False)
    else:
      print("preflight: container image inventory is readable")
      checks.append(True)
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


IMAGE_SOURCE_FILES = (
  "container/Dockerfile",
  "container/rotation_registry_roundtrip.py",
  "container/verify_resolver_runtime_inputs.py",
  "container/patch_resolver_runtime.py",
  "container/pinned_lookup_outcomes.py",
  "scripts/test_pinned_dht_peer_outcomes.py",
  "scripts/test_pinned_registry_lookup_outcomes.py",
  "scripts/test_pinned_adversarial_identity_peer.py",
  "scripts/test_rotation_registry_roundtrip.py",
  "scripts/rotation_registry_roundtrip.py",
  "scripts/issue5_adversarial_cases.py",
)
IMAGE_SOURCE_DIRECTORIES = ("src/main/java", "src/main/resources")
IMAGE_BUILD_ARTIFACT_FILES = (
  "target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar",
  "target/providers/java-json-canonicalization-1.1.jar",
  "target/providers/core-3.4.0.jar",
)


def _digest_named_files(paths: list[Path]) -> tuple[str, int]:
  digest = hashlib.sha256()
  for path in sorted(paths):
    relative = path.relative_to(ROOT).as_posix().encode("utf-8")
    payload = path.read_bytes()
    digest.update(len(relative).to_bytes(4, "big"))
    digest.update(relative)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
  return digest.hexdigest(), len(paths)


def fingerprint_source(*, include_build_artifacts: bool = False) -> dict:
  """Fingerprint only repository inputs used to construct the container image."""
  source_paths = {ROOT / relative for relative in IMAGE_SOURCE_FILES}
  for relative in IMAGE_SOURCE_DIRECTORIES:
    directory = ROOT / relative
    if directory.is_dir():
      source_paths.update(path for path in directory.rglob("*") if path.is_file())
  missing_sources = [path for path in source_paths if not path.is_file()]
  if missing_sources:
    raise RuntimeError("unable to fingerprint a required container image source input")
  source_hash, source_count = _digest_named_files(list(source_paths))
  fingerprint = {
    "image_source_sha256": source_hash,
    "image_source_file_count": source_count,
  }
  if include_build_artifacts:
    artifact_paths = [ROOT / relative for relative in IMAGE_BUILD_ARTIFACT_FILES]
    if any(not path.is_file() for path in artifact_paths):
      raise RuntimeError("unable to fingerprint a required container image artifact")
    artifact_hash, artifact_count = _digest_named_files(artifact_paths)
    fingerprint.update({
      "image_artifacts_sha256": artifact_hash,
      "image_artifact_file_count": artifact_count,
    })
  return fingerprint


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


def _engine_command(engine: str, tag: str, sources: Path, dependencies: Path,
    *, run_id: str) -> list[str]:
  identity = str(sources / "identity")
  registry = str(sources / "registry")
  build_args = ["--build-arg", f"LIFECYCLE_RUN_ID={run_id}"]
  if engine == "docker":
    return ["docker", "buildx", "build", "--platform", "linux/amd64", "--pull",
            "--no-cache", "--load", "--network=none", *build_args, "--build-context",
            f"identity-src={identity}", "--build-context", f"registry-src={registry}",
            "--build-context", f"binary-dependencies={dependencies}",
            "--file", "container/Dockerfile", "--target", "runtime", "--tag", tag, "."]
  return ["podman", "build", "--no-cache", "--pull=never", "--network=none",
          *build_args, "--build-context", f"identity-src={identity}", "--build-context",
          f"registry-src={registry}", "--build-context", f"binary-dependencies={dependencies}",
          "--file", "container/Dockerfile", "--target",
          "runtime", "--tag", tag, "."]


def _image_remove_command(engine: str, image_id: str) -> list[str]:
  return [engine, "image", "rm", image_id]


def _image_remove_tag_command(engine: str, tag: str) -> list[str]:
  return [engine, "image", "rm", tag]


def _image_tag_command(engine: str, image_id: str, tag: str) -> list[str]:
  return [engine, "image", "tag", image_id, tag]


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


def _image_inventory_command(engine: str) -> list[str]:
  if engine not in {"podman", "docker"}:
    raise ValueError("unsupported container engine")
  return [engine, "image", "ls", "--all", "--no-trunc", "--quiet"]


def _image_inventory(engine: str) -> set[str]:
  result = capture_command(_image_inventory_command(engine))
  if result.returncode:
    raise RuntimeError("image_inventory_unavailable")
  image_ids: set[str] = set()
  for line in result.stdout.splitlines():
    if not line.strip():
      continue
    image_id = normalize_image_id(line)
    if image_id is None:
      raise RuntimeError("image_inventory_id_invalid")
    image_ids.add(image_id)
  return image_ids


def _image_metadata_command(engine: str, image_id: str) -> list[str]:
  return [engine, "image", "inspect", "--format", "{{json .}}", image_id]


def _image_metadata(engine: str, image_id: str) -> dict | None:
  result = capture_command(_image_metadata_command(engine, image_id))
  if result.returncode:
    return None
  try:
    payload = json.loads(result.stdout)
  except json.JSONDecodeError as error:
    raise RuntimeError("image_inspect_invalid") from error
  if isinstance(payload, list):
    payload = payload[0] if len(payload) == 1 else None
  if not isinstance(payload, dict):
    raise RuntimeError("image_inspect_invalid")
  actual_id = normalize_image_id(str(payload.get("Id", "")))
  if actual_id != image_id:
    raise RuntimeError("image_inspect_identity_mismatch")
  return payload


def _image_labels(metadata: dict) -> dict:
  config = metadata.get("Config")
  labels = config.get("Labels") if isinstance(config, dict) else None
  if not isinstance(labels, dict):
    labels = metadata.get("Labels")
  return labels if isinstance(labels, dict) else {}


def _image_parent(metadata: dict) -> str | None:
  parent = metadata.get("Parent")
  if not isinstance(parent, str) or not parent:
    return None
  normalized = normalize_image_id(parent)
  if normalized is None:
    raise RuntimeError("image_parent_id_invalid")
  return normalized


def _remove_image_by_id(engine: str, image_id: str) -> int:
  return run(_image_remove_command(engine, image_id))


def _image_remove(engine: str, tag: str, expected_id: str) -> int:
  exists = capture_command(_image_inspect_command(engine, tag))
  if exists.returncode:
    return 0
  actual_id = normalize_image_id(exists.stdout)
  if actual_id != expected_id:
    return 2
  if run(_image_remove_tag_command(engine, tag)):
    return 1
  remaining = capture_command(_image_inspect_command(engine, tag))
  return 1 if remaining.returncode == 0 else 0


def _image_removal_order(metadata_by_id: dict[str, dict]) -> list[str]:
  """Order run-owned images leaf-first so children never pin their parents."""
  parents = {image_id: _image_parent(metadata) for image_id, metadata in metadata_by_id.items()}
  depth_cache: dict[str, int] = {}

  def depth(image_id: str, active: set[str]) -> int:
    if image_id in depth_cache:
      return depth_cache[image_id]
    if image_id in active:
      raise RuntimeError("image_parent_cycle")
    parent = parents.get(image_id)
    if parent not in parents:
      depth_cache[image_id] = 0
    else:
      depth_cache[image_id] = depth(parent, active | {image_id}) + 1
    return depth_cache[image_id]

  return sorted(metadata_by_id, key=lambda image_id: (depth(image_id, set()), image_id), reverse=True)


def _owned_image_snapshot(engine: str, baseline_ids: set[str], run_id: str) -> set[str]:
  """Capture build-created IDs and owner labels before later lifecycle stages run."""
  candidates = _image_inventory(engine) - baseline_ids
  owned: set[str] = set()
  for image_id in candidates:
    metadata = _image_metadata(engine, image_id)
    if metadata is not None and _image_labels(metadata).get(
        "io.decent.lifecycle.run-id") == run_id:
      owned.add(image_id)
  return owned


def _cleanup_owned_images(engine: str, baseline_ids: set[str], run_id: str,
    *, known_owned_ids: set[str] | None = None,
    retain_image_id: str | None = None) -> dict:
  after_ids = _image_inventory(engine)
  candidates = after_ids - baseline_ids
  known_owned_ids = known_owned_ids or set()
  owned_metadata: dict[str, dict] = {}
  uninspectable_candidates: set[str] = set()
  initially_inconclusive_uninspectable: set[str] = set()
  inconclusive_image_ids: set[str] = set()
  unowned_count = 0
  for image_id in sorted(candidates):
    try:
      metadata = _image_metadata(engine, image_id)
    except RuntimeError:
      metadata = None
    if metadata is None:
      uninspectable_candidates.add(image_id)
      if image_id not in known_owned_ids:
        initially_inconclusive_uninspectable.add(image_id)
        inconclusive_image_ids.add(image_id)
      continue
    if _image_labels(metadata).get("io.decent.lifecycle.run-id") != run_id:
      if image_id in known_owned_ids:
        inconclusive_image_ids.add(image_id)
        continue
      unowned_count += 1
      continue
    owned_metadata[image_id] = metadata

  retained = False
  if retain_image_id is not None and retain_image_id in owned_metadata:
    try:
      metadata = _image_metadata(engine, retain_image_id)
    except RuntimeError:
      metadata = None
    if metadata is not None and _image_labels(metadata).get(
        "io.decent.lifecycle.run-id") == run_id:
      retained = True
      owned_metadata.pop(retain_image_id)
    else:
      inconclusive_image_ids.add(retain_image_id)
  elif retain_image_id is not None:
    inconclusive_image_ids.add(retain_image_id)

  removed: list[str] = []
  confirmed_absent: set[str] = set()
  for image_id in _image_removal_order(owned_metadata):
    # An earlier removal may have pruned this exact owned parent already.
    if image_id in confirmed_absent:
      continue
    # Re-read identity and ownership immediately before deleting the exact ID.
    try:
      metadata = _image_metadata(engine, image_id)
    except RuntimeError:
      metadata = None
    if metadata is None:
      if image_id in _image_inventory(engine):
        inconclusive_image_ids.add(image_id)
      else:
        confirmed_absent.add(image_id)
      continue
    if _image_labels(metadata).get("io.decent.lifecycle.run-id") != run_id:
      inconclusive_image_ids.add(image_id)
      continue
    if _remove_image_by_id(engine, image_id):
      inconclusive_image_ids.add(image_id)
      continue
    removed.append(image_id)
    # A normal image removal may prune dangling parent layers. Confirm exact
    # candidate absence now so a later loop iteration does not treat it as a
    # failed readback; any still-present parent will be inspected normally.
    for parent_id in _image_removal_order(owned_metadata):
      if parent_id == image_id or parent_id in confirmed_absent:
        continue
      if parent_id in _image_inventory(engine):
        continue
      confirmed_absent.add(parent_id)
      inconclusive_image_ids.discard(parent_id)

  remaining = _image_inventory(engine)
  # Podman may list transient intermediate IDs that it cannot inspect; deleting
  # an owned descendant can remove them transitively. Only remaining IDs need
  # a successful ownership readback, while disappearance is confirmed by the
  # complete immutable-ID inventory.
  for image_id in sorted(uninspectable_candidates):
    if image_id not in remaining and image_id in initially_inconclusive_uninspectable:
      inconclusive_image_ids.discard(image_id)
    elif image_id in remaining:
      inconclusive_image_ids.add(image_id)
  missing_after_cleanup = sorted(image_id for image_id in removed if image_id in remaining)
  still_owned = []
  for image_id in sorted(remaining - baseline_ids):
    try:
      metadata = _image_metadata(engine, image_id)
    except RuntimeError:
      metadata = None
    if metadata is None:
      if image_id in known_owned_ids:
        inconclusive_image_ids.add(image_id)
      continue
    if image_id == retain_image_id:
      continue
    if _image_labels(metadata).get("io.decent.lifecycle.run-id") == run_id:
      still_owned.append(image_id)
    elif image_id in known_owned_ids:
      inconclusive_image_ids.add(image_id)
  inconclusive_image_ids.update(missing_after_cleanup)
  inconclusive_image_ids.update(still_owned)
  if retained:
    if retain_image_id not in remaining:
      inconclusive_image_ids.add(retain_image_id)
    else:
      try:
        retained_metadata = _image_metadata(engine, retain_image_id)
      except RuntimeError:
        retained_metadata = None
      if retained_metadata is None or _image_labels(retained_metadata).get(
          "io.decent.lifecycle.run-id") != run_id:
        retained = False
        inconclusive_image_ids.add(retain_image_id)
  return {
      "status": "pass" if not inconclusive_image_ids else "fail",
      "baseline_image_count": len(baseline_ids),
      "baseline_image_ids": sorted(baseline_ids),
      "candidate_image_count": len(candidates),
      "removed_image_count": len(removed),
      "removed_image_ids": sorted(removed),
      "retained_image_id": retain_image_id if retained else None,
      "unowned_new_image_count": unowned_count,
      "inconclusive_image_count": len(inconclusive_image_ids),
      "image_retained": retained,
  }


def _run_capture(command: list[str], *, env: dict[str, str] | None = None) -> tuple[int, str]:
  result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
  if result.stdout:
    print(result.stdout, end="", flush=True)
  if result.stderr:
    print(result.stderr, end="", file=sys.stderr, flush=True)
  return result.returncode, result.stdout + result.stderr


def run_profile(profile: str, *, pull_base: bool = False, retain_image: bool = False) -> int:
  run_id = uuid.uuid4().hex
  preflight_status = preflight(live=profile == "issue5-live")
  receipt_path = ROOT / "target/lifecycle/evidence" / f"{run_id}.json"
  profile_steps = [step["name"] for step in plan(profile, retain_image=retain_image)["steps"]]
  receipt = {
    "schema_version": 1,
    "run_id": run_id,
    "profile": profile,
    "started_at": datetime.now(timezone.utc).isoformat(),
    "source": fingerprint_source(),
    "steps": {name: {"status": "not_run"} for name in profile_steps},
    "issue5_acceptance_gates": dict(ISSUE5_GATES),
    "image": {"status": "not_built", "retention_requested": retain_image, "retained": False},
    "cleanup": {"status": "not_run", "image_retained": False,
        "baseline_image_count": 0, "baseline_image_ids": [],
        "baseline_image_ids_sha256": None,
        "candidate_image_count": 0, "removed_image_count": 0,
        "removed_image_ids": [], "retained_image_id": None,
        "unowned_new_image_count": 0, "inconclusive_image_count": 0},
  }
  write_receipt(receipt_path, receipt)
  engine = container_engine()
  tag = f"decent-keycloak-wallet-provider:lifecycle-{run_id}"
  built_image_id: str | None = None
  image_build_started = False
  baseline_image_ids: set[str] | None = None
  known_owned_image_ids: set[str] = set()
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
    build_fingerprint = fingerprint_source(include_build_artifacts=True)
    if (receipt["source"].get("image_source_sha256")
        != build_fingerprint.get("image_source_sha256")):
      _record_step(receipt, receipt_path, "provider-image", "fail",
                   detail="image_source_changed_during_lifecycle")
      return 2
    receipt["source"] = build_fingerprint
    write_receipt(receipt_path, receipt)
    baseline_image_ids = _image_inventory(engine)
    receipt["image"]["baseline_image_count"] = len(baseline_image_ids)
    receipt["image"]["baseline_image_ids"] = sorted(baseline_image_ids)
    receipt["image"]["baseline_image_ids_sha256"] = hashlib.sha256(
        "\n".join(sorted(baseline_image_ids)).encode()).hexdigest()
    write_receipt(receipt_path, receipt)
    before = capture_command(_image_inspect_command(engine, tag))
    if before.returncode == 0:
      _record_step(receipt, receipt_path, "provider-image", "fail", detail="run_owned_tag_collision")
      return 2
    build_command = _engine_command(engine, tag, sources, dependencies, run_id=run_id)
    if engine == "podman" and pull_base:
      build_command[build_command.index("--pull=never")] = "--pull=always"
    image_build_started = True
    result = run(build_command)
    if result:
      try:
        known_owned_image_ids = _owned_image_snapshot(engine, baseline_image_ids, run_id)
      except Exception:
        known_owned_image_ids = set()
      _record_step(receipt, receipt_path, "provider-image", "fail", detail=f"exit_{result}")
      return result
    post_build_fingerprint = fingerprint_source(include_build_artifacts=True)
    if post_build_fingerprint != receipt["source"]:
      _record_step(receipt, receipt_path, "provider-image", "fail",
                   detail="image_inputs_changed_during_build")
      return 2
    _record_step(receipt, receipt_path, "provider-image", "pass")
    inspected = capture_command(_image_inspect_command(engine, tag))
    if inspected.returncode or not inspected.stdout.strip():
      _record_step(receipt, receipt_path, "provider-image", "fail", detail="immutable_id_unavailable")
      return 2
    built_image_id = normalize_image_id(inspected.stdout)
    if built_image_id is None:
      _record_step(receipt, receipt_path, "provider-image", "fail", detail="immutable_id_invalid")
      return 2
    known_owned_image_ids = _owned_image_snapshot(engine, baseline_image_ids, run_id)
    if built_image_id not in known_owned_image_ids:
      _record_step(receipt, receipt_path, "provider-image", "fail", detail="run_image_ownership_unverified")
      return 2
    receipt["image"] = {"status": "built", "engine": engine, "run_owned_tag": tag,
                        "immutable_id": built_image_id,
                        "baseline_image_count": len(baseline_image_ids),
                        "baseline_image_ids": sorted(baseline_image_ids),
                        "baseline_image_ids_sha256": hashlib.sha256(
                            "\n".join(sorted(baseline_image_ids)).encode()).hexdigest(),
                        "retention_requested": retain_image, "retained": False}
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
      live_env["WALLET_IT_PROFILE"] = ISSUE5_LIVE_MATRIX_PROFILE
      live_status, live_output = _run_capture(
          [sys.executable, "scripts/wallet_login_live_e2e.py"], env=live_env)
      evidence_prefix = "evidence="
      evidence_lines = [line[len(evidence_prefix):]
                        for line in live_output.splitlines() if line.startswith(evidence_prefix)]
      if live_status:
        receipt["issue5_acceptance_gates"].update(
            {name: "inconclusive" for name in issue5_live_matrix_gate_statuses({})})
        if len(evidence_lines) == 1:
          try:
            partial_evidence = json.loads(evidence_lines[0])
          except json.JSONDecodeError:
            partial_evidence = None
          if isinstance(partial_evidence, dict):
            receipt["issue5_live_evidence"] = partial_evidence
            receipt["issue5_acceptance_gates"].update(
                issue5_live_matrix_gate_statuses(partial_evidence))
        _record_step(receipt, receipt_path, "issue5-live-matrix", "fail",
                     detail=f"exit_{live_status}")
        return live_status
      if len(evidence_lines) != 1:
        receipt["issue5_acceptance_gates"].update(
            {name: "inconclusive" for name in issue5_live_matrix_gate_statuses({})})
        _record_step(receipt, receipt_path, "issue5-live-matrix", "fail",
                     detail="sanitized_evidence_missing_or_ambiguous")
        return 2
      try:
        live_evidence = json.loads(evidence_lines[0])
      except json.JSONDecodeError:
        live_evidence = None
      if not isinstance(live_evidence, dict):
        receipt["issue5_acceptance_gates"].update(
            {name: "inconclusive" for name in issue5_live_matrix_gate_statuses({})})
        _record_step(receipt, receipt_path, "issue5-live-matrix", "fail",
                     detail="sanitized_evidence_invalid")
        return 2
      receipt["issue5_live_evidence"] = live_evidence
      matrix_gate_statuses = issue5_live_matrix_gate_statuses(live_evidence)
      receipt["issue5_acceptance_gates"].update(matrix_gate_statuses)
      if any(status != "pass" for status in matrix_gate_statuses.values()):
        _record_step(receipt, receipt_path, "issue5-live-matrix", "fail",
                     detail="acceptance_gate_evidence_inconclusive_or_failed")
        return 2
      _record_step(receipt, receipt_path, "issue5-live-matrix", "pass",
                   detail="all_mapped_live_matrix_gates_passed")
      current_step = None

      current_step = "issue5-adversarial"
      adversarial_env = dict(os.environ)
      adversarial_env["WALLET_IT_IMAGE"] = built_image_id
      adversarial_env["WALLET_IT_PROFILE"] = "issue5-adversarial"
      adversarial_status, adversarial_output = _run_capture(
          [sys.executable, "scripts/wallet_login_live_e2e.py"], env=adversarial_env)
      evidence_prefix = "issue5-adversarial-evidence="
      evidence_lines = [line.split("=", 1)[1].strip()
                        for line in adversarial_output.splitlines()
                        if line.startswith(evidence_prefix)]
      if adversarial_status:
        receipt["issue5_acceptance_gates"].update(
            {name: "inconclusive" for name in ISSUE5_ADVERSARIAL_CASES})
        if len(evidence_lines) == 1:
          try:
            receipt["issue5_adversarial_evidence"] = json.loads(evidence_lines[0])
          except json.JSONDecodeError:
            pass
        _record_step(receipt, receipt_path, current_step, "fail",
                     detail=f"exit_{adversarial_status}")
        return adversarial_status
      if len(evidence_lines) != 1:
        receipt["issue5_acceptance_gates"].update(
            {name: "inconclusive" for name in ISSUE5_ADVERSARIAL_CASES})
        _record_step(receipt, receipt_path, current_step, "fail",
                     detail="sanitized_evidence_missing_or_ambiguous")
        return 2
      try:
        adversarial_evidence = json.loads(evidence_lines[0])
      except json.JSONDecodeError:
        adversarial_evidence = None
      if not isinstance(adversarial_evidence, dict):
        receipt["issue5_acceptance_gates"].update(
            {name: "inconclusive" for name in ISSUE5_ADVERSARIAL_CASES})
        _record_step(receipt, receipt_path, current_step, "fail",
                     detail="sanitized_evidence_invalid")
        return 2
      receipt["issue5_adversarial_evidence"] = adversarial_evidence
      adversarial_gate_statuses = issue5_adversarial_gate_statuses(adversarial_evidence)
      receipt["issue5_acceptance_gates"].update(adversarial_gate_statuses)
      receipt["issue5_acceptance_gates"]["account_denial_concurrency"] = (
          issue5_account_denial_gate_status(live_evidence))
      receipt["issue5_acceptance_gates"]["runtime_provider"] = (
          issue5_runtime_provider_gate_status(live_evidence))
      if any(status != "unavailable" for status in adversarial_gate_statuses.values()):
        _record_step(receipt, receipt_path, current_step, "fail",
                     detail="adversarial_gate_evidence_inconclusive")
        return 2
      if not issue5_acceptance_gate_set_complete(receipt["issue5_acceptance_gates"]):
        _record_step(receipt, receipt_path, current_step, "fail",
                     detail="required_acceptance_gate_set_incomplete")
        return 2
      _record_step(receipt, receipt_path, current_step, "pass",
                   detail="bounded_fixture_evidence_mapped_fail_closed")
      current_step = None
    return 0
  except KeyboardInterrupt:
    failure_code = 130
    receipt["interrupted"] = True
    if image_build_started and baseline_image_ids is not None:
      try:
        known_owned_image_ids = _owned_image_snapshot(engine, baseline_image_ids, run_id)
      except Exception:
        known_owned_image_ids = set()
    if current_step == "issue5-live-matrix":
      receipt["issue5_acceptance_gates"].update(
          {name: "inconclusive" for name in issue5_live_matrix_gate_statuses({})})
    if current_step == "issue5-adversarial":
      receipt["issue5_acceptance_gates"].update(
          {name: "inconclusive" for name in ISSUE5_ADVERSARIAL_CASES})
    if current_step and receipt["steps"][current_step]["status"] == "not_run":
      _record_step(receipt, receipt_path, current_step, "interrupted", detail="keyboard_interrupt")
    return failure_code
  except Exception as error:
    failure_code = 2
    receipt["failure_category"] = type(error).__name__
    if image_build_started and baseline_image_ids is not None:
      try:
        known_owned_image_ids = _owned_image_snapshot(engine, baseline_image_ids, run_id)
      except Exception:
        known_owned_image_ids = set()
    if current_step == "issue5-live-matrix":
      receipt["issue5_acceptance_gates"].update(
          {name: "inconclusive" for name in issue5_live_matrix_gate_statuses({})})
    if current_step == "issue5-adversarial":
      receipt["issue5_acceptance_gates"].update(
          {name: "inconclusive" for name in ISSUE5_ADVERSARIAL_CASES})
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
    image_retained = False
    cleanup_result: dict = {}
    if image_build_started:
      try:
        if baseline_image_ids is None:
          raise RuntimeError("image_baseline_unavailable")
        cleanup_result = _cleanup_owned_images(
            engine, baseline_image_ids, run_id,
            known_owned_ids=known_owned_image_ids,
            retain_image_id=built_image_id if retain_image and built_image_id else None)
        image_retained = cleanup_result["image_retained"]
        receipt["cleanup"].update(cleanup_result)
        if cleanup_result["status"] != "pass":
          cleanup_failures.append("image_cleanup_inconclusive")
      except Exception as error:
        cleanup_failures.append("image_cleanup_inconclusive")
        receipt["cleanup"].update({
            "status": "fail",
            "inconclusive_image_count": max(1, receipt["cleanup"].get("inconclusive_image_count", 0)),
            "detail": f"{type(error).__name__}",
        })
    receipt["image"]["retained"] = image_retained
    cleanup_code = 2 if cleanup_failures else 0
    receipt["cleanup"]["status"] = "pass" if cleanup_code == 0 else "fail"
    receipt["cleanup"]["image_retained"] = image_retained
    receipt["cleanup"]["retained_image_id"] = cleanup_result.get("retained_image_id")
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


def promotion_source_from_receipt(receipt: object) -> tuple[str, str, str]:
  """Require a complete successful Issue #5 live receipt and its retained immutable image."""
  if not isinstance(receipt, dict) or receipt.get("profile") != "issue5-live" or receipt.get("exit_code") != 0:
    raise ValueError("promotion requires a successful issue5-live receipt")
  gates = receipt.get("issue5_acceptance_gates")
  if not isinstance(gates, dict) or set(gates) != set(ISSUE5_GATES):
    raise ValueError("promotion receipt has incomplete acceptance gates")
  expected_gates = {
      name: ("unavailable" if name in ISSUE5_ADVERSARIAL_CASES else "pass")
      for name in ISSUE5_GATES
  }
  if gates != expected_gates:
    raise ValueError("promotion requires all Issue #5 acceptance gates to pass")
  cleanup = receipt.get("cleanup")
  if not isinstance(cleanup, dict) or cleanup.get("status") != "pass":
    raise ValueError("promotion receipt cleanup is not verified")
  image = receipt.get("image")
  if not isinstance(image, dict) or image.get("status") != "built":
    raise ValueError("promotion receipt has no built image")
  if image.get("retention_requested") is not True or image.get("retained") is not True:
    raise ValueError("promotion requires explicit retention of the accepted local image")
  engine = image.get("engine")
  if engine not in {"podman", "docker"}:
    raise ValueError("promotion receipt has an unsupported image engine")
  image_id = normalize_image_id(image.get("immutable_id", ""))
  tag = image.get("run_owned_tag")
  if (not isinstance(tag, str) or tag != f"decent-keycloak-wallet-provider:lifecycle-{receipt.get('run_id')}"):
    raise ValueError("promotion receipt run-owned tag does not match its lifecycle run ID")
  if image_id is None or not isinstance(tag, str) or not tag.startswith(
      "decent-keycloak-wallet-provider:lifecycle-"):
    raise ValueError("promotion receipt has invalid immutable image provenance")
  if (cleanup.get("image_retained") is not True
      or normalize_image_id(cleanup.get("retained_image_id", "")) != image_id):
    raise ValueError("promotion receipt cleanup retention does not match the accepted image")
  source = receipt.get("source")
  if not isinstance(source, dict):
    raise ValueError("promotion receipt lacks source provenance")
  source_hash = source.get("image_source_sha256")
  source_file_count = source.get("image_source_file_count")
  artifact_hash = source.get("image_artifacts_sha256")
  artifact_file_count = source.get("image_artifact_file_count")
  if (not isinstance(source_hash, str) or re.fullmatch(r"[0-9a-f]{64}", source_hash) is None
      or type(source_file_count) is not int or source_file_count < 1
      or not isinstance(artifact_hash, str)
      or re.fullmatch(r"[0-9a-f]{64}", artifact_hash) is None
      or type(artifact_file_count) is not int or artifact_file_count != len(IMAGE_BUILD_ARTIFACT_FILES)):
    raise ValueError("promotion receipt lacks complete image-input fingerprints")
  return engine, tag, image_id


def manifest_identity(raw_manifest: bytes, expected_image_id: str) -> tuple[str, str]:
  try:
    manifest = json.loads(raw_manifest)
  except (json.JSONDecodeError, UnicodeDecodeError) as error:
    raise ValueError("registry manifest is invalid") from error
  config = manifest.get("config") if isinstance(manifest, dict) else None
  config_digest = config.get("digest") if isinstance(config, dict) else None
  if not isinstance(config_digest, str) or config_digest != expected_image_id:
    raise ValueError("manifest image identity does not match accepted immutable ID")
  return "sha256:" + hashlib.sha256(raw_manifest).hexdigest(), config_digest


def validate_release_candidate_destination(destination: str) -> str:
  if not isinstance(destination, str) or not destination.startswith("docker://"):
    raise ValueError("destination must use the docker:// registry transport")
  reference = destination[len("docker://"):]
  pattern = (r"[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?/"
      r"[a-z0-9]+(?:[._/-][a-z0-9]+)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
  if re.fullmatch(pattern, reference) is None or "@" in reference:
    raise ValueError("destination must be a registry repository with an explicit tag and no credentials")
  tag = reference.rsplit(":", 1)[1]
  if "rc" not in tag.casefold() and "candidate" not in tag.casefold():
    raise ValueError("destination tag must identify a release candidate")
  return destination


def capture_binary_command(command: list[str]) -> subprocess.CompletedProcess[bytes]:
  print("+ " + shlex.join(command), flush=True)
  return subprocess.run(command, cwd=ROOT, capture_output=True, check=False)


def run_promotion(receipt_path: str, destination: str, *, allow_publish: bool) -> int:
  if not allow_publish:
    print("promotion requires explicit --allow-publish authorization", file=sys.stderr)
    return 2
  try:
    destination = validate_release_candidate_destination(destination)
    path = Path(receipt_path).expanduser()
    if not path.is_absolute():
      path = ROOT / path
    raw_receipt = path.read_bytes()
    receipt = json.loads(raw_receipt)
    engine, source_tag, image_id = promotion_source_from_receipt(receipt)
  except (OSError, json.JSONDecodeError, ValueError) as error:
    print(f"promotion preflight failed: {type(error).__name__}: {error}", file=sys.stderr)
    return 2
  if not check_tool("container engine", [engine, "--version"], "version"):
    return 2
  if not check_tool("Skopeo", ["skopeo", "--version"], "skopeo version"):
    return 2
  info_command = ([engine, "info", "--format", "{{json .}}"] if engine == "docker"
      else [engine, "info", "--format", "json"])
  info = subprocess.run(info_command, cwd=ROOT, text=True, capture_output=True, check=False)
  if info.returncode:
    print("promotion preflight failed: container engine daemon is unavailable", file=sys.stderr)
    return 2

  promotion_id = uuid.uuid4().hex
  temporary_tag = f"localhost/decent-issue5-promotion:{promotion_id}"
  promotion_path = ROOT / "target/lifecycle/promotions" / f"{promotion_id}.json"
  promotion = {
      "schema_version": 1,
      "promotion_id": promotion_id,
      "status": "failed",
      "source_receipt_sha256": hashlib.sha256(raw_receipt).hexdigest(),
      "source_image_id": image_id,
      "source_run_tag": source_tag,
      "destination": destination,
      "steps": {"local_tag": "not_run", "local_manifest": "not_run",
          "registry_copy": "not_run", "registry_readback": "not_run",
          "temporary_tag_cleanup": "not_run"},
  }
  failure_code = 1
  local_tag_created = False
  try:
    existing = capture_command(_image_inspect_command(engine, temporary_tag))
    if existing.returncode == 0:
      promotion["failure_category"] = "temporary_tag_collision"
      failure_code = 2
      return failure_code
    source_check = capture_command(_image_inspect_command(engine, source_tag))
    if source_check.returncode or normalize_image_id(source_check.stdout) != image_id:
      promotion["failure_category"] = "retained_source_image_mismatch"
      failure_code = 2
      return failure_code
    tag_command = _image_tag_command(engine, source_tag, temporary_tag)
    if run(tag_command):
      promotion["failure_category"] = "local_tag_failed"
      failure_code = 1
      return failure_code
    local_tag_created = True
    tagged = capture_command(_image_inspect_command(engine, temporary_tag))
    if tagged.returncode or normalize_image_id(tagged.stdout) != image_id:
      promotion["failure_category"] = "temporary_tag_identity_mismatch"
      failure_code = 2
      return failure_code
    promotion["steps"]["local_tag"] = "pass"
    transport = "containers-storage" if engine == "podman" else "docker-daemon"
    local_manifest_result = capture_binary_command([
        "skopeo", "inspect", "--raw", f"{transport}:{temporary_tag}"])
    if local_manifest_result.returncode:
      promotion["failure_category"] = "local_manifest_unavailable"
      failure_code = 1
      return failure_code
    try:
      source_manifest_digest, _ = manifest_identity(local_manifest_result.stdout, image_id)
    except ValueError:
      promotion["failure_category"] = "local_manifest_identity_mismatch"
      failure_code = 2
      return failure_code
    promotion["source_manifest_digest"] = source_manifest_digest
    promotion["steps"]["local_manifest"] = "pass"
    if run(["skopeo", "copy", "--preserve-digests",
        f"{transport}:{temporary_tag}", destination]):
      promotion["failure_category"] = "registry_copy_failed"
      failure_code = 1
      return failure_code
    promotion["steps"]["registry_copy"] = "pass"
    manifest_result = capture_binary_command(["skopeo", "inspect", "--raw", destination])
    if manifest_result.returncode:
      promotion["failure_category"] = "registry_readback_failed"
      failure_code = 1
      return failure_code
    try:
      manifest_digest, config_digest = manifest_identity(manifest_result.stdout, image_id)
    except ValueError:
      promotion["failure_category"] = "registry_image_identity_mismatch"
      failure_code = 2
      return failure_code
    if manifest_digest != promotion["source_manifest_digest"]:
      promotion["failure_category"] = "registry_manifest_digest_mismatch"
      failure_code = 2
      return failure_code
    promotion["registry_manifest_digest"] = manifest_digest
    promotion["remote_config_digest"] = config_digest
    promotion["steps"]["registry_readback"] = "pass"
    promotion["status"] = "pass"
    failure_code = 0
  finally:
    if local_tag_created:
      cleanup = _image_remove(engine, temporary_tag, image_id)
      promotion["steps"]["temporary_tag_cleanup"] = "pass" if cleanup == 0 else "fail"
      if cleanup:
        promotion["status"] = "fail"
        promotion["failure_category"] = "temporary_tag_cleanup_failed"
        failure_code = 2
    else:
      promotion["steps"]["temporary_tag_cleanup"] = "not_needed"
    if failure_code and "failure_category" not in promotion:
      promotion["failure_category"] = "promotion_failed"
    write_receipt(promotion_path, promotion)
    print(f"promotion receipt: {promotion_path}")
  return failure_code


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
  run_parser.add_argument("--retain-image", action="store_true",
                          help="explicitly retain this run's immutable local image after receipt finalization")
  promote_parser = subparsers.add_parser("promote", help="promote an accepted retained image to a release-candidate registry tag")
  promote_parser.add_argument("--receipt", required=True, help="successful issue5-live lifecycle receipt")
  promote_parser.add_argument("--destination", required=True, help="explicit docker:// registry/repository:rc-tag")
  promote_parser.add_argument("--allow-publish", action="store_true", required=True,
                              help="authorize publishing this exact accepted image digest")
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
  if args.action == "promote":
    return run_promotion(args.receipt, args.destination, allow_publish=args.allow_publish)
  if args.profile == "issue5-live" and not args.allow_live:
    parser.error("issue5-live requires explicit --allow-live authorization")
  execution_plan = plan(args.profile, retain_image=args.retain_image)
  if args.plan:
    print(json.dumps(execution_plan, sort_keys=True) if args.json else "\n".join(
      f"{step['name']}: {shlex.join(step['command']) if 'command' in step else step['action']}"
      for step in execution_plan["steps"]))
    return 0
  if args.json:
    parser.error("--json is only valid with --plan")
  return run_profile(args.profile, pull_base=args.pull_base_images,
      retain_image=args.retain_image)


if __name__ == "__main__":
  raise SystemExit(main())
