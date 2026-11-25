"""Offline contract tests through the executable, in isolated scratch repositories."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import keycloakctl_cli
from scripts import lifecycle


ROOT = Path(__file__).resolve().parents[1]


class KeycloakctlTest(unittest.TestCase):
  def setUp(self):
    scratch = tempfile.TemporaryDirectory(prefix="keycloakctl-test-")
    self.addCleanup(scratch.cleanup)
    self.cwd = Path(scratch.name)
    self.repo = self.cwd / "repo"
    self.repo.mkdir()
    (self.repo / "scripts").mkdir()
    self.bin = self.cwd / "bin"
    self.bin.mkdir()
    fake_maven = self.bin / "mvn"
    fake_maven.write_text(
        "#!/bin/sh\n"
        "if [ -f target/surefire-reports/TEST-fixture.xml ]; then\n"
        "  touch target/surefire-reports/TEST-fixture.xml\n"
        "fi\n"
        "exit 0\n", encoding="utf-8")
    fake_maven.chmod(0o755)
    shutil.copy2(ROOT / "keycloakctl", self.repo)
    (self.repo / "container/rp-fixture").mkdir(parents=True)
    shutil.copy2(ROOT / "container/Dockerfile", self.repo / "container/Dockerfile")
    shutil.copy2(ROOT / "container/rp-fixture/Dockerfile", self.repo / "container/rp-fixture/Dockerfile")
    shutil.copy2(ROOT / "scripts/oidc_rp_fixture.py", self.repo / "scripts/oidc_rp_fixture.py")
    for relative in ("scripts/lifecycle.py", "scripts/remote_test_host.py"):
      shutil.copy2(ROOT / relative, self.repo / relative)
    for module in ROOT.glob("scripts/keycloakctl*.py"):
      shutil.copy2(module, self.repo / "scripts")

    subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Acceptance Test"], check=True)
    subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "fixture"], check=True)
    if (ROOT / "config/keycloakctl").is_dir():
      shutil.copytree(ROOT / "config/keycloakctl", self.repo / "config/keycloakctl")
    python311 = shutil.which("python3.11")
    self.env = {
        "HOME": str(self.cwd),
        "PATH": os.pathsep.join(filter(None, [str(self.bin),
                                                   str(Path(python311).parent) if python311 else None,
                                                   str(Path(sys.executable).absolute().parent), os.defpath])),
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(self.cwd),
    }

  def refresh_surefire_reports(self, root):
    for report in (root / "target/surefire-reports").glob("TEST-*.xml"):
      os.utime(report, None)

  def test_acceptance_orchestration_does_not_delegate_to_lifecycle_run(self):
    marker = self.cwd / "lifecycle-run-invoked"
    lifecycle_script = self.repo / "scripts/lifecycle.py"
    lifecycle_script.write_text("\n".join((
        "from pathlib import Path",
        "def fingerprint_source(include_build_artifacts=False): return {}",
        "def local_source_provenance(root=None): return {'source_revision': '0' * 40, 'worktree_clean': True, 'worktree_diff_sha256': '0' * 64, 'worktree_untracked_file_count': 0}",
        "def run_python_tests(): return 0",
        "def verify_surefire(): return 0",
        "def verify_provider(): return 0",
        "if __name__ == '__main__':",
        f"  Path({str(marker)!r}).write_text(' '.join(__import__('sys').argv[1:]))",
        "  raise SystemExit(0)",
        "")), encoding="utf-8")
    self.install_fixture_test()
    self.write_java_acceptance_artifacts(self.repo)

    result = self.cli("acceptance", "--profile", "ci")

    self.assertEqual(0, result.returncode, result.stderr)
    self.assertFalse(marker.exists(), "keycloakctl acceptance must own stages instead of delegating lifecycle profile run")

  def test_local_receipt_records_commit_and_dirty_worktree_provenance(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      subprocess.run(["git", "init", "-q", str(root)], check=True)
      subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
      subprocess.run(["git", "-C", str(root), "config", "user.name", "Acceptance Test"], check=True)
      tracked = root / "input.txt"
      tracked.write_text("committed input")
      subprocess.run(["git", "-C", str(root), "add", "input.txt"], check=True)
      subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
      revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
      tracked.write_text("dirty input")
      (root / "untracked.txt").write_text("new input")
      with patch.object(lifecycle, "ROOT", root):
        provenance = lifecycle.local_source_provenance()
        (root / "target/lifecycle/evidence").mkdir(parents=True)
        (root / "target/lifecycle/evidence/generated.json").write_text("generated")
        after_generated_output = lifecycle.local_source_provenance()
        tracked.write_text("changed while still dirty")
        changed_provenance = lifecycle.local_source_provenance()
      self.assertEqual(provenance, after_generated_output)
      self.assertEqual(revision, provenance["source_revision"])
      self.assertFalse(provenance["worktree_clean"])
      self.assertEqual(1, provenance["worktree_untracked_file_count"])
      self.assertNotEqual(provenance["worktree_diff_sha256"],
                          changed_provenance["worktree_diff_sha256"])
      self.assertFalse(changed_provenance["worktree_clean"])

  def test_local_keycloakctl_steps_stay_aligned_with_canonical_lifecycle(self):
    canonical_steps = tuple(name for name, _ in lifecycle.core_test_stages())
    self.assertEqual(canonical_steps, keycloakctl_cli.TEST_STEPS[:len(canonical_steps)])

    for profile in ("offline", "ci"):
      planned = {step["name"] for step in lifecycle.plan(profile)["steps"]}
      self.assertTrue(set(canonical_steps) <= planned)
      self.assertIn("image-smoke", planned)
      self.assertIn("diff-check", planned)
    self.assertEqual("rp-fixture-smoke", keycloakctl_cli.TEST_STEPS[-2])
    self.assertNotIn("rp-fixture-smoke", {step["name"] for step in lifecycle.plan("ci")["steps"]})

  def test_acceptance_python_stage_selects_canonical_locked_suite(self):
    root = self.cwd / "acceptance-root"
    root.mkdir()
    self.write_java_acceptance_artifacts(root)
    calls = []

    def record_lifecycle_command(command, *, env=None):
      calls.append((command, env))
      return 0

    def successful_subprocess(command, **kwargs):
      calls.append((command, kwargs.get("env")))
      if command and command[0] == "mvn":
        self.refresh_surefire_reports(root)
      return subprocess.CompletedProcess(command, 0, "Ran 1 test in 0.001s\\n", "")

    with (patch.object(keycloakctl_cli, "ROOT", root),
          patch.object(keycloakctl_cli, "acceptance_source_provenance", return_value={}),
          patch.object(lifecycle, "run", side_effect=record_lifecycle_command),
          patch.object(lifecycle, "extract_verified_wheelhouse", return_value=0),
          patch.object(lifecycle, "verify_surefire", return_value=0),
          patch.object(lifecycle, "verify_provider", return_value=0),
          patch.object(keycloakctl_cli.subprocess, "run", side_effect=successful_subprocess)):
      result = keycloakctl_cli.run_acceptance("ci")

    self.assertEqual(0, result)
    commands = [command for command, _ in calls]
    self.assertIn([sys.executable, "-m", "unittest", *lifecycle.PYTHON_TESTS, "-q"], commands)
    self.assertIn([sys.executable, "container/build_resolver_runtime.py", "--materialize-sources",
                   "--sources-directory", unittest.mock.ANY], commands)
    self.assertTrue(any(command[:2] == [sys.executable, "container/verify_resolver_runtime_inputs.py"]
                        for command in commands), "acceptance must verify pinned source/dependency inputs")
    self.assertTrue(any("--require-hashes" in command
                        and "container/resolver-requirements.lock.txt" in command
                        and "--target" in command for command in commands),
                    "resolver wheels must be installed from the hash-locked requirements")
    self.assertTrue(any(command[:2] == [sys.executable, "container/patch_resolver_runtime.py"]
                        for command in commands), "the canonical resolver runtime patch must be applied")
    self.assertIn([sys.executable, "-m", "pip", "download", "--disable-pip-version-check",
                   "--no-cache-dir", "--require-hashes", "--only-binary=:all:", "--index-url",
                   "https://pypi.org/simple", "--dest", unittest.mock.ANY,
                   "-r", "requirements/issue8-oidc.lock"], commands)
    suite_env = next(env for command, env in calls
                     if command[:3] == [sys.executable, "-m", "unittest"])
    self.assertIn("PYTHONPATH", suite_env)
    self.assertIn("resolver-sources/identity/src", suite_env["PYTHONPATH"])
    self.assertIn("resolver-sources/registry/src", suite_env["PYTHONPATH"])

  def test_acceptance_runs_maven_then_requires_surefire_before_python_tests(self):
    root = self.cwd / "java-acceptance-root"
    reports = root / "target/surefire-reports"
    reports.mkdir(parents=True)
    (reports / "TEST-fixture.xml").write_text(
        '<testsuite tests="1" failures="0" errors="0" skipped="0"/>', encoding="utf-8")
    self.write_java_acceptance_artifacts(root)
    calls = []

    def successful_subprocess(command, **kwargs):
      calls.append(command)
      if command and command[0] == "mvn":
        self.refresh_surefire_reports(root)
      stdout = "Ran 1 test in 0.001s\\n" if command[:3] == [sys.executable, "-m", "unittest"] else ""
      return subprocess.CompletedProcess(command, 0, stdout, "")

    with (patch.object(keycloakctl_cli, "ROOT", root),
          patch.object(lifecycle, "ROOT", root),
          patch.object(keycloakctl_cli, "acceptance_source_provenance", return_value={}),
          patch.object(lifecycle, "run", return_value=0),
          patch.object(lifecycle, "extract_verified_wheelhouse", return_value=0),
          patch.object(lifecycle, "verify_surefire", return_value=2) as legacy_surefire,
          patch.object(lifecycle, "verify_provider", return_value=0),
          patch.object(keycloakctl_cli.subprocess, "run", side_effect=successful_subprocess)):
      result = keycloakctl_cli.run_acceptance("ci")

    self.assertEqual(0, result)
    legacy_surefire.assert_not_called()
    receipt_path = next((root / "target/keycloakctl/acceptance").glob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    stages = [stage["name"] for stage in receipt["stages"]]
    self.assertEqual(["java-tests", "surefire", "provider-service-registration",
                      "python-tests", "python-compile", "diff-check"], stages)
    self.assertEqual(["mvn", "--batch-mode", "--no-transfer-progress", "package"], calls[0])

  def test_acceptance_diff_check_rejects_committed_pr_whitespace(self):
    self.install_import_safe_fake_lifecycle()
    self.install_fixture_test()
    self.write_java_acceptance_artifacts(self.repo)
    base = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
    bad_source = self.repo / "scripts/committed_with_trailing_whitespace.py"
    bad_source.write_text("value = 'candidate' \n", encoding="utf-8")
    subprocess.run(["git", "-C", str(self.repo), "add", str(bad_source)], check=True)
    subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "candidate whitespace"], check=True)
    self.env["PR_BASE_SHA"] = base

    result = self.cli("acceptance", "--profile", "ci")

    self.assertEqual(2, result.returncode)
    receipt_path = Path(result.stderr.strip().split("receipt: ", 1)[1])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("failed", receipt["status"])
    self.assertEqual(("diff-check", "fail"),
                     (receipt["stages"][-1]["name"], receipt["stages"][-1]["status"]))

  def test_acceptance_diff_check_rejects_untracked_whitespace(self):
    self.install_import_safe_fake_lifecycle()
    self.install_fixture_test()
    self.write_java_acceptance_artifacts(self.repo)
    (self.repo / "untracked_with_trailing_whitespace.txt").write_text(
        "candidate has trailing whitespace \n", encoding="utf-8")

    result = self.cli("acceptance", "--profile", "ci")

    self.assertEqual(2, result.returncode)
    self.assertIn("untracked_with_trailing_whitespace.txt:1: trailing whitespace", result.stdout)
    receipt_path = Path(result.stderr.strip().split("receipt: ", 1)[1])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual(("diff-check", "fail"),
                     (receipt["stages"][-1]["name"], receipt["stages"][-1]["status"]))

  def test_acceptance_rejects_surefire_reports_untouched_by_maven(self):
    self.install_import_safe_fake_lifecycle()
    self.install_fixture_test()
    self.write_java_acceptance_artifacts(self.repo)
    fake_maven = self.bin / "mvn"
    fake_maven.write_text("#!/bin/sh" + chr(10) + "exit 0" + chr(10), encoding="utf-8")
    fake_maven.chmod(0o755)

    result = self.cli("acceptance", "--profile", "ci")

    self.assertEqual(2, result.returncode)
    receipt_path = Path(result.stderr.strip().split("receipt: ", 1)[1])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("failed", receipt["status"])
    self.assertEqual([("java-tests", "pass"), ("surefire", "fail")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])

  def test_acceptance_stops_after_maven_when_surefire_reports_are_missing(self):
    root = self.cwd / "missing-surefire-root"
    root.mkdir()
    calls = []

    def successful_subprocess(command, **kwargs):
      calls.append(command)
      return subprocess.CompletedProcess(command, 0, "", "")

    with (patch.object(keycloakctl_cli, "ROOT", root),
          patch.object(lifecycle, "ROOT", root),
          patch.object(keycloakctl_cli, "acceptance_source_provenance", return_value={}),
          patch.object(keycloakctl_cli.subprocess, "run", side_effect=successful_subprocess),
          patch.object(lifecycle, "run_python_tests") as python_tests):
      result = keycloakctl_cli.run_acceptance("ci")

    self.assertEqual(2, result)
    self.assertEqual([["mvn", "--batch-mode", "--no-transfer-progress", "package"]], calls)
    python_tests.assert_not_called()
    receipt_path = next((root / "target/keycloakctl/acceptance").glob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("failed", receipt["status"])
    self.assertEqual([("java-tests", "pass"), ("surefire", "fail")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])

  def test_acceptance_verifies_provider_registration_after_surefire(self):
    root = self.cwd / "provider-acceptance-root"
    reports = root / "target/surefire-reports"
    reports.mkdir(parents=True)
    (reports / "TEST-fixture.xml").write_text(
        '<testsuite tests="1" failures="0" errors="0" skipped="0"/>', encoding="utf-8")
    provider_jar = root / "target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar"
    provider_jar.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(provider_jar, "w") as archive:
      archive.writestr(
          "META-INF/services/org.keycloak.authentication.AuthenticatorFactory",
          "org.decentwallet.keycloak.wallet.WalletChallengeAuthenticatorFactory\n")

    def successful_subprocess(command, **kwargs):
      if command and command[0] == "mvn":
        self.refresh_surefire_reports(root)
      stdout = "Ran 1 test in 0.001s\\n" if command[:3] == [sys.executable, "-m", "unittest"] else ""
      return subprocess.CompletedProcess(command, 0, stdout, "")

    with (patch.object(keycloakctl_cli, "ROOT", root),
          patch.object(lifecycle, "ROOT", root),
          patch.object(keycloakctl_cli, "acceptance_source_provenance", return_value={}),
          patch.object(lifecycle, "run", return_value=0),
          patch.object(lifecycle, "extract_verified_wheelhouse", return_value=0),
          patch.object(lifecycle, "verify_provider", return_value=2) as legacy_provider,
          patch.object(keycloakctl_cli.subprocess, "run", side_effect=successful_subprocess)):
      result = keycloakctl_cli.run_acceptance("ci")

    self.assertEqual(0, result)
    legacy_provider.assert_not_called()
    receipt_path = next((root / "target/keycloakctl/acceptance").glob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual(["java-tests", "surefire", "provider-service-registration",
                      "python-tests", "python-compile", "diff-check"],
                     [stage["name"] for stage in receipt["stages"]])
    self.assertTrue(all(stage["status"] == "pass" for stage in receipt["stages"]))

  def test_acceptance_python_stage_failure_is_read_back_as_failed_receipt(self):
    root = self.cwd / "acceptance-failure-root"
    root.mkdir()
    self.write_java_acceptance_artifacts(root)

    def successful_maven(command, **kwargs):
      self.refresh_surefire_reports(root)
      return subprocess.CompletedProcess(command, 0)

    with (patch.object(keycloakctl_cli, "ROOT", root),
          patch.object(keycloakctl_cli, "acceptance_source_provenance", return_value={}),
          patch.object(lifecycle, "verify_surefire", return_value=0),
          patch.object(lifecycle, "verify_provider", return_value=0),
          patch.object(keycloakctl_cli.subprocess, "run", side_effect=successful_maven),
          patch.object(lifecycle, "run_python_tests", return_value=2)):
      result = keycloakctl_cli.run_acceptance("ci")

    self.assertEqual(2, result)
    receipt_path = next((root / "target/keycloakctl/acceptance").glob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("failed", receipt["status"])
    self.assertEqual([("java-tests", "pass"), ("surefire", "pass"),
                      ("provider-service-registration", "pass"), ("python-tests", "fail")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])

  def test_python_stage_rejects_successful_zero_test_summary(self):
    successful_setup = patch.object(lifecycle, "run", return_value=0)
    wheelhouse = patch.object(lifecycle, "extract_verified_wheelhouse", return_value=0)
    zero_tests = patch.object(lifecycle.subprocess, "run", return_value=subprocess.CompletedProcess(
        [], 0, "", "Ran 0 tests in 0.000s\\n"))
    with successful_setup, wheelhouse, zero_tests:
      self.assertEqual(2, lifecycle.run_python_tests())

  def test_python_stage_failure_cleans_its_temporary_package_tree(self):
    created = []
    original_temporary_directory = tempfile.TemporaryDirectory

    def track_temporary_directory(*args, **kwargs):
      temporary = original_temporary_directory(*args, **kwargs)
      created.append(Path(temporary.name))
      return temporary

    with (patch.object(lifecycle, "run", return_value=1),
          patch.object(lifecycle.tempfile, "TemporaryDirectory", side_effect=track_temporary_directory)):
      result = lifecycle.run_python_tests()

    self.assertEqual(1, result)
    self.assertEqual(1, len(created))
    self.assertFalse(created[0].exists(), "failed canonical stage must remove its isolated temp tree")

  def test_acceptance_refuses_a_zero_test_python_suite(self):
    self.install_import_safe_fake_lifecycle(test_count=0)
    self.install_fixture_test()
    self.write_java_acceptance_artifacts(self.repo)
    result = self.cli("acceptance", "--profile", "ci")

    self.assertEqual(2, result.returncode)
    self.assertIn("acceptance stage failed; receipt: ", result.stderr)
    receipt_path = Path(result.stderr.strip().split("receipt: ", 1)[1])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("failed", receipt["status"])
    self.assertEqual([("java-tests", "pass"), ("surefire", "pass"),
                      ("provider-service-registration", "pass"), ("python-tests", "fail")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])

  def test_acceptance_runs_only_local_profiles_and_verifies_owned_receipt(self):
    self.install_import_safe_fake_lifecycle()
    self.install_fixture_test()
    self.write_java_acceptance_artifacts(self.repo)
    for profile in ("offline", "ci"):
      result = self.cli("acceptance", "--profile", profile)
      self.assertEqual(0, result.returncode, result.stderr)
      receipt_path = Path(result.stdout.strip().splitlines()[-1].removeprefix("acceptance verified: "))
      self.assertEqual(self.repo / "target/keycloakctl/acceptance" / receipt_path.name, receipt_path)
      receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
      self.assertEqual(profile, receipt["profile"])
      self.assertEqual("complete", receipt["status"])
      self.assertEqual(["java-tests", "surefire", "provider-service-registration",
                        "python-tests", "python-compile", "diff-check"],
                       [stage["name"] for stage in receipt["stages"]])
      self.assertTrue(all(stage["status"] == "pass" for stage in receipt["stages"]))

  def test_acceptance_failure_writes_durable_failed_stage_receipt(self):
    self.install_import_safe_fake_lifecycle()
    self.install_fixture_test()
    self.write_java_acceptance_artifacts(self.repo)
    (self.repo / "scripts/broken_acceptance_fixture.py").write_text("def broken(:\n")
    result = self.cli("acceptance", "--profile", "ci")
    self.assertEqual(2, result.returncode)
    self.assertEqual("Surefire totals: tests=1, failures=0, errors=0, skipped=0\nprovider service registration verified\n", result.stdout)
    receipt_path = Path(result.stderr.strip().split("receipt: ", 1)[1])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("failed", receipt["status"])
    self.assertEqual([("java-tests", "pass"), ("surefire", "pass"),
                      ("provider-service-registration", "pass"),
                      ("python-tests", "pass"), ("python-compile", "fail")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])

  def test_acceptance_refuses_live_profiles(self):
    for profile in ("wallet-login-qualification", "remote-test-host"):
      result = self.cli("acceptance", "--profile", profile)
      self.assertEqual(2, result.returncode)
      self.assertEqual("", result.stdout)
      self.assertIn("invalid arguments", result.stderr)

  def test_local_setup_docs_pin_required_python_patch_version(self):
    docs = (ROOT / "docs/acceptance/keycloakctl-foundation.md").read_text(encoding="utf-8")
    self.assertIn("Run `./keycloakctl --help` with Python 3.11.13.", docs)
  def write_java_acceptance_artifacts(self, root):
    reports = root / "target/surefire-reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "TEST-fixture.xml").write_text(
        '<testsuite tests="1" failures="0" errors="0" skipped="0"/>', encoding="utf-8")
    provider_jar = root / "target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar"
    provider_jar.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(provider_jar, "w") as archive:
      archive.writestr(
          "META-INF/services/org.keycloak.authentication.AuthenticatorFactory",
          "org.decentwallet.keycloak.wallet.WalletChallengeAuthenticatorFactory\n")

  def install_fixture_test(self):
    (self.repo / "scripts/test_fixture.py").write_text("\n".join((
        "import unittest",
        "class Fixture(unittest.TestCase):",
        "  def test_fixture(self): self.assertTrue(True)",
        "")), encoding="utf-8")

  def install_import_safe_fake_lifecycle(self, *, test_count=1):
    python_test_status = 2 if test_count == 0 else 0
    (self.repo / "scripts/lifecycle.py").write_text("\n".join((
        "def fingerprint_source(include_build_artifacts=False): return {}",
        "def local_source_provenance(root=None): return {'source_revision': '0' * 40, 'worktree_clean': True, 'worktree_diff_sha256': '0' * 64, 'worktree_untracked_file_count': 0}",
        f"def run_python_tests(): return {python_test_status}",
        "def verify_surefire(): return 0",
        "def verify_provider(): return 0",
        "if __name__ == '__main__': raise SystemExit(0)",
        "")), encoding="utf-8")

  def cli(self, *args):
    return subprocess.run([str(self.repo / "keycloakctl"), *args], cwd=self.cwd,
                          env=self.env, capture_output=True, text=True, timeout=10)

  def config_file(self, data):
    path = self.cwd / "config.json"
    path.write_text(json.dumps(data) if isinstance(data, dict) else data, encoding="utf-8")
    return path.name  # Caller-relative paths, distinct from the executable's repository.

  def test_config_validation_accepts_only_supported_closed_profile_shapes(self):
    basic = {"version": 1, "profile": "dev", "engine": "podman"}
    result = self.cli("validate-config", "--config", self.config_file(basic))
    self.assertEqual(0, result.returncode, result.stderr)
    self.assertEqual("configuration valid\n", result.stdout)
    for profile in ("dev", "ci", "readiness", "qualification"):
      with self.subTest(profile=profile):
        result = self.cli("validate-config", "--profile", profile, "--config",
                          str(self.repo / f"config/keycloakctl/{profile}.json"))
        self.assertEqual(0, result.returncode, result.stderr)

    marker = "test-secret-marker-68f4b979e3"
    malformed = (
        {**basic, "password": marker},
        {**basic, marker: "value"},
        {**basic, "profile": marker},
        {**basic, "version": True},
        {**basic, "version": 1.0},
        {**basic, "engine": "docker\n"},
        {**basic, "remote": {}},
        {**basic, "profile": "readiness", "remote": {"token": marker}},
        {**basic, "profile": "readiness", "remote": {"target_ip": "100.128.0.1"}},
        {**basic, "profile": "qualification", "remote": {"route_attested": "yes"}},
        {**basic, "profile": "qualification", "remote": {"target_host": "user@ben-x260"}},
        {**basic, "profile": "readiness", "remote": {"target_host": "ben-x260;id"}},
        {**basic, "profile": "readiness", "remote": {"target_user": "ben;id"}},
        {**basic, "profile": "qualification", "remote": {"public_origin": f"https://rp.invalid/?token={marker}"}},
        f'{{"version":1,"profile":"{marker}","profile":"dev","engine":"podman"}}',
        '{"version":1,"profile":"readiness","engine":"podman","remote":{"target_ip":"100.64.1.1","target_ip":"100.64.1.2"}}',
        '{"version":1,"profile":"dev","engine":NaN}',
        " " * 8193 + json.dumps(basic),
    )
    for case, data in enumerate(malformed):
      with self.subTest(case=case):
        result = self.cli("validate-config", "--config", self.config_file(data))
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("error: invalid configuration\n", result.stderr)
        self.assertNotIn(marker, result.stderr)
    self.assertFalse((self.repo / "target").exists())
    self.assertFalse((self.repo / ".keycloakctl").exists())

  def test_validator_tracks_schema_profile_and_required_rules(self):
    schema_path = self.repo / "config/keycloakctl/config.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema["properties"]["profile"]["enum"].append("review")
    schema["required"] = ["version", "profile"]
    schema_path.write_text(json.dumps(schema), encoding="utf-8")
    result = self.cli("validate-config", "--profile", "review",
                      "--config", self.config_file({"version": 1, "profile": "review"}))
    self.assertEqual((0, "configuration valid\n", ""),
                     (result.returncode, result.stdout, result.stderr))

  def test_public_https_origin_accepts_valid_explicit_port_only(self):
    base = self.live_config()
    for origin in ("https://fictional-keycloak.example.org:443",
                   "https://fictional-keycloak.example.org:8443",
                   "https://a.example.org:65535"):
      with self.subTest(origin=origin):
        result = self.cli("validate-config", "--config", self.config_file(
            {**base, "remote": {**base["remote"], "public_origin": origin}}))
        self.assertEqual(0, result.returncode, result.stderr)
    for origin in ("https://fictional-keycloak.example.org:0",
                   "https://fictional-keycloak.example.org:65536",
                   "https://fictional-keycloak.example.org:user@other.example",
                   "https://fictional-keycloak.example.org:8443/keycloak",
                   "https://fictional-keycloak.example.org:8443?x=1",
                   "https://fictional-keycloak.example.org:8443#fragment"):
      with self.subTest(origin=origin):
        result = self.cli("validate-config", "--config", self.config_file(
            {**base, "remote": {**base["remote"], "public_origin": origin}}))
        self.assertEqual(2, result.returncode)

  def test_config_rejects_a_fifo_without_waiting_for_a_writer(self):
    path = self.cwd / "config.pipe"
    os.mkfifo(path)
    self.rejection(2, "invalid configuration", "setup", "--config", path.name)
    self.assertFalse((self.repo / "target").exists())
    self.assertFalse((self.repo / ".keycloakctl").exists())

  def run_directory(self, run_id):
    return self.repo / "target/keycloakctl/runs" / run_id

  def prepare_build_inputs(self):
    shutil.copy2(ROOT / "pom.xml", self.repo / "pom.xml")
    shutil.copytree(ROOT / "src", self.repo / "src")
    for relative in ("decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar",
                     "providers/java-json-canonicalization-1.1.jar", "providers/core-3.4.0.jar"):
      path = self.repo / "target" / relative
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_bytes(f"test artifact: {relative}".encode("ascii"))
    for relative in (
        "container/build_resolver_runtime.py", "container/verify_resolver_runtime_inputs.py",
        "container/resolver-runtime.lock.json", "container/resolver-binary-dependencies.lock.json",
        "container/resolver-requirements.lock.txt", "container/resolver-build-requirements.lock.txt",
        "container/registry-lock-constraints.txt", "container/resolver-requirements.in",
        "container/rotation_registry_roundtrip.py", "container/patch_resolver_runtime.py",
        "container/pinned_lookup_outcomes.py", "scripts/test_pinned_dht_peer_outcomes.py",
        "scripts/test_pinned_registry_lookup_outcomes.py",
        "scripts/test_pinned_adversarial_identity_peer.py", "scripts/test_rotation_registry_roundtrip.py",
        "scripts/rotation_registry_roundtrip.py", "scripts/issue5_adversarial_cases.py"):
      source = ROOT / relative
      destination = self.repo / relative
      destination.parent.mkdir(parents=True, exist_ok=True)
      shutil.copy2(source, destination)
    shutil.copytree(ROOT / "requirements", self.repo / "requirements")
    (self.repo / "container").mkdir(exist_ok=True)
    self.env["MATERIALIZER_LOG"] = str(self.cwd / "materializer.jsonl")
    (self.repo / "container/build_resolver_runtime.py").write_text('''import os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["MATERIALIZER_LOG"], "a") as log:
  log.write(" ".join(args) + "\\n")
if "--materialize-sources" in args:
  if os.environ.get("MATERIALIZER_FAIL") == "sources": raise SystemExit(23)
  destination = Path(args[args.index("--sources-directory") + 1])
  for name in ("identity", "registry"):
    source = destination / name
    (source / "src").mkdir(parents=True, exist_ok=True)
    (source / ".pinned-commit").write_text("0" * 40 + "\\n")
elif "--materialize-binary-dependencies" in args:
  if os.environ.get("MATERIALIZER_FAIL") == "binary": raise SystemExit(24)
  destination = Path(args[args.index("--binary-dependencies-directory") + 1])
  destination.mkdir(parents=True, exist_ok=True)
  (destination / "locked-test-marker").write_text("test-only")
else:
  raise SystemExit(25)
''', encoding="utf-8")
    (self.repo / "container/verify_resolver_runtime_inputs.py").write_text('''import os, sys
with open(os.environ["MATERIALIZER_LOG"], "a") as log:
  log.write("verify " + " ".join(sys.argv[1:]) + "\\n")
''', encoding="utf-8")
    git = self.cwd / "git"
    git.write_text('''#!/usr/bin/env python3.11
import sys
if sys.argv[1:] == ["rev-parse", "--verify", "HEAD"]:
  print("0123456789abcdef0123456789abcdef01234567")
else:
  raise SystemExit(97)
''', encoding="utf-8")
    git.chmod(0o700)
    mvn = self.cwd / "mvn"
    mvn.write_text('''#!/usr/bin/env python3.11
import os, sys
if os.environ.get("MAVEN_SKIP_RC") != "1": raise SystemExit(92)
if sys.argv[1:] != ["--batch-mode", "--no-transfer-progress", "package"]:
  raise SystemExit(93)
raise SystemExit(int(os.environ.get("MAVEN_BUILD_EXIT", "0")))
''', encoding="utf-8")
    mvn.chmod(0o700)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]

  def use_unavailable_engine(self):
    engine = self.cwd / "podman"
    engine.write_text("#!/bin/sh\nexit 97\n", encoding="ascii")
    engine.chmod(0o700)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]

  def setup_run(self, *args):
    result = self.cli("setup", *args)
    self.assertEqual(0, result.returncode, result.stderr)
    self.assertEqual("", result.stderr)
    self.assertRegex(result.stdout, r"\A[0-9a-f]{32}\n\Z")
    return result.stdout.strip()

  def test_setup_creates_a_minimal_run_and_only_reopens_the_named_run(self):
    first = self.setup_run()
    second = self.setup_run("--profile", "ci")
    self.assertNotEqual(first, second)
    manifest = self.run_directory(first) / "manifest.json"
    original = manifest.read_bytes()
    state = json.loads(original)
    self.assertEqual({"version", "run_id", "profile", "completed", "config_sha256"}, set(state))
    self.assertEqual((1, first, "dev", ["setup"]),
                     (state["version"], state["run_id"], state["profile"], state["completed"]))
    self.assertRegex(state["config_sha256"], r"\A[0-9a-f]{64}\Z")
    self.assertEqual(first, self.setup_run("--run-id", first))
    self.assertEqual(second, self.setup_run("--run-id", second))
    self.assertEqual(original, manifest.read_bytes())
    self.assertEqual({first, second}, {path.name for path in manifest.parent.parent.iterdir()})

    unknown = self.cli("setup", "--run-id", "f" * 32)
    self.assertEqual((2, "", "error: unknown run ID\n"),
                     (unknown.returncode, unknown.stdout, unknown.stderr))
    self.assertFalse(self.run_directory("f" * 32).exists())
    for invalid in ("../escape", str(self.cwd / "outside"), "A" * 32, "a" * 33, "a" * 32 + "\n"):
      with self.subTest(invalid=invalid):
        result = self.cli("setup", "--run-id", invalid)
        self.assertEqual((2, "", "error: invalid run ID\n"),
                         (result.returncode, result.stdout, result.stderr))
    self.assertEqual({first, second}, {path.name for path in manifest.parent.parent.iterdir()})
    self.assertFalse((self.cwd / "outside").exists())

  def test_target_cleanup_removes_run_state_but_keeps_reservation(self):
    config_path = self.config_file(self.live_config(profile="readiness"))
    run_id = self.setup_run("--config", config_path)
    manifest = self.run_directory(run_id) / "manifest.json"
    reservation = self.repo / ".keycloakctl/run-ids" / run_id
    reservation_before = reservation.read_bytes()

    shutil.rmtree(self.repo / "target")

    self.rejection(2, "run readback conflict", "setup", "--run-id", run_id)
    self.assertFalse(manifest.exists())
    self.assertEqual(reservation_before, reservation.read_bytes())
    new_run_id = self.setup_run()
    self.assertNotEqual(run_id, new_run_id)
    self.assertTrue(self.run_directory(new_run_id).is_dir())

  def test_phase_guards_allow_only_next_phase_without_advancing_it(self):
    result = self.cli("--help")
    self.assertEqual(0, result.returncode, result.stderr)
    for text in ("build", "test", "publish", "setup", "preflight", "deploy", "configure", "integration-test",
                 "verify readiness", "verify qualification", "teardown", "promote", "full",
                 "dev", "ci", "--profile", "--allow-live", "--allow-publish", "--new-run", "--run-id",
                 "stage receipts"):
      with self.subTest(help=text):
        self.assertIn(text, result.stdout)
    self.assertIn("Maven `package` without `clean`", result.stdout)
    self.assertIn("validates Surefire reports", result.stdout)
    self.assertIn("image build/smoke", result.stdout)

    self.prepare_build_inputs()
    self.use_unavailable_engine()
    run_id = self.setup_run("--profile", "dev")
    dev = ("--run-id", run_id)
    original = (self.run_directory(run_id) / "manifest.json").read_bytes()
    self.rejection(2, "invalid phase order; next phase is build", "test", *dev)
    self.rejection(2, "phase is not supported by run profile", "publish", *dev, "--allow-live")
    self.rejection(3, "provider build or image readback failed", "build", *dev)
    self.rejection(3, "provider build or image readback failed", "build", *dev)
    self.assertEqual(original, (self.run_directory(run_id) / "manifest.json").read_bytes())

  def test_build_uses_local_engine_then_verifies_immutable_ids_and_resumes(self):
    # Fake only the process boundary. The executable must issue two local builds
    # and inspect each resulting immutable image ID before recording success.
    self.prepare_build_inputs()
    maven_log = self.cwd / "maven-build.log"
    mvn = self.cwd / "mvn"
    mvn.write_text('''#!/usr/bin/env python3.11
import os, sys
from pathlib import Path
if os.environ.get("MAVEN_SKIP_RC") != "1": raise SystemExit(92)
Path(os.environ["MAVEN_BUILD_LOG"]).write_text("\\n".join(sys.argv[1:]) + "\\n")
raise SystemExit(int(os.environ.get("MAVEN_BUILD_EXIT", "0")))
''', encoding="utf-8")
    mvn.chmod(0o700)
    self.env["MAVEN_BUILD_LOG"] = str(maven_log)
    engine_log = self.cwd / "engine.jsonl"
    engine = self.cwd / "docker"
    engine.write_text('''#!/usr/bin/env python3.11
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["ENGINE_LOG"], "a") as out: out.write(json.dumps(args) + "\\n")
if args[:2] == ["build", "--no-cache"]:
  print("build complete")
elif args[:3] == ["image", "inspect", "--format"]:
  image = args[-1]
  print(image if image.startswith("sha256:") else ("1" if "provider" in image else "2") * 64)
else:
  raise SystemExit(91)
''', encoding="utf-8")
    engine.chmod(0o700)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]
    self.env["ENGINE_LOG"] = str(engine_log)
    materializer_log = self.cwd / "materializer.jsonl"
    self.env["MATERIALIZER_LOG"] = str(materializer_log)
    config = self.config_file({"version": 1, "profile": "ci", "engine": "docker"})
    run_id = self.setup_run("--profile", "ci", "--config", config)
    first = self.cli("build", "--config", config, "--run-id", run_id)
    self.assertEqual((0, "build verified\n", ""),
                     (first.returncode, first.stdout, first.stderr))
    self.assertEqual(["--batch-mode", "--no-transfer-progress", "package"],
                     maven_log.read_text().splitlines())
    commands = [json.loads(line) for line in engine_log.read_text().splitlines()]
    self.assertEqual(4, len(commands))
    provider_build = commands[0]
    self.assertEqual(["build", "--no-cache", "--network=none", "--label",
                      f"io.decent-keycloak.run-id={run_id}", "--tag",
                      f"localhost/decent-keycloak/provider:{run_id}", "--file", "container/Dockerfile"],
                     provider_build[:provider_build.index("--build-arg")])
    build_args = [provider_build[index + 1] for index, value in enumerate(provider_build[:-1])
                  if value == "--build-arg"]
    self.assertEqual(["LIFECYCLE_RUN_ID=" + run_id,
                      "SOURCE_REVISION=0123456789abcdef0123456789abcdef01234567"],
                     [value for value in build_args if value.startswith(("LIFECYCLE_RUN_ID=", "SOURCE_REVISION="))])
    for name in ("IMAGE_SOURCE_SHA256", "IMAGE_ARTIFACTS_SHA256"):
      values = [value.split("=", 1)[1] for value in build_args if value.startswith(name + "=")]
      self.assertEqual(1, len(values))
      self.assertRegex(values[0], r"\A[0-9a-f]{64}\Z")
    named_contexts = [provider_build[index + 1] for index, value in enumerate(provider_build[:-1])
                      if value == "--build-context"]
    self.assertEqual(["identity-src", "registry-src", "binary-dependencies"],
                     [value.split("=", 1)[0] for value in named_contexts])
    self.assertTrue(all(Path(value.split("=", 1)[1]).is_absolute() for value in named_contexts))
    self.assertEqual(".", provider_build[-1])
    rp_build = commands[2]
    self.assertEqual(["build", "--no-cache", "--network=none", "--label",
                      f"io.decent-keycloak.run-id={run_id}", "--tag",
                      f"localhost/decent-keycloak/rp-fixture:{run_id}", "--file",
                      "container/rp-fixture/Dockerfile"], rp_build[:rp_build.index("--build-context")])
    rp_contexts = [rp_build[index + 1] for index, value in enumerate(rp_build[:-1])
                   if value == "--build-context"]
    self.assertEqual(["binary-dependencies"], [value.split("=", 1)[0] for value in rp_contexts])
    self.assertTrue(all(Path(value.split("=", 1)[1]).is_absolute() for value in rp_contexts))
    self.assertEqual(".", rp_build[-1])
    rp_dockerfile = (self.repo / "container/rp-fixture/Dockerfile").read_text()
    self.assertIn("COPY --from=binary-dependencies /resolver-wheelhouse.tar.gz", rp_dockerfile)
    self.assertIn("python3.11 -m pip install --disable-pip-version-check --no-compile --no-index", rp_dockerfile)
    self.assertIn("--find-links=/tmp/rp-fixture-wheelhouse --require-hashes -r /tmp/rp-fixture.lock", rp_dockerfile)
    self.assertNotRegex(rp_dockerfile, r"(?m)^CMD(?:\s|$)")
    self.assertIn("cryptography==50.0.1", (self.repo / "requirements/rp-fixture.lock").read_text())
    materialized_commands = [line.split() for line in materializer_log.read_text().splitlines()]
    self.assertEqual(3, len(materialized_commands))
    self.assertIn("--materialize-sources", materialized_commands[0])
    self.assertIn("--materialize-binary-dependencies", materialized_commands[1])
    self.assertEqual("verify", materialized_commands[2][0])
    self.assertTrue(all(not Path(value.split("=", 1)[1]).exists() for value in named_contexts))
    self.assertEqual(["image", "inspect", "--format", "{{.Id}}",
                      f"localhost/decent-keycloak/provider:{run_id}"], commands[1])
    self.assertEqual(["image", "inspect", "--format", "{{.Id}}",
                      f"localhost/decent-keycloak/rp-fixture:{run_id}"], commands[3])
    self.assertTrue(all("--network=none" in command for command in commands if command[0] == "build"))
    self.assertFalse(any(token in {"push", "publish", "deploy", "run"}
                         for command in commands for token in command))
    receipt = self.run_directory(run_id) / "build.json"
    state = json.loads(receipt.read_text())
    self.assertEqual("complete", state["status"])
    self.assertEqual("sha256:" + "1" * 64, state["images"]["provider"]["image_id"])
    self.assertEqual("sha256:" + "2" * 64, state["images"]["rp-fixture"]["image_id"])
    for image in state["images"].values():
      self.assertRegex(image["source_sha256"], r"\A[0-9a-f]{64}\Z")
      self.assertRegex(image["config_sha256"], r"\A[0-9a-f]{64}\Z")
    before = receipt.read_bytes()
    materializer_count = len(materializer_log.read_text().splitlines())
    self.env["MATERIALIZER_FAIL"] = "sources"
    again = self.cli("build", "--config", config, "--run-id", run_id)
    self.assertEqual((0, "build verified\n", ""),
                     (again.returncode, again.stdout, again.stderr))
    self.assertEqual(before, receipt.read_bytes())
    self.assertEqual(materializer_count, len(materializer_log.read_text().splitlines()))
    self.assertEqual(6, len(engine_log.read_text().splitlines()))

  def test_build_stops_before_materializing_or_building_when_provider_package_fails(self):
    self.prepare_build_inputs()
    self.use_unavailable_engine()
    self.env["MAVEN_BUILD_EXIT"] = "1"
    run_id = self.setup_run()

    result = self.cli("build", "--run-id", run_id)

    self.assertEqual((3, "", ["error: offline provider package failed"]),
                     (result.returncode, result.stdout, result.stderr.splitlines()))
    run_dir = self.run_directory(run_id)
    failures = [json.loads(path.read_text()) for path in run_dir.glob("failure-*.json")]
    self.assertEqual([{"version": 1, "run_id": run_id, "phase": "provider-package", "status": "failed"}],
                     failures)
    self.assertEqual([], list(run_dir.glob("provider.json")))
    self.assertFalse((self.cwd / "materializer.jsonl").exists())
    self.assertFalse((self.cwd / "engine.jsonl").exists())

  def test_test_phase_follows_verified_build_and_runs_offline_checks_once(self):
    self.prepare_build_inputs()
    engine_log = self.cwd / "engine.jsonl"
    engine = self.cwd / "podman"
    engine.write_text('''#!/usr/bin/env python3.11
import json, os, sys
args = sys.argv[1:]
with open(os.environ["ENGINE_LOG"], "a") as out: out.write(json.dumps(args) + "\\n")
if args[0] == "build": print("build complete")
elif args[:3] == ["image", "inspect", "--format"]:
  image = args[-1]
  print(image if image.startswith("sha256:") else ("1" if "provider" in image else "2") * 64)
elif args[:3] == ["run", "--rm", "--network=none"]:
  image = args[args.index("--entrypoint") + 2]
  if image.startswith("sha256:" + "1" * 64):
    with open(os.environ["STEP_LOG"], "a") as out: out.write("image-smoke\\n")
    print("Keycloak 26.8.0\\nJVM: 21")
  else:
    with open(os.environ["STEP_LOG"], "a") as out: out.write("rp-fixture-smoke\\n")
    print("RP fixture import ok")
    raise SystemExit(int(os.environ.get("RP_SMOKE_EXIT", "0")))
else: raise SystemExit(91)
''', encoding="utf-8")
    engine.chmod(0o700)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]
    self.env["ENGINE_LOG"] = str(engine_log)
    run_id = self.setup_run()
    self.rejection(2, "invalid phase order; next phase is build", "test", "--run-id", run_id)
    built = self.cli("build", "--run-id", run_id)
    self.assertEqual((0, "build verified\n", ""), (built.returncode, built.stdout, built.stderr))

    failed_java_run = self.setup_run()
    java_rebuild = self.cli("build", "--run-id", failed_java_run)
    self.assertEqual(0, java_rebuild.returncode, java_rebuild.stderr)
    failed_surefire_run = self.setup_run()
    surefire_rebuild = self.cli("build", "--run-id", failed_surefire_run)
    self.assertEqual(0, surefire_rebuild.returncode, surefire_rebuild.stderr)
    failed_fixture_smoke_run = self.setup_run()
    fixture_build = self.cli("build", "--run-id", failed_fixture_smoke_run)
    self.assertEqual(0, fixture_build.returncode, fixture_build.stderr)
    failed_compile_run = self.setup_run()
    compile_build = self.cli("build", "--run-id", failed_compile_run)
    self.assertEqual(0, compile_build.returncode, compile_build.stderr)
    failed_diff_run = self.setup_run()
    diff_build = self.cli("build", "--run-id", failed_diff_run)
    self.assertEqual(0, diff_build.returncode, diff_build.stderr)

    test_log = self.cwd / "python-tests.log"
    surefire_log = self.cwd / "surefire.log"
    step_log = self.cwd / "steps.log"
    mvn = self.cwd / "mvn"
    mvn.write_text('''#!/usr/bin/env python3.11
import os, shutil, sys
from pathlib import Path
if os.environ.get("MAVEN_SKIP_RC") != "1": raise SystemExit(92)
with open(os.environ["STEP_LOG"], "a") as out: out.write("java-tests\\n")
Path(os.environ["MAVEN_LOG"]).write_text("\\n".join(sys.argv[1:]) + "\\n")
if "clean" in sys.argv[1:]: shutil.rmtree(Path.cwd() / "target", ignore_errors=True)
raise SystemExit(int(os.environ.get("MAVEN_EXIT", "0")))
''', encoding="utf-8")
    mvn.chmod(0o700)
    (self.repo / "scripts/lifecycle.py").write_text('''import os, sys
from pathlib import Path
def java_21_runtime(output):
  return "JVM: 21" in output
if __name__ == "__main__":
  if sys.argv[1:] == ["verify-surefire"]:
    with open(os.environ["STEP_LOG"], "a") as out: out.write("surefire\\n")
    Path(os.environ["SUREFIRE_LOG"]).write_text("verified\\n")
    raise SystemExit(int(os.environ.get("SUREFIRE_EXIT", "0")))
  elif sys.argv[1:] in (["python-tests"], ["python-compile"], ["diff-check"]):
    action = sys.argv[1]
    with open(os.environ["STEP_LOG"], "a") as out: out.write(action + "\\n")
    if action == "python-tests":
      Path(os.environ["PYTHON_TEST_LOG"]).write_text("passed\\n")
    raise SystemExit(int(os.environ.get(action.upper().replace('-', '_') + "_EXIT", "0")))
  else: raise SystemExit(91)
''', encoding="utf-8")
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]
    self.env["STEP_LOG"] = str(step_log)
    self.env["MAVEN_LOG"] = str(self.cwd / "maven.log")
    self.env["SUREFIRE_LOG"] = str(surefire_log)
    self.env["PYTHON_TEST_LOG"] = str(test_log)
    tested = self.cli("test", "--run-id", run_id)
    self.assertEqual((0, "test verified\n", ""), (tested.returncode, tested.stdout, tested.stderr))
    self.assertTrue((self.run_directory(run_id) / "manifest.json").exists())
    self.assertEqual("passed\n", test_log.read_text())
    self.assertEqual(["--offline", "--batch-mode", "--no-transfer-progress", "package"],
                     (self.cwd / "maven.log").read_text().splitlines())
    self.assertEqual(["verified"], surefire_log.read_text().splitlines())
    self.assertEqual(["java-tests", "surefire", "python-tests", "python-compile", "image-smoke", "rp-fixture-smoke", "diff-check"],
                     step_log.read_text().splitlines())
    receipt = json.loads((self.run_directory(run_id) / "test.json").read_text())
    self.assertEqual("complete", receipt["status"])
    self.assertEqual([
        {"name": "java-tests", "status": "pass"},
        {"name": "surefire", "status": "pass"},
        {"name": "python-tests", "status": "pass"},
        {"name": "python-compile", "status": "pass"},
        {"name": "image-smoke", "status": "pass"},
        {"name": "rp-fixture-smoke", "status": "pass"},
        {"name": "diff-check", "status": "pass"},
    ], receipt["steps"])
    self.assertEqual("sha256:" + "1" * 64, receipt["provider_image_id"])
    engine_commands = [json.loads(line) for line in engine_log.read_text().splitlines()]
    smoke_commands = [command for command in engine_commands
                      if command[:3] == ["run", "--rm", "--network=none"]]
    self.assertEqual(2, len(smoke_commands))
    self.assertEqual(["run", "--rm", "--network=none", "--entrypoint",
                      "/opt/keycloak/bin/kc.sh", "sha256:" + "1" * 64, "--version"],
                     smoke_commands[0])
    self.assertEqual(["run", "--rm", "--network=none", "--entrypoint", "python3.11",
                      "sha256:" + "2" * 64, "-c", "import sys; sys.path.insert(0, '/opt/rp-fixture'); "
                      "import oidc_rp_fixture; print('RP fixture import ok')"], smoke_commands[1])

    resumed = self.cli("test", "--run-id", run_id)
    self.assertEqual((0, "test verified\n", ""), (resumed.returncode, resumed.stdout, resumed.stderr))
    self.assertEqual("passed\n", test_log.read_text())
    self.assertEqual(2, sum(command[:3] == ["run", "--rm", "--network=none"]
                             for command in map(json.loads, engine_log.read_text().splitlines())))
    java_test_source = next((self.repo / "src/test/java").rglob("*.java"))
    java_test_source.write_text(java_test_source.read_text() + chr(10) + "// test input changed")
    stale_receipt = self.cli("test", "--run-id", run_id)
    self.assertEqual(2, stale_receipt.returncode)
    self.assertEqual("", stale_receipt.stdout)
    self.assertEqual(["error: test source readback conflict"], stale_receipt.stderr.splitlines())
    self.assertEqual(["java-tests", "surefire", "python-tests", "python-compile", "image-smoke", "rp-fixture-smoke", "diff-check"],
                     step_log.read_text().splitlines())

    self.env["MAVEN_EXIT"] = "23"
    test_log.unlink()
    failed_java = self.cli("test", "--run-id", failed_java_run)
    self.assertEqual(3, failed_java.returncode)
    self.assertEqual("", failed_java.stdout)
    self.assertEqual(["error: offline Java test suite failed"], failed_java.stderr.splitlines())
    java_failure = json.loads(next(self.run_directory(failed_java_run).glob("failure-*.json")).read_text())
    self.assertEqual("java-tests", java_failure["phase"])
    self.assertFalse((self.run_directory(failed_java_run) / "test.json").exists())
    self.assertFalse(test_log.exists())
    self.assertEqual(["java-tests"], step_log.read_text().splitlines()[-1:])

    self.env["MAVEN_EXIT"] = "0"
    self.env["SUREFIRE_EXIT"] = "19"
    failed_surefire = self.cli("test", "--run-id", failed_surefire_run)
    self.assertEqual(3, failed_surefire.returncode)
    self.assertEqual("", failed_surefire.stdout)
    self.assertEqual(["error: Surefire verification failed"], failed_surefire.stderr.splitlines())
    surefire_failure = json.loads(next(self.run_directory(failed_surefire_run).glob("failure-*.json")).read_text())
    self.assertEqual("surefire", surefire_failure["phase"])
    self.assertFalse((self.run_directory(failed_surefire_run) / "test.json").exists())
    self.assertFalse(test_log.exists())
    self.assertEqual(["java-tests", "surefire"], step_log.read_text().splitlines()[-2:])
    engine_commands = [json.loads(line) for line in engine_log.read_text().splitlines()]
    self.assertEqual(2, sum(command[:3] == ["run", "--rm", "--network=none"]
                             for command in engine_commands))

    self.env["MAVEN_EXIT"] = "0"
    self.env["SUREFIRE_EXIT"] = "0"
    self.env["RP_SMOKE_EXIT"] = "19"
    failed_fixture_smoke = self.cli("test", "--run-id", failed_fixture_smoke_run)
    self.assertEqual((3, "", "error: RP fixture image smoke failed\n"),
                     (failed_fixture_smoke.returncode, failed_fixture_smoke.stdout,
                      failed_fixture_smoke.stderr))
    fixture_failure = json.loads(next(self.run_directory(failed_fixture_smoke_run)
                                      .glob("failure-*.json")).read_text())
    self.assertEqual("rp-fixture-smoke", fixture_failure["phase"])
    self.assertFalse((self.run_directory(failed_fixture_smoke_run) / "test.json").exists())
    engine_commands = [json.loads(line) for line in engine_log.read_text().splitlines()]
    self.assertEqual(4, sum(command[:3] == ["run", "--rm", "--network=none"]
                             for command in engine_commands))

    self.env["PYTHON_COMPILE_EXIT"] = "17"
    failed_compile = self.cli("test", "--run-id", failed_compile_run)
    self.assertEqual((3, "", "error: Python compilation failed\n"),
                     (failed_compile.returncode, failed_compile.stdout, failed_compile.stderr))
    compile_failure = json.loads(next(self.run_directory(failed_compile_run)
                                      .glob("failure-*.json")).read_text())
    self.assertEqual({"version": 1, "run_id": failed_compile_run,
                      "phase": "python-compile", "status": "failed"}, compile_failure)
    self.assertFalse((self.run_directory(failed_compile_run) / "test.json").exists())
    self.assertEqual(["java-tests", "surefire", "python-tests", "python-compile"],
                     step_log.read_text().splitlines()[-4:])

    self.env["PYTHON_COMPILE_EXIT"] = "0"
    self.env["RP_SMOKE_EXIT"] = "0"
    self.env["DIFF_CHECK_EXIT"] = "21"
    failed_diff = self.cli("test", "--run-id", failed_diff_run)
    self.assertEqual((3, "", "error: diff check failed\n"),
                     (failed_diff.returncode, failed_diff.stdout, failed_diff.stderr))
    diff_failure = json.loads(next(self.run_directory(failed_diff_run)
                                   .glob("failure-*.json")).read_text())
    self.assertEqual({"version": 1, "run_id": failed_diff_run,
                      "phase": "diff-check", "status": "failed"}, diff_failure)
    self.assertFalse((self.run_directory(failed_diff_run) / "test.json").exists())
    self.assertEqual(["java-tests", "surefire", "python-tests", "python-compile", "image-smoke", "rp-fixture-smoke", "diff-check"],
                     step_log.read_text().splitlines()[-7:])

  def test_build_stops_before_engine_when_locked_input_fetch_fails(self):
    self.prepare_build_inputs()
    engine_log = self.cwd / "engine.jsonl"
    engine = self.cwd / "podman"
    engine.write_text('''#!/usr/bin/env python3.11
import json, os, sys
with open(os.environ["ENGINE_LOG"], "a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")
raise SystemExit(91)
''', encoding="utf-8")
    engine.chmod(0o700)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]
    self.env["ENGINE_LOG"] = str(engine_log)
    self.env["MATERIALIZER_FAIL"] = "sources"
    run_id = self.setup_run()

    failed = self.cli("build", "--run-id", run_id)

    self.assertEqual((3, "", "error: provider build prerequisites failed\n"),
                     (failed.returncode, failed.stdout, failed.stderr))
    run_dir = self.run_directory(run_id)
    failure = json.loads(next(run_dir.glob("failure-*.json")).read_text())
    self.assertEqual({"version": 1, "run_id": run_id,
                      "phase": "resolver-inputs", "status": "failed"}, failure)
    self.assertFalse(engine_log.exists())
    materialized = [line.split() for line in
                    (self.cwd / "materializer.jsonl").read_text().splitlines()]
    sources = Path(materialized[0][materialized[0].index("--sources-directory") + 1])
    self.assertFalse(sources.exists())
    self.assertFalse((self.repo / "resolver-wheelhouse.tar.gz").exists())

  def test_build_failure_is_durable_and_resume_keeps_verified_provider(self):
    self.prepare_build_inputs()
    engine_log = self.cwd / "engine.jsonl"
    engine = self.cwd / "podman"
    engine.write_text('''#!/usr/bin/env python3.11
import json, os, sys
args = sys.argv[1:]
with open(os.environ["ENGINE_LOG"], "a") as out: out.write(json.dumps(args) + "\\n")
if args[0] == "build":
  if "rp-fixture" in args[args.index("--tag") + 1] and os.environ.get("FAIL_RP") == "1":
    raise SystemExit(12)
elif args[:3] == ["image", "inspect", "--format"]:
  image = args[-1]
  print(image if image.startswith("sha256:") else "sha256:" + ("1" if "provider" in image else "2") * 64)
else:
  raise SystemExit(91)
''', encoding="utf-8")
    engine.chmod(0o700)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]
    self.env["ENGINE_LOG"] = str(engine_log)
    self.env["FAIL_RP"] = "1"
    run_id = self.setup_run()
    failed = self.cli("build", "--run-id", run_id)
    self.assertEqual((3, "", "error: rp-fixture build or image readback failed\n"),
                     (failed.returncode, failed.stdout, failed.stderr))
    run_dir = self.run_directory(run_id)
    self.assertTrue((run_dir / "provider.json").is_file())
    self.assertFalse((run_dir / "rp-fixture.json").exists())
    self.assertFalse((run_dir / "build.json").exists())
    failures = list(run_dir.glob("failure-*.json"))
    self.assertEqual(1, len(failures))
    self.assertEqual({"version": 1, "run_id": run_id,
                      "phase": "rp-fixture", "status": "failed"}, json.loads(failures[0].read_text()))
    self.assertEqual(["build", "image", "build"],
                     [json.loads(line)[0] for line in engine_log.read_text().splitlines()])

    self.env.pop("FAIL_RP")
    resumed = self.cli("build", "--run-id", run_id)
    self.assertEqual((0, "build verified\n", ""),
                     (resumed.returncode, resumed.stdout, resumed.stderr))
    self.assertTrue((run_dir / "build.json").is_file())
    commands = [json.loads(line) for line in engine_log.read_text().splitlines()]
    self.assertEqual(6, len(commands))
    self.assertEqual("sha256:" + "1" * 64,
                     json.loads((run_dir / "provider.json").read_text())["image_id"])
    self.assertTrue(all("--network=none" in command for command in commands if command[0] == "build"))
    self.assertFalse(any(token in {"push", "publish", "deploy", "run"}
                         for command in commands for token in command))

  def test_build_rejects_invalid_immutable_id_readback_before_success(self):
    self.prepare_build_inputs()
    engine_log = self.cwd / "engine.jsonl"
    engine = self.cwd / "podman"
    engine.write_text('''#!/usr/bin/env python3.11
import json, os, sys
args = sys.argv[1:]
with open(os.environ["ENGINE_LOG"], "a") as out: out.write(json.dumps(args) + "\\n")
if args[0] == "build": print("ok")
elif args[:3] == ["image", "inspect", "--format"]: print("not-an-image-id")
else: raise SystemExit(91)
''', encoding="utf-8")
    engine.chmod(0o700)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]
    self.env["ENGINE_LOG"] = str(engine_log)
    run_id = self.setup_run()
    result = self.cli("build", "--run-id", run_id)
    self.assertEqual((3, "", "error: provider build or image readback failed\n"),
                     (result.returncode, result.stdout, result.stderr))
    run_dir = self.run_directory(run_id)
    self.assertFalse((run_dir / "provider.json").exists())
    self.assertFalse((run_dir / "build.json").exists())
    failure = json.loads(next(run_dir.glob("failure-*.json")).read_text())
    self.assertEqual("provider", failure["phase"])
    self.assertEqual(["build", "image"],
                     [json.loads(line)[0] for line in engine_log.read_text().splitlines()])

  def test_build_resume_conflicts_if_a_provider_artifact_changes(self):
    self.prepare_build_inputs()
    engine_log = self.cwd / "engine.jsonl"
    engine = self.cwd / "podman"
    engine.write_text('''#!/usr/bin/env python3.11
import json, os, sys
args = sys.argv[1:]
with open(os.environ["ENGINE_LOG"], "a") as out: out.write(json.dumps(args) + "\\n")
if args[0] == "build": print("build complete")
elif args[:3] == ["image", "inspect", "--format"]:
  image = args[-1]
  print(image if image.startswith("sha256:") else "sha256:" + ("1" if "provider" in image else "2") * 64)
else: raise SystemExit(91)
''', encoding="utf-8")
    engine.chmod(0o700)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]
    self.env["ENGINE_LOG"] = str(engine_log)
    run_id = self.setup_run()
    result = self.cli("build", "--run-id", run_id)
    self.assertEqual((0, "build verified\n", ""),
                     (result.returncode, result.stdout, result.stderr))

    artifact = self.repo / "target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar"
    artifact.write_bytes(b"changed provider artifact")
    resumed = self.cli("build", "--run-id", run_id)
    self.assertEqual((2, "", "error: build source or configuration readback conflict\n"),
                     (resumed.returncode, resumed.stdout, resumed.stderr))
    self.assertEqual(4, len(engine_log.read_text().splitlines()))

  def test_read_only_preflight_can_be_rechecked_without_advancing_any_phase(self):
    config = self.live_config()
    path = self.config_file(config)
    run_id = self.setup_run("--config", path)
    self.install_preflight_adapters()
    original = self.storage_snapshot()
    for _ in range(2):
      result = self.cli("preflight", "--run-id", run_id, "--config", path)
      self.assertEqual((0, "preflight passed\n", ""),
                       (result.returncode, result.stdout, result.stderr))
    self.assertEqual(original, self.storage_snapshot())
    manifest = self.run_directory(run_id) / "manifest.json"
    self.assertEqual(["setup"], json.loads(manifest.read_text())["completed"])
    calls = [json.loads(line) for line in (self.cwd / "tailscale.jsonl").read_text().splitlines()]
    self.assertEqual(4, len(calls))
    for call in calls:
      self.assertEqual(["ssh", "ben@ben-x260"], call[:2])
    self.assertEqual(["tailscale status --json"], calls[0][2:])
    self.assertEqual(["podman info --format json"], calls[1][2:])
    self.assertFalse((self.cwd / "ssh.jsonl").exists())
    self.assertEqual(["tailscale version", "podman --version"] * 2,
                     (self.cwd / "tool.jsonl").read_text().splitlines())

  def install_local_preflight_tools(self, engine):
    for name in tuple(self.env):
      if name.startswith(("FAKE_", "DOCKER_", "CONTAINER_")) or name in {
          "XDG_CONFIG_HOME", "PODMAN_CONNECTIONS_CONF"}:
        self.env.pop(name)
    log = self.cwd / "local-preflight-tools.log"
    log.write_text("", encoding="utf-8")
    scripts = {
        "java": '''#!/usr/bin/env python3.11
import os, sys
open(os.environ["LOCAL_PREFLIGHT_LOG"], "a").write("java\\n")
print('openjdk version "' + os.environ.get("FAKE_JAVA", "21.0.1") + '"', file=sys.stderr)
''',
        "mvn": '''#!/usr/bin/env python3.11
import os
open(os.environ["LOCAL_PREFLIGHT_LOG"], "a").write("mvn\\n")
print("Apache Maven " + os.environ.get("FAKE_MAVEN", "3.9.9"))
''',
        "git": '''#!/usr/bin/env python3.11
import os
open(os.environ["LOCAL_PREFLIGHT_LOG"], "a").write("git\\n")
print("git version " + os.environ.get("FAKE_GIT", "2.47.1"))
''',
    }
    for name, content in scripts.items():
      path = self.cwd / name
      path.write_text(content, encoding="utf-8")
      path.chmod(0o700)
    if engine == "podman":
      content = '''#!/usr/bin/env python3.11
import json, os, sys
args = sys.argv[1:]
open(os.environ["LOCAL_PREFLIGHT_LOG"], "a").write("podman " + " ".join(args) + "\\n")
if args == ["--version"]: print("podman version " + os.environ.get("FAKE_ENGINE", "5.4.0"))
elif args == ["info", "--format", "json"]: print(os.environ.get("FAKE_INFO", json.dumps({"host":{"security":{"rootless":os.environ.get("FAKE_ROOTLESS", "true") == "true"}}})))
elif args == ["images", "--no-trunc", "--format", "json"]: print(os.environ.get("FAKE_PODMAN_INVENTORY", "[]"))
else: raise SystemExit(91)
'''
    else:
      content = '''#!/usr/bin/env python3.11
import json, os, sys
args = sys.argv[1:]
open(os.environ["LOCAL_PREFLIGHT_LOG"], "a").write("docker " + " ".join(args) + "\\n")
if args == ["--version"]: print("Docker version " + os.environ.get("FAKE_ENGINE", "27.5.1") + ", build deadbee")
elif args == ["version", "--format", "{{.Server.Version}}"]: print(os.environ.get("FAKE_DAEMON", "27.5.1"))
elif args == ["image", "ls", "--no-trunc", "--format", "{{json .}}"]: print(os.environ.get("FAKE_INVENTORY", '{"ID":"sha256:' + 'd' * 64 + '"}'))
elif args == ["buildx", "version"]:
  if os.environ.get("FAKE_BUILDX") == "missing": raise SystemExit(1)
  print("github.com/docker/buildx v0.20.1")
else: raise SystemExit(91)
'''
    executable = self.cwd / engine
    executable.write_text(content, encoding="utf-8")
    executable.chmod(0o700)
    tailscale = self.cwd / "tailscale"
    tailscale.write_text('#!/bin/sh\necho tailscale >> "$LOCAL_PREFLIGHT_LOG"\nexit 99\n', encoding="utf-8")
    tailscale.chmod(0o700)
    self.env["LOCAL_PREFLIGHT_LOG"] = str(log)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]
    return log

  def test_local_preflight_passes_dev_podman_and_ci_docker_without_state_or_tailscale(self):
    for profile, engine in (("dev", "podman"), ("ci", "docker")):
      with self.subTest(profile=profile):
        log = self.install_local_preflight_tools(engine)
        path = self.config_file({"version": 1, "profile": profile, "engine": engine})
        run_id = self.setup_run("--profile", profile, "--config", path)
        before = self.storage_snapshot()
        result = self.cli("preflight", "--run-id", run_id, "--config", path)
        self.assertEqual((0, "preflight passed\n", ""),
                         (result.returncode, result.stdout, result.stderr))
        self.assertEqual(before, self.storage_snapshot())
        self.assertEqual(["setup"], json.loads((self.run_directory(run_id) / "manifest.json").read_text())["completed"])
        calls = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(["java", "mvn", "git"], calls[:3])
        self.assertFalse(any(call == "tailscale" for call in calls))
        self.assertIn(engine + " --version", calls)
        if engine == "podman":
          self.assertIn("podman info --format json", calls)
          self.assertIn("podman images --no-trunc --format json", calls)
        else:
          self.assertIn("docker version --format {{.Server.Version}}", calls)
          self.assertIn("docker buildx version", calls)
          self.assertIn("docker image ls --no-trunc --format {{json .}}", calls)

  def test_local_preflight_requires_exact_python_311_patch_before_tool_side_effects(self):
    calls = []

    def record_command(executable, arguments):
      calls.append((executable, arguments))
      return {
          "java": 'openjdk version "21.0.1"',
          "mvn": "Apache Maven 3.9.9",
          "git": "git version 2.47.1",
      }.get(executable, "podman version 5.4.0")

    with patch.object(keycloakctl_cli.sys, "version_info", (3, 11, 12)), \
         patch.object(keycloakctl_cli, "local_command", side_effect=record_command):
      with self.assertRaisesRegex(keycloakctl_cli.Rejected,
                                  "^preflight local tool check failed$"):
        keycloakctl_cli.perform_local_preflight(None, "dev")

    self.assertEqual([], calls)

  def test_local_preflight_accepts_empty_and_id_shaped_engine_inventories(self):
    cases = (("docker", "empty", {"FAKE_INVENTORY": ""}),
             ("docker", "row", {"FAKE_INVENTORY": json.dumps({"ID": "sha256:" + "a" * 64})}),
             ("podman", "empty", {"FAKE_PODMAN_INVENTORY": "[]"}),
             ("podman", "row", {"FAKE_PODMAN_INVENTORY": json.dumps([{"Id": "sha256:" + "b" * 64}])}))
    for engine, inventory_case, overrides in cases:
      with self.subTest(engine=engine, inventory_case=inventory_case):
        log = self.install_local_preflight_tools(engine)
        self.env.update(overrides)
        profile = "ci" if engine == "docker" else "dev"
        path = self.config_file({"version": 1, "profile": profile, "engine": engine})
        run_id = self.setup_run("--profile", profile, "--config", path)
        before = self.storage_snapshot()

        result = self.cli("preflight", "--run-id", run_id, "--config", path)

        self.assertEqual((0, "preflight passed\n", ""),
                         (result.returncode, result.stdout, result.stderr))
        self.assertEqual(before, self.storage_snapshot())
        self.assertFalse(any(call == "tailscale" for call in log.read_text().splitlines()))

  def test_local_preflight_rejects_malformed_image_inventory_rows(self):
    cases = (("docker", {"FAKE_INVENTORY": "{}"}),
             ("docker", {"FAKE_INVENTORY": json.dumps({"ID": 7})}),
             ("docker", {"FAKE_INVENTORY": json.dumps({"ID": "not-an-id"})}),
             ("podman", {"FAKE_PODMAN_INVENTORY": "[{}]"}),
             ("podman", {"FAKE_PODMAN_INVENTORY": json.dumps([{"Id": 7}])}),
             ("podman", {"FAKE_PODMAN_INVENTORY": json.dumps([{"Id": "sha256:short"}])}))
    for engine, overrides in cases:
      with self.subTest(engine=engine, overrides=overrides):
        log = self.install_local_preflight_tools(engine)
        self.env.update(overrides)
        profile = "ci" if engine == "docker" else "dev"
        path = self.config_file({"version": 1, "profile": profile, "engine": engine})
        run_id = self.setup_run("--profile", profile, "--config", path)
        before = self.storage_snapshot()

        result = self.cli("preflight", "--run-id", run_id, "--config", path)

        self.assertEqual((2, "", "error: preflight local tool check failed\n"),
                         (result.returncode, result.stdout, result.stderr))
        self.assertEqual(before, self.storage_snapshot())
        self.assertFalse(any(call == "tailscale" for call in log.read_text().splitlines()))

  def test_local_preflight_rejects_bad_toolchain_or_engine_readback(self):
    cases = (("java", {"FAKE_JAVA": "17.0.12"}),
             ("mvn", {"FAKE_MAVEN": "not-a-version"}),
             ("git", {"FAKE_GIT": "not-a-version"}),
             ("podman", {"FAKE_ENGINE": "not-a-version"}),
             ("podman", {"FAKE_ROOTLESS": "false"}),
             ("podman", {"FAKE_INFO": "not-json"}),
             ("podman", {"FAKE_PODMAN_INVENTORY": "not-json"}),
             ("docker", {"FAKE_ENGINE": "not-a-version"}),
             ("docker", {"FAKE_DAEMON": "unavailable"}),
             ("docker", {"FAKE_BUILDX": "missing"}),
             ("docker", {"FAKE_INVENTORY": "not-json"}))
    for engine, overrides in cases:
      with self.subTest(engine=engine, overrides=overrides):
        selected_engine = "podman" if engine in {"java", "mvn", "git"} else engine
        log = self.install_local_preflight_tools(selected_engine)
        self.env.update(overrides)
        profile = "ci" if selected_engine == "docker" else "dev"
        path = self.config_file({"version": 1, "profile": profile, "engine": selected_engine})
        run_id = self.setup_run("--profile", profile, "--config", path)
        before = self.storage_snapshot()
        result = self.cli("preflight", "--run-id", run_id, "--config", path)
        self.assertEqual((2, "", "error: preflight local tool check failed\n"),
                         (result.returncode, result.stdout, result.stderr))
        self.assertEqual(before, self.storage_snapshot())
        calls = log.read_text(encoding="utf-8").splitlines()
        self.assertFalse(any(call == "tailscale" for call in calls))

    log = self.install_local_preflight_tools("podman")
    (self.cwd / "mvn").unlink()
    path = self.config_file({"version": 1, "profile": "dev", "engine": "podman"})
    run_id = self.setup_run("--profile", "dev", "--config", path)
    before = self.storage_snapshot()
    result = self.cli("preflight", "--run-id", run_id, "--config", path)
    self.assertEqual((2, "", "error: preflight local tool check failed\n"),
                     (result.returncode, result.stdout, result.stderr))
    self.assertEqual(before, self.storage_snapshot())
    calls = log.read_text(encoding="utf-8").splitlines()
    self.assertTrue(calls)
    self.assertTrue(all(call == "java" for call in calls))

  def test_local_preflight_rejects_remote_engine_endpoints_before_engine_invocation(self):
    cases = (("docker", {"DOCKER_HOST": "tcp://remote.invalid:2376"}, None),
             ("docker", {"DOCKER_CONTEXT": "remote"}, "context"),
             ("docker", {}, "current-context"),
             ("docker", {}, "relative-current-context"),
             ("podman", {"CONTAINER_HOST": "ssh://user@remote.invalid/run/podman.sock"}),
             ("podman", {"CONTAINER_CONNECTION": "remote"}, "connection"))
    for case in cases:
      engine, endpoint_vars = case[:2]
      fixture = case[2] if len(case) == 3 else None
      with self.subTest(engine=engine, endpoint_vars=endpoint_vars):
        log = self.install_local_preflight_tools(engine)
        self.env.update(endpoint_vars)
        if fixture in {"context", "current-context", "relative-current-context"}:
          docker_dir = (self.repo / "docker-config" if fixture == "relative-current-context"
                        else self.cwd / ".docker")
          metadata = docker_dir / "contexts/meta/remote-id"
          metadata.mkdir(parents=True, exist_ok=True)
          (metadata / "meta.json").write_text(json.dumps({"Name": "remote", "Endpoints": {"docker": {"Host": "tcp://remote.invalid:2376"}}}))
          if fixture in {"current-context", "relative-current-context"}:
            (docker_dir / "config.json").write_text(json.dumps({"currentContext": "remote"}))
          self.env["DOCKER_CONFIG"] = ("docker-config" if fixture == "relative-current-context"
                                       else str(docker_dir))
        if fixture == "connection":
          connections = self.cwd / ".config/containers"
          connections.mkdir(parents=True)
          (connections / "podman-connections.json").write_text(json.dumps({
              "Default": "remote", "Connection list": [{"Name": "remote", "URI": "ssh://user@remote.invalid/run/podman.sock"}]}))
          self.env["XDG_CONFIG_HOME"] = str(self.cwd / ".config")
        profile = "ci" if engine == "docker" else "dev"
        path = self.config_file({"version": 1, "profile": profile, "engine": engine})
        run_id = self.setup_run("--profile", profile, "--config", path)
        before = self.storage_snapshot()
        result = self.cli("preflight", "--run-id", run_id, "--config", path)
        self.assertEqual((2, "", "error: preflight local tool check failed\n"),
                         (result.returncode, result.stdout, result.stderr))
        calls = log.read_text(encoding="utf-8").splitlines()
        self.assertFalse(any(call.startswith(engine + " ") for call in calls))
        self.assertFalse(any(call == "tailscale" for call in calls))
        self.assertEqual(before, self.storage_snapshot())

  def install_preflight_adapters(self, *, ip="100.64.12.100", rootless=True, malformed=False, ssh_status=0):
    tailscale = self.cwd / "tailscale"
    tailscale.write_text('''#!/usr/bin/python3
import json, os, sys
args = sys.argv[1:]
if args == ["version"]:
  with open(os.environ["TOOL_LOG"], "a") as out: out.write("tailscale version" + chr(10))
  if os.environ.get("FAIL_TOOL") == "tailscale": raise SystemExit(1)
  raise SystemExit(0)
if args[:1] != ["ssh"] or len(args) != 3: raise SystemExit(91)
with open(os.environ["TAILSCALE_LOG"], "a") as out: out.write(json.dumps(args) + chr(10))
if os.environ.get("SSH_STATUS", "0") != "0": raise SystemExit(int(os.environ["SSH_STATUS"]))
command = args[2]
if command == "tailscale status --json":
  print(json.dumps({"Self": {"DNSName": os.environ["TARGET_DNS_NAME"], "TailscaleIPs": [os.environ["TARGET_IP"]]}}))
elif command == "podman info --format json":
  if os.environ.get("MALFORMED"): print("not json")
  else: print(json.dumps({"host": {"security": {"rootless": os.environ["ROOTLESS"] == "true"}}}))
else: raise SystemExit(91)
''', encoding="utf-8")
    tailscale.chmod(0o700)
    podman = self.cwd / "podman"
    podman.write_text('''#!/usr/bin/python3
import os, sys
with open(os.environ["TOOL_LOG"], "a") as out:
  out.write("podman " + " ".join(sys.argv[1:]) + chr(10))
if os.environ.get("FAIL_TOOL") == "podman": raise SystemExit(1)
''', encoding="utf-8")
    podman.chmod(0o700)
    self.env["PATH"] = str(self.cwd) + os.pathsep + self.env["PATH"]
    self.env["TAILSCALE_LOG"] = str(self.cwd / "tailscale.jsonl")
    self.env["TOOL_LOG"] = str(self.cwd / "tool.jsonl")
    self.env["TARGET_IP"] = ip
    self.env["TARGET_DNS_NAME"] = "ben-x260.tailnet.ts.net"
    self.env["ROOTLESS"] = "true" if rootless else "false"
    self.env["MALFORMED"] = "1" if malformed else ""
    self.env["SSH_STATUS"] = str(ssh_status)
    self.env["FAIL_TOOL"] = ""

  def test_preflight_fails_closed_on_target_identity_and_remote_rootless_check(self):
    cases = (("identity mismatch", {"TARGET_IP": "100.64.12.101"}),
             ("identity mismatch", {"TARGET_DNS_NAME": "other-device.tailnet.ts.net"}),
             ("identity mismatch", {"TARGET_DNS_NAME": "ben-x260.other-tailnet.ts.net"}),
             ("not rootless", {"ROOTLESS": "false"}),
             ("invalid Podman response", {"MALFORMED": "1"}),
             ("SSH check failed", {"SSH_STATUS": "255"}),
             ("local tool check failed", {"FAIL_TOOL": "podman"}),
             ("local tool check failed", {"FAIL_TOOL": "tailscale"}))
    for message, overrides in cases:
      with self.subTest(message=message):
        config = self.live_config()
        path = self.config_file(config)
        run_id = self.setup_run("--config", path)
        self.install_preflight_adapters()
        self.env.update(overrides)
        before = self.storage_snapshot()
        result = self.cli("preflight", "--run-id", run_id, "--config", path)
        self.assertEqual((2, "", f"error: preflight {message}\n"),
                         (result.returncode, result.stdout, result.stderr))
        self.assertEqual(before, self.storage_snapshot())

  def test_preflight_requires_an_explicit_expected_tailscale_dns_name(self):
    config = self.live_config()
    del config["remote"]["target_dns_name"]
    path = self.config_file(config)
    run_id = self.setup_run("--config", path)
    self.install_preflight_adapters()

    result = self.cli("preflight", "--run-id", run_id, "--config", path)

    self.assertEqual((2, "", "error: preflight requires matching operator inputs and route attestation\n"),
                     (result.returncode, result.stdout, result.stderr))

  def test_full_first_step_uses_same_public_read_only_preflight_without_live_flag(self):
    config = self.live_config()
    path = self.config_file(config)
    run_id = self.setup_run("--config", path)
    self.install_preflight_adapters()
    before = self.storage_snapshot()
    for _ in range(2):
      result = self.cli("full", "--profile", "readiness", "--run-id", run_id, "--config", path)
      self.assertEqual((0, "preflight passed\n", ""),
                       (result.returncode, result.stdout, result.stderr))
    self.assertEqual(before, self.storage_snapshot())
    self.assertEqual(["setup"], json.loads((self.run_directory(run_id) / "manifest.json").read_text())["completed"])

  def rejection(self, code, message, *args):
    result = self.cli(*args)
    self.assertEqual((code, "", f"error: {message}\n"),
                     (result.returncode, result.stdout, result.stderr))

  def live_config(self, profile="readiness"):
    return {"version": 1, "profile": profile, "engine": "podman", "remote": {
        "target_host": "ben-x260", "target_dns_name": "ben-x260.tailnet.ts.net",
        "target_user": "ben",
        "target_ip": "100.64.12.100", "proxy_ip": "100.127.12.101",
        "public_origin": "https://fictional-keycloak.example.org", "route_attested": True,
    }}

  def test_full_requires_explicit_selection_and_resumes_only_the_same_run(self):
    base = ("full", "--profile", "readiness")
    unknown = "f" * 32
    self.rejection(2, "invalid arguments; see --help", *base)
    self.rejection(2, "invalid arguments; see --help", *base, "--run-id", unknown, "--new-run")
    self.rejection(2, "invalid arguments; see --help", "full", "--profile", "dev", "--new-run")
    self.rejection(2, "unknown run ID", *base, "--run-id", unknown)
    self.assertFalse((self.repo / "target").exists())
    self.assertFalse((self.repo / ".keycloakctl").exists())

    config = self.live_config()
    path = self.config_file(config)
    self.install_preflight_adapters()
    result = self.cli(*base, "--new-run", "--config", path)
    self.assertEqual(0, result.returncode, result.stderr)
    self.assertEqual("", result.stderr)
    self.assertRegex(result.stdout, r"\A[0-9a-f]{32}\npreflight passed\n\Z")
    run_id = result.stdout.splitlines()[0]
    manifest = self.run_directory(run_id) / "manifest.json"
    original = manifest.read_bytes()
    self.assertEqual(["setup"], json.loads(original)["completed"])
    result = self.cli(*base, "--run-id", run_id,
                      "--config", self.config_file(dict(reversed(list(config.items())))))
    self.assertEqual((0, "preflight passed\n", ""),
                     (result.returncode, result.stdout, result.stderr))
    self.rejection(2, "preflight requires matching operator inputs and route attestation", *base, "--run-id", run_id)
    self.rejection(2, "run profile does not match", "full", "--profile", "qualification", "--run-id", run_id)
    self.rejection(2, "run configuration readback conflict", *base, "--run-id", run_id,
                   "--config", self.config_file({**config, "engine": "docker"}))
    self.assertEqual({run_id}, {path.name for path in manifest.parent.parent.iterdir()})
    self.assertEqual(original, manifest.read_bytes())

  def test_live_and_publish_authorization_are_distinct_and_not_persisted(self):
    config = self.live_config("qualification")
    qual = ("--run-id", self.setup_run("--config", self.config_file(config)))
    ready = ("--run-id", self.setup_run("--profile", "readiness"))
    original = self.storage_snapshot()
    for command, run in (("publish", qual), ("deploy", qual), ("configure", qual),
                         ("integration-test", qual), ("teardown", qual), ("verify readiness", ready)):
      with self.subTest(command=command):
        args = (*command.split(), *run)
        denied = f"{command} requires --allow-live on this invocation"
        self.rejection(2, denied, *args)
        authorized = ("teardown requires exact run-owned deployment readback" if command == "teardown"
                      else "invalid phase order; next phase is preflight")
        self.rejection(2, authorized, *args, "--allow-live")
        self.rejection(2, denied, *args)

    self.rejection(2, "phase is not supported by run profile", "verify", "readiness", *qual, "--allow-live")
    self.rejection(2, "phase is not supported by run profile", "integration-test", *ready, "--allow-live")
    self.rejection(2, "phase is not supported by run profile", "verify", "qualification", *ready)
    self.rejection(2, "invalid phase order; next phase is preflight", "verify", "qualification", *qual)
    promote = ("promote", "--receipt", str(self.cwd / "reviewed-receipt.json"),
               "--destination", "docker://registry.invalid/example:rc-test")
    self.rejection(2, "promote requires --allow-publish on this invocation", *promote)
    self.rejection(2, "invalid arguments; see --help", *promote, "--allow-live")
    self.rejection(3, "promote unavailable in the offline foundation", *promote, "--allow-publish")
    self.rejection(2, "promote requires --allow-publish on this invocation", *promote)
    self.assertEqual(original, self.storage_snapshot())
    for raw in original.values():
      for forbidden in (b"allow-live", b"allow-publish", b"attested", b"fictional-keycloak", b"100.64.12.100"):
        self.assertNotIn(forbidden, raw)

  def storage_snapshot(self):
    return {path.relative_to(self.repo): path.read_bytes()
            for directory in (self.repo / "target", self.repo / ".keycloakctl")
            for path in directory.rglob("*") if path.is_file()}

  def test_invalid_config_never_creates_state_or_exposes_unknown_values(self):
    marker = "synthetic-credential-value-53394840d528"
    path = self.config_file({**self.live_config(), "client_secret": marker})
    self.rejection(2, "invalid configuration", "setup", "--config", path)
    self.rejection(2, "invalid configuration", "full", "--profile", "readiness", "--new-run", "--config", path)
    self.rejection(2, "invalid arguments; see --help", "setup", "--profile", marker)
    self.assertEqual({}, self.storage_snapshot())
    self.assertFalse((self.repo / "target").exists())
    self.assertFalse((self.repo / ".keycloakctl").exists())

  def test_remote_preflight_rejects_missing_or_placeholder_operator_inputs(self):
    config = self.live_config()
    for remote in ({}, {**config["remote"], "route_attested": False},
                   {**config["remote"], "public_origin": "https://readiness.example.invalid"},
                   {**config["remote"], "proxy_ip": config["remote"]["target_ip"]}):
      with self.subTest(remote=remote):
        path = self.config_file({**config, "remote": remote})
        run_id = self.setup_run("--config", path)
        original = self.storage_snapshot()
        self.rejection(2, "preflight requires matching operator inputs and route attestation",
                       "preflight", "--run-id", run_id, "--config", path)
        self.assertEqual(original, self.storage_snapshot())

  def reservation(self, run_id):
    return self.repo / ".keycloakctl/run-ids" / run_id

  def test_readback_refuses_copied_forged_missing_or_symlinked_manifests(self):
    self.prepare_build_inputs()
    self.use_unavailable_engine()
    first, second = self.setup_run(), self.setup_run()
    manifest = self.run_directory(first) / "manifest.json"
    other = self.run_directory(second) / "manifest.json"
    original = manifest.read_bytes()
    marker = "run-readback-secret-marker-c11abb6fb07"
    manifest.write_bytes(other.read_bytes())
    self.rejection(2, "run readback conflict", "build", "--run-id", first)
    self.rejection(3, "provider build or image readback failed", "build", "--run-id", second)
    forged = {**json.loads(original), "completed": ["setup", "build"]}
    for raw in (json.dumps(forged).encode(), json.dumps({**json.loads(original), "token": marker}).encode(),
                original.replace(b'{', b'{"version":1,', 1)):
      with self.subTest(case=raw[:20]):
        # Even if a local editor also changes the hash, invalid state is rejected.
        self.reservation(first).write_text(sha256(raw).hexdigest(), encoding="ascii")
        manifest.write_bytes(raw)
        self.rejection(2, "run readback conflict", "test", "--run-id", first)
        self.assertEqual(raw, manifest.read_bytes())

    manifest.unlink()
    self.rejection(2, "run readback conflict", "setup", "--run-id", first)
    self.reservation(first).write_text(sha256(original).hexdigest(), encoding="ascii")
    outside = self.cwd / "outside.json"
    outside.write_bytes(original)
    manifest.symlink_to(outside)
    self.rejection(2, "run readback conflict", "setup", "--run-id", first)
    self.assertEqual(original, outside.read_bytes())
    manifest.unlink()
    manifest.write_bytes(original)
    self.reservation(first).unlink()
    self.rejection(2, "run readback conflict", "setup", "--run-id", first)

  def test_teardown_never_treats_phase_completion_as_ownership_proof(self):
    config = self.live_config()
    run_id = self.setup_run("--config", self.config_file(config))
    state_path = self.run_directory(run_id) / "manifest.json"
    original = state_path.read_bytes()
    result = self.cli("teardown", "--run-id", run_id, "--allow-live")
    self.assertEqual((2, "", "error: teardown requires exact run-owned deployment readback\n"),
                     (result.returncode, result.stdout, result.stderr))
    self.assertEqual(original, state_path.read_bytes())
    forged = {**json.loads(original), "completed": ["setup", "preflight", "build", "test",
                                                       "publish", "deploy"]}
    raw = json.dumps(forged, separators=(",", ":")).encode() + b"\n"
    self.reservation(run_id).write_text(sha256(raw).hexdigest(), encoding="ascii")
    state_path.write_bytes(raw)
    result = self.cli("teardown", "--run-id", run_id, "--allow-live")
    self.assertEqual((2, "", "error: run readback conflict\n"),
                     (result.returncode, result.stdout, result.stderr))
    self.assertEqual(raw, state_path.read_bytes())

  def use_fixed_run_id(self, run_id):
    # Force a collision across real executable processes. No runtime credentials
    # or production test flags; inject only the UUID source at interpreter startup.
    (self.cwd / "sitecustomize.py").write_text(
        f"import uuid\nuuid.uuid4 = lambda: uuid.UUID('{run_id}')\n", encoding="ascii")
    self.env["PYTHONPATH"] = str(self.cwd)

  def test_concurrent_setup_exclusively_creates_one_run_and_never_reuses_its_id(self):
    run_id = "a" * 32
    self.use_fixed_run_id(run_id)
    with ThreadPoolExecutor(max_workers=2) as pool:
      first = pool.submit(self.cli, "setup", "--profile", "dev")
      second = pool.submit(self.cli, "setup", "--profile", "ci")
      results = sorted((first.result(), second.result()), key=lambda result: result.returncode)
    self.assertEqual((0, run_id + "\n", ""), (results[0].returncode, results[0].stdout, results[0].stderr))
    self.assertEqual((2, "", "error: run ID already reserved or run directory exists\n"),
                     (results[1].returncode, results[1].stdout, results[1].stderr))
    original = self.storage_snapshot()
    self.assertEqual(run_id, self.setup_run("--run-id", run_id))
    self.assertEqual(2, len(original))
    self.assertEqual(original, self.storage_snapshot())

    shutil.rmtree(self.repo / "target", ignore_errors=True)  # Run manifests follow the required target/ layout.
    self.rejection(2, "run ID already reserved or run directory exists", "setup")
    self.rejection(2, "run readback conflict", "setup", "--run-id", run_id)
    self.assertEqual(original[self.reservation(run_id).relative_to(self.repo)],
                     self.reservation(run_id).read_bytes())

  def test_setup_never_overwrites_a_preexisting_run_directory(self):
    run_id = "b" * 32
    self.use_fixed_run_id(run_id)
    directory = self.run_directory(run_id)
    directory.mkdir(parents=True)
    manifest = directory / "manifest.json"
    manifest.write_bytes(b"existing bytes without a reservation\n")
    self.rejection(2, "run ID already reserved or run directory exists", "setup")
    self.assertEqual(b"existing bytes without a reservation\n", manifest.read_bytes())
    self.rejection(2, "run readback conflict", "setup", "--run-id", run_id)
    shutil.rmtree(directory)
    self.rejection(2, "run ID already reserved or run directory exists", "setup")
    self.assertFalse(directory.exists())


if __name__ == "__main__":
  unittest.main()
