"""Public contract tests for the repository lifecycle CLI."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import lifecycle
from scripts.lifecycle import _engine_command, image_smoke_command, normalize_image_id


ROOT = Path(__file__).parents[1]
CLI = ROOT / "scripts" / "lifecycle.py"


class LifecycleCliTest(unittest.TestCase):
  def run_cli(self, *args):
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

  def test_podman_and_docker_image_ids_are_normalized(self):
    raw_id = "a" * 64
    self.assertEqual(f"sha256:{raw_id}", normalize_image_id(raw_id))
    image_id = normalize_image_id(f"sha256:{raw_id}")
    self.assertIsNotNone(image_id)
    assert image_id is not None
    self.assertEqual(f"sha256:{raw_id}", image_id)
    self.assertIsNone(normalize_image_id("short-id"))
    self.assertEqual(
        ["podman", "run", "--rm", "--entrypoint", "/opt/keycloak/bin/kc.sh",
         f"sha256:{raw_id}", "--version"],
        image_smoke_command("podman", image_id),
    )

  def test_both_container_engines_receive_the_run_scoped_dependency_context(self):
    sources = Path("/run/source-checkouts")
    dependencies = Path("/run/binary-dependencies")
    for engine in ("docker", "podman"):
      command = _engine_command(engine, "candidate", sources, dependencies)
      self.assertIn(f"binary-dependencies={dependencies}", command)
      self.assertIn(f"identity-src={sources / 'identity'}", command)
      self.assertIn(f"registry-src={sources / 'registry'}", command)

  def test_preflight_runs_before_evidence_directory_is_created(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      evidence = root / "target/lifecycle/evidence"

      def preflight_before_write(*, live=False):
        self.assertFalse(evidence.exists())
        return 1

      with mock.patch.object(lifecycle, "ROOT", root), \
          mock.patch.object(lifecycle, "preflight", side_effect=preflight_before_write), \
          mock.patch.object(lifecycle, "fingerprint_source", return_value={}):
        result = lifecycle.run_profile("offline")

      self.assertEqual(2, result)
      receipts = list(evidence.glob("*.json"))
      self.assertEqual(1, len(receipts))
      receipt = json.loads(receipts[0].read_text())
      self.assertEqual("fail", receipt["steps"]["preflight"]["status"])

  def test_interrupted_current_stage_is_recorded_and_later_stage_remains_not_run(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      with mock.patch.object(lifecycle, "ROOT", root), \
          mock.patch.object(lifecycle, "preflight", return_value=0), \
          mock.patch.object(lifecycle, "fingerprint_source", return_value={}), \
          mock.patch.object(lifecycle, "container_engine", return_value="docker"), \
          mock.patch.object(lifecycle, "run", side_effect=KeyboardInterrupt):
        result = lifecycle.run_profile("offline")

      self.assertEqual(130, result)
      receipt = json.loads(next((root / "target/lifecycle/evidence").glob("*.json")).read_text())
      self.assertEqual("interrupted", receipt["steps"]["java-tests"]["status"])
      self.assertEqual("not_run", receipt["steps"]["surefire"]["status"])
      self.assertEqual("pass", receipt["steps"]["evidence"]["status"])
      self.assertEqual("pass", receipt["steps"]["teardown"]["status"])

  def test_interrupted_resolver_materialization_is_recorded_without_masking_cleanup(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      with mock.patch.object(lifecycle, "ROOT", root), \
          mock.patch.object(lifecycle, "preflight", return_value=0), \
          mock.patch.object(lifecycle, "fingerprint_source", return_value={}), \
          mock.patch.object(lifecycle, "container_engine", return_value="docker"), \
          mock.patch.object(lifecycle, "run", side_effect=[0, KeyboardInterrupt()]), \
          mock.patch.object(lifecycle, "verify_surefire", return_value=0), \
          mock.patch.object(lifecycle, "run_python_tests", return_value=0), \
          mock.patch.object(lifecycle, "compile_sources", return_value=0):
        result = lifecycle.run_profile("offline")

      self.assertEqual(130, result)
      receipt = json.loads(next((root / "target/lifecycle/evidence").glob("*.json")).read_text())
      self.assertEqual("interrupted", receipt["steps"]["resolver-sources"]["status"])
      self.assertEqual("not_run", receipt["steps"]["provider-service-registration"]["status"])
      self.assertEqual("pass", receipt["cleanup"]["status"])

  def test_cleanup_discovers_and_removes_run_tag_after_interrupted_build(self):
    image_id = "sha256:" + "a" * 64
    inspected = subprocess.CompletedProcess([], 0, image_id + "\n", "")
    with mock.patch.object(lifecycle, "capture_command", return_value=inspected), \
        mock.patch.object(lifecycle, "_image_remove", return_value=0) as remove:
      result = lifecycle._cleanup_run_image("podman", "run-unique-tag", None)

    self.assertEqual(0, result)
    remove.assert_called_once_with("podman", "run-unique-tag", image_id)

  def make_git_worktree(self, root: Path):
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Lifecycle Test"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "lifecycle@example.invalid"], check=True)
    (root / "tracked.txt").write_text("baseline\n")
    subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "baseline"], check=True)

  def test_local_diff_check_catches_tracked_worktree_edits(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      self.make_git_worktree(root)
      (root / "tracked.txt").write_text("changed \n")
      with mock.patch.object(lifecycle, "ROOT", root):
        with mock.patch.dict(lifecycle.os.environ, {"PR_BASE_SHA": ""}):
          result = lifecycle.diff_check()

    self.assertNotEqual(0, result)

  def test_local_diff_check_catches_untracked_files_before_staging(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      self.make_git_worktree(root)
      (root / "new.py").write_text("untracked \n")
      with mock.patch.object(lifecycle, "ROOT", root):
        with mock.patch.dict(lifecycle.os.environ, {"PR_BASE_SHA": ""}):
          result = lifecycle.diff_check()

    self.assertNotEqual(0, result)

  def test_lists_named_profiles_and_distinguishes_live_qualification(self):
    result = self.run_cli("profiles", "--json")

    self.assertEqual(0, result.returncode, result.stderr)
    profiles = json.loads(result.stdout)
    self.assertEqual({"offline", "ci", "issue5-live"}, set(profiles))
    self.assertFalse(profiles["offline"]["live"])
    self.assertTrue(profiles["issue5-live"]["live"])

  def test_live_profile_refuses_to_start_without_explicit_opt_in(self):
    result = self.run_cli("run", "issue5-live", "--plan")

    self.assertNotEqual(0, result.returncode)
    self.assertIn("--allow-live", result.stderr)

  def test_plan_is_json_and_uses_the_canonical_python_suite(self):
    result = self.run_cli("run", "offline", "--plan", "--json")

    self.assertEqual(0, result.returncode, result.stderr)
    plan = json.loads(result.stdout)
    self.assertEqual("offline", plan["profile"])
    names = [step["name"] for step in plan["steps"]]
    self.assertIn("java-tests", names)
    self.assertIn("python-tests", names)
    self.assertIn("provider-image", names)
    self.assertIn("resolver-sources", names)
    self.assertIn("resolver-dependencies", names)
    self.assertIn("evidence", names)
    self.assertIn("teardown", names)
    suite = next(step for step in plan["steps"] if step["name"] == "python-tests")
    self.assertEqual("python-tests", suite["command"][-1])

  def test_ci_and_local_offline_profiles_share_one_definition(self):
    local = self.run_cli("run", "offline", "--plan", "--json")
    ci = self.run_cli("run", "ci", "--plan", "--json")

    self.assertEqual(0, local.returncode, local.stderr)
    self.assertEqual(0, ci.returncode, ci.stderr)
    self.assertEqual(json.loads(local.stdout)["steps"], json.loads(ci.stdout)["steps"])

  def test_live_profile_plan_uses_the_immutable_image_built_by_the_lifecycle(self):
    result = self.run_cli("run", "issue5-live", "--plan", "--json", "--allow-live")

    self.assertEqual(0, result.returncode, result.stderr)
    plan = json.loads(result.stdout)
    steps = {step["name"]: step for step in plan["steps"]}
    self.assertIn("provider-image", steps)
    self.assertIn("issue5-live-matrix", steps)
    self.assertEqual("full", steps["issue5-live-matrix"]["env"]["WALLET_IT_PROFILE"])
    self.assertIn("--allow-live", steps["issue5-live-matrix"]["requires"])


if __name__ == "__main__":
  unittest.main()
