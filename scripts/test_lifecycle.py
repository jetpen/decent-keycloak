"""Public contract tests for the repository lifecycle CLI."""

import hashlib
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
      command = _engine_command(engine, "candidate", sources, dependencies, run_id="e" * 32)
      self.assertIn(f"binary-dependencies={dependencies}", command)
      self.assertIn(f"identity-src={sources / 'identity'}", command)
      self.assertIn(f"registry-src={sources / 'registry'}", command)

  def test_both_build_engines_label_every_build_stage_with_the_run_owner(self):
    sources = Path("/run/source-checkouts")
    dependencies = Path("/run/binary-dependencies")
    run_id = "e" * 32
    for engine in ("docker", "podman"):
      command = _engine_command(engine, "candidate", sources, dependencies, run_id=run_id)
      self.assertIn(f"LIFECYCLE_RUN_ID={run_id}", command)
      self.assertIn("--build-arg", command)
      self.assertEqual([engine, "image", "rm", "sha256:" + "a" * 64],
          lifecycle._image_remove_command(engine, "sha256:" + "a" * 64))
      self.assertEqual([engine, "image", "rm", "tag"],
          lifecycle._image_remove_tag_command(engine, "tag"))
      self.assertEqual([engine, "image", "tag", "source", "target"],
          lifecycle._image_tag_command(engine, "source", "target"))
      self.assertEqual([engine, "image", "ls", "--all", "--no-trunc", "--quiet"],
          lifecycle._image_inventory_command(engine))

    dockerfile = (ROOT / "container/Dockerfile").read_text()
    stages = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    labels = [line for line in dockerfile.splitlines()
              if "io.decent.lifecycle.run-id" in line]
    self.assertEqual(len(stages), len(labels), "every Dockerfile stage must carry the run owner label")

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

  def test_run_profile_retains_image_only_with_opt_in_and_matching_owned_id(self):
    image_id = "sha256:" + "a" * 64
    absent = subprocess.CompletedProcess([], 1, "", "")
    present = subprocess.CompletedProcess([], 0, image_id + "\n", "")
    owner_run_id = {"value": ""}
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      def fake_run(command, **_kwargs):
        if "build" in command:
          build_tag = command[command.index("--tag") + 1]
          owner_run_id["value"] = build_tag.rsplit("lifecycle-", 1)[1]
        return 0

      def fake_capture(command):
        if "{{json .}}" in command:
          payload = [{"Id": image_id, "Parent": "", "Config": {"Labels": {
              "io.decent.lifecycle.run-id": owner_run_id["value"]}}}]
          return subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        if command[1:3] == ["image", "ls"]:
          if not owner_run_id["value"]:
            return subprocess.CompletedProcess([], 0, "", "")
          return subprocess.CompletedProcess([], 0, image_id + "\n", "")
        if "{{.Id}}" in command:
          return absent if not owner_run_id["value"] else present
        return present
      with mock.patch.object(lifecycle, "ROOT", root), \
          mock.patch.object(lifecycle, "preflight", return_value=0), \
          mock.patch.object(lifecycle, "fingerprint_source", return_value={}), \
          mock.patch.object(lifecycle, "container_engine", return_value="podman"), \
          mock.patch.object(lifecycle, "core_test_stages", return_value=[]), \
          mock.patch.object(lifecycle, "run", side_effect=fake_run), \
          mock.patch.object(lifecycle, "verify_provider", return_value=0), \
          mock.patch.object(lifecycle, "_run_capture",
              return_value=(0, "Keycloak 26.8.0\\nJVM: 21.0.12.1")), \
          mock.patch.object(lifecycle, "diff_check", return_value=0), \
          mock.patch.object(lifecycle, "capture_command", side_effect=fake_capture), \
          mock.patch.object(lifecycle, "_cleanup_owned_images", return_value={
              "status": "pass", "image_retained": True, "removed_image_count": 0,
              "removed_image_ids": [], "unowned_new_image_count": 0,
              "inconclusive_image_count": 0}) as cleanup:
        result = lifecycle.run_profile("offline", retain_image=True)

      receipt = json.loads(next((root / "target/lifecycle/evidence").glob("*.json")).read_text())
      self.assertEqual(0, result)
      self.assertTrue(receipt["image"]["retained"])
      self.assertEqual(0, receipt["image"]["baseline_image_count"])
      self.assertEqual([], receipt["image"]["baseline_image_ids"])
      self.assertEqual(64, len(receipt["image"]["baseline_image_ids_sha256"]))
      self.assertTrue(receipt["cleanup"]["image_retained"])
      self.assertEqual("pass", receipt["cleanup"]["status"])
      cleanup.assert_called_once()

  def _run_profile_with_fake_engine(self, *, build_outcome="success", retain=False,
      change_owner_before_removal=False, add_unowned_image=False, removal_noop=False,
      uninspectable_transient_image=False,
      known_owned_transient_becomes_uninspectable=False):
    baseline_id = "sha256:" + "b" * 64
    runtime_id = "sha256:" + "a" * 64
    builder_id = "sha256:" + "c" * 64
    base_stage_id = "sha256:" + "d" * 64
    transient_id = "sha256:" + "e" * 64
    images = {baseline_id: {"Parent": "", "owner": "upstream"}}
    tags = {"pre-existing:keep": baseline_id}
    run_id = None
    inventory_calls = 0
    changed = False
    removals = []

    def inspected_image(image_id):
      record = images.get(image_id)
      if uninspectable_transient_image and image_id == transient_id:
        payload = [{"Id": image_id, "Parent": record["Parent"], "Config": {"Labels": {}}}]
        return subprocess.CompletedProcess([], 0, json.dumps(payload), "")
      if known_owned_transient_becomes_uninspectable and image_id == transient_id and inventory_calls > 2:
        return subprocess.CompletedProcess([], 1, "", "not found")
      if record is None:
        return subprocess.CompletedProcess([], 1, "", "not found")
      labels = {"io.decent.lifecycle.run-id": record["owner"]}
      payload = [{"Id": image_id, "Parent": record["Parent"], "Config": {"Labels": labels}}]
      return subprocess.CompletedProcess([], 0, json.dumps(payload), "")

    def capture(command):
      nonlocal inventory_calls, changed
      if command[1:3] == ["image", "ls"]:
        inventory_calls += 1
        return subprocess.CompletedProcess([], 0, "\n".join(sorted(images)) + "\n", "")
      if command[1:3] == ["image", "inspect"]:
        image = command[-1]
        image_id = tags.get(image, image if image in images else None)
        if "{{json .}}" in command:
          if (change_owner_before_removal and image_id == builder_id
              and not changed and inventory_calls > 2):
            changed = True
            images[builder_id]["owner"] = "another-run"
          return inspected_image(image_id) if image_id else subprocess.CompletedProcess([], 1, "", "not found")
        if "{{.Id}}" in command:
          return subprocess.CompletedProcess([], 0 if image_id else 1,
              (image_id + "\n") if image_id else "", "")
      return subprocess.CompletedProcess([], 1, "", "unexpected engine command")

    def engine_run(command, **_kwargs):
      nonlocal run_id
      if "build" in command:
        build_tag = command[command.index("--tag") + 1]
        run_id = build_tag.rsplit("lifecycle-", 1)[1]
        images[base_stage_id] = {"Parent": "", "owner": run_id}
        images[builder_id] = {"Parent": base_stage_id, "owner": run_id}
        images[runtime_id] = {"Parent": builder_id, "owner": run_id}
        if uninspectable_transient_image or known_owned_transient_becomes_uninspectable:
          # Podman may list an intermediate builder ID whose inspect metadata
          # is unavailable; removing its owned parent/runtime deletes it too.
          images[transient_id] = {"Parent": builder_id, "owner": run_id}
        if add_unowned_image:
          images["sha256:" + "f" * 64] = {"Parent": "", "owner": "unrelated-run"}
        tags[build_tag] = runtime_id
        if build_outcome == "interrupt":
          raise KeyboardInterrupt
        return 7 if build_outcome == "failure" else 0
      if command[1:3] == ["image", "rm"]:
        target = command[-1]
        image_id = tags.pop(target, target)
        removals.append(image_id)
        if not removal_noop:
          images.pop(image_id, None)
          if uninspectable_transient_image and image_id == builder_id:
            images.pop(transient_id, None)
          for tag, tagged_id in list(tags.items()):
            if tagged_id == image_id:
              del tags[tag]
        return 0
      return 0

    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      with mock.patch.object(lifecycle, "ROOT", root), \
          mock.patch.object(lifecycle, "preflight", return_value=0), \
          mock.patch.object(lifecycle, "fingerprint_source", return_value={}), \
          mock.patch.object(lifecycle, "container_engine", return_value="podman"), \
          mock.patch.object(lifecycle, "core_test_stages", return_value=[]), \
          mock.patch.object(lifecycle, "run", side_effect=engine_run), \
          mock.patch.object(lifecycle, "verify_provider", return_value=0), \
          mock.patch.object(lifecycle, "_run_capture",
              return_value=(0, "Keycloak 26.8.0\nJVM: 21.0.12.1")), \
          mock.patch.object(lifecycle, "diff_check", return_value=0), \
          mock.patch.object(lifecycle, "capture_command", side_effect=capture):
        try:
          result = lifecycle.run_profile("offline", retain_image=retain)
        except SystemExit as error:
          result = 0 if error.code is None else int(error.code)
      receipt = json.loads(next((root / "target/lifecycle/evidence").glob("*.json")).read_text())
    return result, receipt, images, removals, baseline_id, runtime_id, builder_id, base_stage_id

  def test_successful_run_removes_all_new_owned_images_but_preserves_preexisting_image(self):
    result, receipt, images, removals, baseline, runtime, builder, base_stage = \
        self._run_profile_with_fake_engine()

    self.assertEqual(0, result)
    self.assertEqual({baseline}, set(images))
    self.assertNotIn(runtime, images)
    self.assertEqual([runtime, builder, base_stage], removals)
    self.assertEqual("pass", receipt["cleanup"]["status"])
    self.assertEqual(3, receipt["cleanup"]["removed_image_count"])
    self.assertEqual(1, receipt["cleanup"]["baseline_image_count"])
    self.assertEqual([baseline], receipt["cleanup"]["baseline_image_ids"])

  def test_failed_and_interrupted_builds_remove_all_partial_run_owned_images(self):
    for outcome, expected_code in (("failure", 7), ("interrupt", 130)):
      with self.subTest(outcome=outcome):
        result, receipt, images, removals, baseline, *_ = self._run_profile_with_fake_engine(
            build_outcome=outcome)
        self.assertEqual(expected_code, result)
        self.assertEqual({baseline}, set(images))
        self.assertEqual(3, len(removals))
        self.assertEqual("pass", receipt["cleanup"]["status"])
        self.assertEqual(3, receipt["cleanup"]["removed_image_count"])

  def test_retain_image_keeps_only_the_exact_final_runtime_image(self):
    result, receipt, images, removals, baseline, runtime, *_ = \
        self._run_profile_with_fake_engine(retain=True)

    self.assertEqual(0, result)
    self.assertEqual({baseline, runtime}, set(images))
    self.assertEqual("pass", receipt["cleanup"]["status"])
    self.assertTrue(receipt["cleanup"]["image_retained"])
    self.assertEqual(2, receipt["cleanup"]["removed_image_count"])
    self.assertNotIn(runtime, removals)

  def test_uninspectable_transient_id_removed_transitively_does_not_fail_cleanup(self):
    result, receipt, images, removals, baseline, runtime, builder, base_stage = \
        self._run_profile_with_fake_engine(uninspectable_transient_image=True)
    transient = "sha256:" + "e" * 64

    self.assertEqual(0, result)
    self.assertEqual({baseline}, set(images))
    self.assertEqual([runtime, builder, base_stage], removals)
    self.assertNotIn(transient, images)
    self.assertEqual("pass", receipt["cleanup"]["status"])
    self.assertEqual(4, receipt["cleanup"]["candidate_image_count"])
    self.assertEqual(3, receipt["cleanup"]["removed_image_count"])
    self.assertEqual(0, receipt["cleanup"]["inconclusive_image_count"])

  def test_uninspectable_transient_id_that_survives_cleanup_fails_closed(self):
    result, receipt, images, _removals, baseline, *_ = \
        self._run_profile_with_fake_engine(
            uninspectable_transient_image=True, removal_noop=True)
    transient = "sha256:" + "e" * 64

    self.assertNotEqual(0, result)
    self.assertEqual({baseline, transient, "sha256:" + "a" * 64,
        "sha256:" + "c" * 64, "sha256:" + "d" * 64}, set(images))
    self.assertEqual("fail", receipt["cleanup"]["status"])
    self.assertGreater(receipt["cleanup"]["inconclusive_image_count"], 0)

  def test_previously_identified_owned_transient_that_becomes_uninspectable_fails_closed(self):
    result, receipt, images, _removals, _baseline, *_ = \
        self._run_profile_with_fake_engine(
            known_owned_transient_becomes_uninspectable=True)
    transient = "sha256:" + "e" * 64

    self.assertNotEqual(0, result)
    self.assertIn(transient, images)
    self.assertEqual("fail", receipt["cleanup"]["status"])
    self.assertGreater(receipt["cleanup"]["inconclusive_image_count"], 0)

  def test_changed_run_ownership_label_is_preserved_and_cleanup_fails_closed(self):
    result, receipt, images, removals, baseline, _, builder, *_ = \
        self._run_profile_with_fake_engine(change_owner_before_removal=True)

    self.assertNotEqual(0, result)
    self.assertIn(builder, images)
    self.assertEqual("another-run", images[builder]["owner"])
    self.assertNotIn(builder, removals)
    self.assertEqual("fail", receipt["cleanup"]["status"])

  def test_cleanup_inventory_or_readback_failure_fails_the_lifecycle(self):
    result, receipt, *_ = self._run_profile_with_fake_engine()
    self.assertEqual(0, result)

    with mock.patch.object(lifecycle, "capture_command",
        return_value=subprocess.CompletedProcess([], 1, "", "engine unavailable")):
      with self.assertRaisesRegex(RuntimeError, "image_inventory_unavailable"):
        lifecycle._cleanup_owned_images("podman", set(), "f" * 32)

  def test_successful_remove_command_without_exact_id_readback_fails_lifecycle(self):
    result, receipt, images, removals, baseline, *_ = self._run_profile_with_fake_engine(
        removal_noop=True)

    self.assertNotEqual(0, result)
    self.assertTrue(removals)
    self.assertGreater(receipt["cleanup"]["inconclusive_image_count"], 0)
    self.assertEqual("fail", receipt["cleanup"]["status"])
    self.assertIn(baseline, images)

  def test_unowned_new_image_is_preserved_without_failing_owned_cleanup(self):
    result, receipt, images, removals, baseline, *_ = self._run_profile_with_fake_engine(
        add_unowned_image=True)
    upstream_new = "sha256:" + "f" * 64

    self.assertEqual(0, result)
    self.assertEqual({baseline, upstream_new}, set(images))
    self.assertNotIn(upstream_new, removals)
    self.assertEqual(1, receipt["cleanup"]["unowned_new_image_count"])
    self.assertEqual("pass", receipt["cleanup"]["status"])

  def test_promotion_requires_complete_live_receipt_and_explicit_image_retention(self):
    image_id = "sha256:" + "a" * 64
    gates = {
        name: ("unavailable" if name in lifecycle.ISSUE5_ADVERSARIAL_CASES else "pass")
        for name in lifecycle.ISSUE5_GATES
    }
    receipt = {
        "profile": "issue5-live", "exit_code": 0,
        "source": {"revision": "c" * 40, "harness_sha256": "d" * 64,
            "resolver_manifest_sha256": "e" * 64,
            "resolver_dependency_provenance_sha256": "f" * 64,
            "resolver_requirements_sha256": "1" * 64},
        "issue5_acceptance_gates": gates,
        "image": {"status": "built", "engine": "podman", "run_owned_tag": "decent-keycloak-wallet-provider:lifecycle-abc",
            "immutable_id": image_id, "retention_requested": True, "retained": True},
        "cleanup": {"status": "pass"},
    }

    self.assertEqual(("podman", "decent-keycloak-wallet-provider:lifecycle-abc", image_id),
        lifecycle.promotion_source_from_receipt(receipt))
    receipt["issue5_acceptance_gates"]["exact_missing_identity"] = "not_run"
    with self.assertRaisesRegex(ValueError, "acceptance gates"):
      lifecycle.promotion_source_from_receipt(receipt)

  def test_promotion_manifest_witness_binds_manifest_and_config_to_accepted_image_id(self):
    image_id = "sha256:" + "a" * 64
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": image_id},
        "layers": []}, separators=(",", ":")).encode()

    digest, config_digest = lifecycle.manifest_identity(manifest, image_id)

    self.assertEqual("sha256:" + hashlib.sha256(manifest).hexdigest(), digest)
    self.assertEqual(image_id, config_digest)
    altered = json.dumps({"schemaVersion": 2, "config": {"digest": "sha256:" + "b" * 64},
        "layers": []}, separators=(",", ":")).encode()
    with self.assertRaisesRegex(ValueError, "image identity"):
      lifecycle.manifest_identity(altered, image_id)

  def test_release_candidate_destination_rejects_credentials_and_non_rc_tags(self):
    valid = "docker://registry.example.invalid/team/provider:v1.0.0-rc.1"
    self.assertEqual(valid, lifecycle.validate_release_candidate_destination(valid))
    for invalid in (
        "docker://user@registry.example.invalid/team/provider:v1.0.0-rc.1",
        "docker://registry.example.invalid/team/provider:latest",
    ):
      with self.assertRaises(ValueError):
        lifecycle.validate_release_candidate_destination(invalid)

  def test_promotion_requires_explicit_publish_opt_in_before_reading_receipt(self):
    result = self.run_cli("promote", "--receipt", "missing.json", "--destination",
        "docker://registry.example.invalid/team/provider:v1.0.0-rc.1")

    self.assertNotEqual(0, result.returncode)
    self.assertIn("--allow-publish", result.stderr)

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
    self.assertEqual(lifecycle.ISSUE5_LIVE_MATRIX_PROFILE,
        steps["issue5-live-matrix"]["env"]["WALLET_IT_PROFILE"])
    self.assertIn("--allow-live", steps["issue5-live-matrix"]["requires"])
    self.assertIn("issue5-adversarial", steps)
    self.assertEqual("issue5-adversarial", steps["issue5-adversarial"]["env"]["WALLET_IT_PROFILE"])
    self.assertEqual("<run-built immutable ID>", steps["issue5-adversarial"]["env"]["WALLET_IT_IMAGE"])
    self.assertIn("--allow-live", steps["issue5-adversarial"]["requires"])


  def test_adversarial_gates_only_record_unavailable_for_two_complete_failed_closed_attempts(self):
    cases = {
        "malformed_result": "hostile-peer-malformed",
        "history_incomplete": "hostile-peer-history-incomplete",
        "ambiguous_registry_result": "hostile-peer-ambiguous",
        "mixed_legacy_rotated_head": "hostile-peer-mixed-head",
    }
    def attempt(label):
      return {
          "fixture_evidence": "test-only-hostile-peer",
          "fixture": label,
          "fixture_source_sha256": "a" * 64,
          "fixture_case_constants_sha256": "b" * 64,
          "direct_resolution": "unavailable",
          "provider_http": 503,
          "status_http": 200,
          "status_pending": True,
          "no_acceptance_or_callback": True,
          "no_authorization_code": True,
          "fixture_cli_key_observed": True,
          "fixture_provider_key_observed": True,
          "fixture_all_provider_peers_observed": True,
      }
    evidence = {"registry_matrix": {
        name: {"attempts": [attempt(label), attempt(label)]}
        for name, label in cases.items()
    }}

    statuses = lifecycle.issue5_adversarial_gate_statuses(evidence)
    self.assertEqual({name: "unavailable" for name in cases}, statuses)

    evidence["registry_matrix"]["malformed_result"]["attempts"][0]["direct_resolution"] = "not_found"
    evidence["registry_matrix"]["history_incomplete"]["attempts"][1]["provider_http"] = 200
    statuses = lifecycle.issue5_adversarial_gate_statuses(evidence)
    self.assertEqual("inconclusive", statuses["malformed_result"])
    self.assertEqual("inconclusive", statuses["history_incomplete"])
    self.assertEqual("unavailable", statuses["ambiguous_registry_result"])

  def test_live_matrix_gates_require_complete_two_attempt_receipts(self):
    current = lambda: {
        "direct_resolution": "resolved", "exact_readback": True,
        "provider_http": 202, "status_http": 200, "status_pending": False,
        "outcome": "current_accepted",
    }
    missing = lambda: {
        "direct_resolution": "not_found", "provider_http": 401,
        "status_http": 200, "status_pending": True,
        "no_acceptance_or_callback": True, "no_authorization_code": True,
        "provider_identity_log_read": True,
        "provider_identity_not_found_observed": True,
        "provider_identity_not_found_marker_count": 1,
        "outcome": "provider_not_found",
    }
    unavailable = lambda: {
        "direct_resolution": "unavailable", "provider_http": 503,
        "status_http": 200, "status_pending": True,
        "no_acceptance_or_callback": True, "no_authorization_code": True,
        "outcome": "registry_unavailable",
    }
    rotation = lambda sequence: {
        "direct_resolution": "resolved", "exact_readback": True,
        "provider_http": 202, "rotation_publish": "passed",
        "current_sequence": sequence, "stale_key_proof_http": 401,
        "current_key_proof_http": 202,
        "stale_transaction_remains_pending": True,
        "current_transaction_accepted": True,
        "independent_rotation_readback": True,
        "outcome": "current_accepted",
    }
    evidence = {
        "issue5_profile": {"stage": "complete"},
        "registry_matrix": {
            "current_identity": {"attempts": [current(), current()]},
            "missing_identity": {"attempts": [missing(), missing()]},
            "unavailable_registry": {"attempts": [unavailable(), unavailable()]},
            "rotation": {"attempts": [rotation(2), rotation(3)]},
        },
        "rotated_identity_case": {"local_mapping_persisted": True},
    }

    statuses = lifecycle.issue5_live_matrix_gate_statuses(evidence)
    self.assertEqual({
        "current_identity": "pass",
        "exact_missing_identity": "pass",
        "registry_unavailable": "pass",
        "valid_current_key_proof": "pass",
        "stale_key_denial": "pass",
        "owner_key_rotation": "pass",
        "independent_rotation_readback": "pass",
    }, statuses)

    evidence["registry_matrix"]["missing_identity"]["attempts"][1]["direct_resolution"] = "unavailable"
    self.assertEqual("fail", lifecycle.issue5_live_matrix_gate_statuses(evidence)["exact_missing_identity"])
    evidence["registry_matrix"]["rotation"]["attempts"][0].pop("independent_rotation_readback")
    self.assertEqual("inconclusive", lifecycle.issue5_live_matrix_gate_statuses(evidence)["independent_rotation_readback"])


if __name__ == "__main__":
  unittest.main()
