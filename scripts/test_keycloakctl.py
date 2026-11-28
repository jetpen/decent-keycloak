"""Offline contract tests through the executable, in isolated scratch repositories."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
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


class SourceManifestCaptureTest(unittest.TestCase):
  def test_ignored_build_input_is_captured_but_explicit_generated_paths_are_excluded(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-source-exclusions-") as temporary:
      root = Path(temporary)
      subprocess.run(["git", "init", "-q", str(root)], check=True)
      (root / ".gitignore").write_text(
          "ignored-build-input.bin\ntarget/\n.keycloakctl/\nscripts/__pycache__/\n"
          "container/__pycache__/\n.pytest_cache/\ncontainer/.cache/resolver-downloads/\n"
          "container/identity-src/\ncontainer/registry-src/\ncontainer/sources/\n",
          encoding="utf-8")
      (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
      subprocess.run(["git", "-C", str(root), "add", ".gitignore", "tracked.txt"], check=True)
      subprocess.run(["git", "-C", str(root), "-c", "user.email=test@example.invalid",
                      "-c", "user.name=Test", "commit", "-qm", "fixture"], check=True)
      ignored = root / "ignored-build-input.bin"
      ignored.write_bytes(b"captured even though git ignores me")
      ignored.chmod(0o640)
      for relative in ("target/image.tar", ".keycloakctl/state.json", "scripts/__pycache__/module.pyc",
                       "container/__pycache__/module.pyc", ".pytest_cache/cache",
                       "container/.cache/resolver-downloads/pkg", "container/identity-src/source",
                       "container/registry-src/source", "container/sources/source"):
        generated = root / relative
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_bytes(b"generated")

      manifest = json.loads(keycloakctl_cli.capture_source_manifest(root))
      entries = {entry["path"]: entry for entry in manifest["files"]}
      self.assertEqual({"path": "ignored-build-input.bin", "mode": "0640",
                        "sha256": sha256(b"captured even though git ignores me").hexdigest()},
                       entries["ignored-build-input.bin"])
      for relative in ("target/image.tar", ".keycloakctl/state.json", "scripts/__pycache__/module.pyc",
                       "container/__pycache__/module.pyc", ".pytest_cache/cache",
                       "container/.cache/resolver-downloads/pkg", "container/identity-src/source",
                       "container/registry-src/source", "container/sources/source"):
        self.assertNotIn(relative, entries)

  def test_internal_symlink_and_target_are_bound_and_mutations_change_manifest(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-source-symlink-") as temporary:
      root = Path(temporary)
      target = root / "source.txt"
      target.write_text("first target bytes\n", encoding="utf-8")
      link = root / "alias.txt"
      link.symlink_to("source.txt")
      subprocess.run(["git", "init", "-q", str(root)], check=True)
      subprocess.run(["git", "-C", str(root), "add", "source.txt", "alias.txt"], check=True)

      first = json.loads(keycloakctl_cli.capture_source_manifest(root))
      entries = {entry["path"]: entry for entry in first["files"]}
      self.assertEqual({"alias.txt", "source.txt"}, set(entries))
      self.assertEqual("symlink", entries["alias.txt"]["type"])
      self.assertEqual(format(link.lstat().st_mode & 0o7777, "04o"), entries["alias.txt"]["mode"])
      self.assertEqual("source.txt", entries["alias.txt"]["target"])
      self.assertEqual(sha256(b"source.txt").hexdigest(), entries["alias.txt"]["sha256"])
      self.assertEqual(sha256(b"first target bytes\n").hexdigest(), entries["source.txt"]["sha256"])

      target.write_text("changed target bytes\n", encoding="utf-8")
      self.assertNotEqual(first, json.loads(keycloakctl_cli.capture_source_manifest(root)))
      target.write_text("first target bytes\n", encoding="utf-8")
      link.unlink()
      link.symlink_to("./source.txt")
      self.assertNotEqual(first, json.loads(keycloakctl_cli.capture_source_manifest(root)))

  def test_escaping_and_special_symlink_targets_are_rejected(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-source-symlink-reject-") as temporary:
      root = Path(temporary)
      outside = Path(temporary).parent / (Path(temporary).name + "-outside")
      outside.write_text("outside", encoding="utf-8")
      self.addCleanup(outside.unlink, missing_ok=True)
      subprocess.run(["git", "init", "-q", str(root)], check=True)
      link = root / "escape.txt"
      link.symlink_to(outside)
      subprocess.run(["git", "-C", str(root), "add", "escape.txt"], check=True)
      with self.assertRaises(keycloakctl_cli.Rejected):
        keycloakctl_cli.capture_source_manifest(root)
      link.unlink()
      fifo = root / "fifo"
      os.mkfifo(fifo)
      link.symlink_to("fifo")
      subprocess.run(["git", "-C", str(root), "add", "-f", "fifo", "escape.txt"], check=False)
      with self.assertRaises(keycloakctl_cli.Rejected):
        keycloakctl_cli.capture_source_manifest(root)

  def test_self_loop_and_symlink_chain_targets_are_rejected(self):
    cases = {
        "self-loop": {"loop": "loop"},
        # Lexical traversal processes a-link before z-link, so the latter's
        # symlink target has already been handled when the chain is discovered.
        "chain": {"a-link": "target.txt", "z-link": "a-link"},
    }
    for name, links in cases.items():
      with self.subTest(name=name), tempfile.TemporaryDirectory(
          prefix="keycloakctl-source-symlink-chain-") as temporary:
        root = Path(temporary)
        (root / "target.txt").write_text("regular target\n", encoding="utf-8")
        for link, target in links.items():
          (root / link).symlink_to(target)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        with self.assertRaises(keycloakctl_cli.Rejected):
          keycloakctl_cli.capture_source_manifest(root)

  def test_leaf_open_is_nonblocking_during_source_capture(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-source-open-") as temporary:
      root = Path(temporary)
      (root / "source.txt").write_text("source bytes\n", encoding="utf-8")
      subprocess.run(["git", "init", "-q", str(root)], check=True)
      subprocess.run(["git", "-C", str(root), "add", "source.txt"], check=True)
      real_open = os.open
      leaf_open_flags = []

      def recording_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == "source.txt" and dir_fd is not None:
          leaf_open_flags.append(flags)
        if dir_fd is None:
          return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

      with patch.object(keycloakctl_cli.os, "open", side_effect=recording_open):
        manifest = keycloakctl_cli.capture_source_manifest(root)

      self.assertIn(b'"path":"source.txt"', manifest)
      self.assertEqual(1, len(leaf_open_flags))
      self.assertTrue(leaf_open_flags[0] & os.O_NONBLOCK)


class FullLocalOnlyTest(unittest.TestCase):
  def _full_artifact_fixture(self, root, config_raw=None, profile="dev"):
    schema_dir = root / "config/keycloakctl"
    schema_dir.mkdir(parents=True, exist_ok=True)
    for name in ("issue74-artifact.schema.json", "config.schema.json"):
      shutil.copy2(ROOT / "config/keycloakctl" / name, schema_dir / name)
    fixture = ArtifactValidationCliTest()
    fixture.setUp()
    self.addCleanup(fixture.doCleanups)
    config = {"version": 1, "profile": profile, "engine": "podman"}
    config_raw = ((json.dumps(config, indent=2) + "\n").encode("ascii")
                  if config_raw is None else config_raw)
    fixture.config_raw = config_raw
    fixture.config_path.write_bytes(config_raw)
    fixture.baseline["runtime_config"]["sha256"] = sha256(config_raw).hexdigest()
    fixture.baseline["case_inventory"]["sha256"] = sha256(fixture.projection_bytes()).hexdigest()
    fixture.write_artifacts()
    (root / "scripts").mkdir(exist_ok=True)
    for relative in ("keycloakctl", "scripts/keycloakctl_cli.py", "scripts/lifecycle.py"):
      path = root / relative
      if not path.exists():
        path.write_text(f"fixture:{relative}\\n", encoding="utf-8")
    return config, config_raw, fixture.baseline_path, fixture.projection_path

  def _run_full_with_artifacts(self, state, config_path, baseline_path, projection_path):
    args = ["full", "--profile", state["profile"], "--run-id", state["run_id"],
            "--config", str(config_path), "--baseline", str(baseline_path),
            "--projection", str(projection_path)]
    return keycloakctl_cli.main(args)

  def test_full_readiness_and_qualification_seal_real_local_intent(self):
    for profile in ("readiness", "qualification"):
      with self.subTest(profile=profile), tempfile.TemporaryDirectory(prefix="full-profile-local-") as temporary:
        root = Path(temporary)
        with patch.object(keycloakctl_cli, "ROOT", root):
          config, config_raw, baseline, projection = self._full_artifact_fixture(root, profile=profile)
          config_path = root / "runtime.json"
          config_path.write_bytes(config_raw)
          (root / ".gitignore").write_text("target/\\n", encoding="utf-8")
          subprocess.run(["git", "init", "-q", str(root)], check=True)
          subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
          subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
          source = root / "tracked-source.txt"
          source.write_text("local source\\n", encoding="utf-8")
          subprocess.run(["git", "-C", str(root), "add", ".gitignore", "tracked-source.txt"], check=True)
          subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
          events = []
          def fake_build(state, _config):
            events.append("build")
            run_id = state["run_id"]
            records = {name: {"version": 1, "run_id": run_id, "status": "verified",
                "image_id": "sha256:" + ("1" if name == "provider" else "2") * 64,
                "source_sha256": "c" * 64, "config_sha256": state["config_sha256"]}
                for name in ("provider", "rp-fixture")}
            receipt = {"version": 1, "run_id": run_id, "status": "complete", "images": records}
            with keycloakctl_cli.open_directory(("target", "keycloakctl", "runs", run_id)) as directory:
              for name, record in records.items():
                keycloakctl_cli.write_exclusive(directory, f"{name}.json", keycloakctl_cli.canonical_json(record))
              keycloakctl_cli.write_exclusive(directory, "build.json", keycloakctl_cli.canonical_json(receipt))
          def fake_test(state, _config):
            events.append("test")
            with keycloakctl_cli.open_directory(("target", "keycloakctl", "runs", state["run_id"])) as directory:
              bundle = keycloakctl_cli.read_build_bundle(state)
              receipt = {"version": 2, "run_id": state["run_id"], "status": "complete",
                  "build_sha256": bundle["digest"], "test_source_sha256": "a" * 64,
                  "config_sha256": state["config_sha256"],
                  "provider_image_id": bundle["records"]["provider"]["image_id"],
                  "steps": [{"name": name, "status": "pass"} for name in keycloakctl_cli.TEST_STEPS]}
              keycloakctl_cli.write_exclusive(directory, "test.json", keycloakctl_cli.canonical_json(receipt))
          with (patch.object(keycloakctl_cli, "perform_local_preflight", side_effect=lambda *_: events.append("local-preflight")),
                patch.object(keycloakctl_cli, "perform_build", side_effect=fake_build),
                patch.object(keycloakctl_cli, "perform_test", side_effect=fake_test),
                patch.object(keycloakctl_cli, "perform_preflight", side_effect=AssertionError("remote preflight reached")),
                redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors):
            result = keycloakctl_cli.main(["full", "--profile", profile, "--new-run", "--config", str(config_path),
                "--baseline", str(baseline), "--projection", str(projection)])
          self.assertEqual(0, result, errors.getvalue())
          self.assertEqual(["local-preflight", "build", "test"], events)
          self.assertIn("no remote operations performed", output.getvalue())
          run_id = output.getvalue().splitlines()[0]
          run_dir = root / "target/keycloakctl/runs" / run_id
          intent_raw = (run_dir / "run-intent.json").read_bytes()
          intent = json.loads(intent_raw)
          source_raw = (run_dir / "source-manifest.json").read_bytes()
          self.assertEqual("local-only", intent["scope"])
          self.assertEqual("verified", intent["status"])
          self.assertEqual(sha256(source_raw).hexdigest(), intent["source_manifest_sha256"])
          state_config_hash = sha256(config_raw).hexdigest()
          verified_build = keycloakctl_cli.read_build_bundle({"run_id": run_id, "config_sha256": state_config_hash})
          verified_test = keycloakctl_cli.read_test_receipt({"run_id": run_id, "config_sha256": state_config_hash}, verified_build)
          self.assertIsNotNone(verified_build)
          self.assertIsNotNone(verified_test)
          self.assertEqual(sha256(keycloakctl_cli.canonical_json(verified_build)).hexdigest(), intent["build_sha256"])
          self.assertEqual(sha256(keycloakctl_cli.canonical_json(verified_test)).hexdigest(), intent["test_receipt_sha256"])
          keycloakctl_cli.validate_persisted_full_intent(
              keycloakctl_cli.checked_run(type("Args", (), {"run_id": run_id, "config": str(config_path), "command": "full"})())[0],
              {"baseline_sha256": intent["baseline_sha256"], "projection_sha256": intent["projection_sha256"]})
          self.assertEqual(0o600, (run_dir / "run-intent.json").stat().st_mode & 0o777)

  def test_public_full_new_run_requires_artifacts_before_creating_run_state(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-full-required-artifacts-") as temporary:
      root = Path(temporary)
      config_path = root / "runtime.json"
      config_path.write_text(json.dumps({"version": 1, "profile": "dev", "engine": "podman"}) + "\n",
                            encoding="utf-8")
      with (patch.object(keycloakctl_cli, "ROOT", root),
            patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
                "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                               "engine": {"enum": ["podman", "docker"]}}}),
            redirect_stderr(io.StringIO()) as errors):
        with self.assertRaises(SystemExit) as rejected:
          keycloakctl_cli.main(["full", "--profile", "dev", "--new-run", "--config", str(config_path)])
      self.assertEqual(2, rejected.exception.code)
      self.assertIn("invalid arguments", errors.getvalue())
      self.assertFalse((root / "target/keycloakctl/runs").exists())
      self.assertFalse((root / "target/keycloakctl/reservations").exists())
      with redirect_stdout(io.StringIO()) as help_output:
        with self.assertRaises(SystemExit):
          keycloakctl_cli.make_parser().parse_args(["full", "--help"])
      self.assertIn("--baseline FILE", help_output.getvalue())
      self.assertIn("--projection FILE", help_output.getvalue())

  def test_public_full_new_run_rejects_bad_artifacts_before_reservation_or_local_phases(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-full-new-run-invalid-") as temporary:
      root = Path(temporary)
      with patch.object(keycloakctl_cli, "ROOT", root), \
           patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
               "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                              "engine": {"enum": ["podman", "docker"]}}}):
        config, config_raw, baseline_path, projection_path = self._full_artifact_fixture(root)
        config_path = root / "runtime.json"
        config_path.write_bytes(config_raw)
        def change_projection_without_updating_baseline():
          projection = json.loads(projection_path.read_text(encoding="utf-8"))
          projection["cases"]["LOGIN-01"]["expected_observations"] = ["different valid projection"]
          projection_path.write_text(json.dumps(projection, sort_keys=True, separators=(",", ":")),
                                     encoding="utf-8")
        cases = {
            "malformed": lambda: projection_path.write_bytes(b"{ malformed"),
            "cross-mismatched": change_projection_without_updating_baseline,
        }
        for name, mutate in cases.items():
          with self.subTest(name=name):
            # Each attempt gets an independent, empty state root.
            for child in ("target",):
              shutil.rmtree(root / child, ignore_errors=True)
            _, _, baseline_path, projection_path = self._full_artifact_fixture(root, config_raw)
            mutate()
            with (patch.object(keycloakctl_cli, "perform_local_preflight") as preflight,
                  patch.object(keycloakctl_cli, "perform_build") as build,
                  patch.object(keycloakctl_cli, "perform_test") as test,
                  redirect_stdout(io.StringIO()) as output,
                  redirect_stderr(io.StringIO()) as errors):
              result = keycloakctl_cli.main(["full", "--profile", "dev", "--new-run",
                  "--config", str(config_path), "--baseline", str(baseline_path),
                  "--projection", str(projection_path)])
            self.assertEqual(2, result)
            self.assertEqual("", output.getvalue())
            self.assertEqual("error: invalid artifacts or bindings\n", errors.getvalue())
            self.assertFalse((root / "target/keycloakctl/runs").exists())
            self.assertFalse((root / "target/keycloakctl/reservations").exists())
            preflight.assert_not_called()
            build.assert_not_called()
            test.assert_not_called()

  def test_public_full_resumes_after_source_manifest_write_before_run_intent(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-full-partial-seal-") as temporary:
      root = Path(temporary)
      with patch.object(keycloakctl_cli, "ROOT", root), \
           patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
               "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                              "engine": {"enum": ["podman", "docker"]}}}):
        config, config_raw, baseline_path, projection_path = self._full_artifact_fixture(root)
        config_path = root / "runtime.json"
        config_path.write_bytes(config_raw)
        (root / ".gitignore").write_text("target/\\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.email=test@example.invalid",
                        "-c", "user.name=Test", "add", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.email=test@example.invalid",
                        "-c", "user.name=Test", "commit", "-qm", "fixture"], check=True)
        write_exclusive = keycloakctl_cli.write_exclusive

        def interrupt_before_intent(directory, name, data):
          if name == "run-intent.json":
            raise OSError("simulated interruption before run-intent write")
          write_exclusive(directory, name, data)

        (root / "scripts").mkdir(exist_ok=True)
        for relative in ("keycloakctl", "scripts/keycloakctl_cli.py", "scripts/lifecycle.py"):
          (root / relative).write_text(f"fixture:{relative}\\n", encoding="utf-8")
        state = keycloakctl_cli.create_run(config, config_raw=config_raw)
        build = {"version": 1, "run_id": state["run_id"], "status": "complete",
                 "images": {"provider": {"image_id": "sha256:" + "1" * 64},
                            "rp-fixture": {"image_id": "sha256:" + "2" * 64}},
                 "receipt": {"version": 1, "run_id": state["run_id"], "status": "complete"},
                 "records": {"provider": {"image_id": "sha256:" + "1" * 64},
                             "rp-fixture": {"image_id": "sha256:" + "2" * 64}}}
        test = {"version": 1, "run_id": state["run_id"], "status": "complete",
                "test_source_sha256": "a" * 64}

        with (patch.object(keycloakctl_cli, "perform_local_preflight"),
              patch.object(keycloakctl_cli, "perform_build"),
              patch.object(keycloakctl_cli, "perform_test"),
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
              patch.object(keycloakctl_cli, "write_exclusive", side_effect=interrupt_before_intent),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as first_errors):
          first = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(2, first)
        self.assertIn("run-intent storage unavailable", first_errors.getvalue())
        run_dir = root / "target/keycloakctl/runs" / state["run_id"]
        manifest_path, intent_path = run_dir / "source-manifest.json", run_dir / "run-intent.json"
        manifest_before = manifest_path.read_bytes()
        self.assertFalse(intent_path.exists())
        manifest_path.chmod(0o644)
        with (patch.object(keycloakctl_cli, "perform_local_preflight") as preflight,
              patch.object(keycloakctl_cli, "perform_build") as build_phase,
              patch.object(keycloakctl_cli, "perform_test") as test_phase,
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as mode_errors):
          mode_rejected = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(2, mode_rejected)
        self.assertIn("run-intent readback conflict", mode_errors.getvalue())
        preflight.assert_not_called()
        build_phase.assert_not_called()
        test_phase.assert_not_called()
        self.assertEqual(manifest_before, manifest_path.read_bytes())
        self.assertFalse(intent_path.exists())
        manifest_path.chmod(0o600)

        with (patch.object(keycloakctl_cli, "perform_local_preflight") as preflight,
              patch.object(keycloakctl_cli, "perform_build") as build_phase,
              patch.object(keycloakctl_cli, "perform_test") as test_phase,
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
              redirect_stdout(io.StringIO()) as output,
              redirect_stderr(io.StringIO()) as errors):
          resumed = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(0, resumed, errors.getvalue())
        self.assertIn("full verified; local run-intent sealed", output.getvalue())
        preflight.assert_called_once_with(config, "dev")
        build_phase.assert_called_once_with(state, config)
        test_phase.assert_called_once_with(state, config)
        self.assertEqual(manifest_before, manifest_path.read_bytes())
        intent = json.loads(intent_path.read_bytes())
        self.assertEqual(sha256(manifest_before).hexdigest(), intent["source_manifest_sha256"])
        self.assertEqual(sha256(keycloakctl_cli.canonical_json(build)).hexdigest(), intent["build_sha256"])
        self.assertEqual(test["test_source_sha256"], intent["test_source_sha256"])
        self.assertEqual(build["records"]["provider"]["image_id"], intent["provider_image_id"])
        self.assertEqual(build["records"]["rp-fixture"]["image_id"], intent["rp_fixture_image_id"])
        self.assertEqual(sha256(keycloakctl_cli.canonical_json(build["receipt"])).hexdigest(),
                         intent["build_receipt_sha256"])
        self.assertEqual(sha256(keycloakctl_cli.canonical_json(test)).hexdigest(), intent["test_receipt_sha256"])
        source_files = json.loads(manifest_before)["files"]
        identity_paths = {"keycloakctl", "scripts/keycloakctl_cli.py", "scripts/lifecycle.py"}
        identity = {entry["path"]: entry for entry in source_files if entry["path"] in identity_paths}
        self.assertEqual(identity_paths, set(identity))
        self.assertEqual(sha256(keycloakctl_cli.canonical_json(identity)).hexdigest(), intent["cli_helper_sha256"])

        intent_before = intent_path.read_bytes()
        with (patch.object(keycloakctl_cli, "perform_local_preflight") as preflight,
              patch.object(keycloakctl_cli, "perform_build") as build_phase,
              patch.object(keycloakctl_cli, "perform_test") as test_phase,
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as resume_errors):
          resumed_again = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(0, resumed_again, resume_errors.getvalue())
        preflight.assert_called_once_with(config, "dev")
        build_phase.assert_called_once_with(state, config)
        test_phase.assert_called_once_with(state, config)
        self.assertEqual(intent_before, intent_path.read_bytes())
        self.assertEqual(manifest_before, manifest_path.read_bytes())
        intent_path.chmod(0o644)
        with (patch.object(keycloakctl_cli, "perform_local_preflight") as preflight,
              patch.object(keycloakctl_cli, "perform_build") as build_phase,
              patch.object(keycloakctl_cli, "perform_test") as test_phase,
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as mode_errors):
          mode_rejected = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(2, mode_rejected)
        self.assertIn("run-intent readback conflict", mode_errors.getvalue())
        preflight.assert_not_called()
        build_phase.assert_not_called()
        test_phase.assert_not_called()
        self.assertEqual(intent_before, intent_path.read_bytes())

  def test_public_full_binds_exact_artifact_bytes_into_local_intent(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-full-artifact-bind-") as temporary:
      root = Path(temporary)
      with patch.object(keycloakctl_cli, "ROOT", root), \
           patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
               "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                              "engine": {"enum": ["podman", "docker"]}}}):
        config, config_raw, baseline_path, projection_path = self._full_artifact_fixture(root)
        config_path = root / "runtime.json"
        config_path.write_bytes(config_raw)
        (root / ".gitignore").write_text("target/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.email=test@example.invalid",
                        "-c", "user.name=Test", "commit", "-qm", "fixture"], check=True)
        state = keycloakctl_cli.create_run(config, config_raw=config_raw)
        build = {"version": 1, "run_id": state["run_id"], "status": "complete",
                 "images": {"provider": {"image_id": "sha256:" + "1" * 64},
                            "rp-fixture": {"image_id": "sha256:" + "2" * 64}},
                 "receipt": {"version": 1, "run_id": state["run_id"], "status": "complete"},
                 "records": {"provider": {"image_id": "sha256:" + "1" * 64},
                             "rp-fixture": {"image_id": "sha256:" + "2" * 64}}}
        test = {"version": 1, "run_id": state["run_id"], "status": "complete",
                "test_source_sha256": "a" * 64}
        baseline_raw = baseline_path.read_bytes()
        projection_raw = projection_path.read_bytes()
        with (patch.object(keycloakctl_cli, "perform_local_preflight"),
              patch.object(keycloakctl_cli, "perform_build"),
              patch.object(keycloakctl_cli, "perform_test"),
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors):
          result = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(0, result, errors.getvalue())
        run_dir = root / "target/keycloakctl/runs" / state["run_id"]
        intent_raw = (run_dir / "run-intent.json").read_bytes()
        intent = json.loads(intent_raw)
        self.assertEqual(sha256(config_raw).hexdigest(), intent["config_sha256"])
        self.assertEqual(sha256(baseline_raw).hexdigest(), intent["baseline_sha256"])
        self.assertEqual(sha256(projection_raw).hexdigest(), intent["projection_sha256"])
        self.assertEqual("local-only", intent["scope"])
        self.assertEqual("verified", intent["status"])
        for forbidden in (str(baseline_path), str(projection_path), "owner_approval", "approved_by",
                          "authorization", "readiness", "live"):
          self.assertNotIn(forbidden, intent_raw.decode("utf-8"))
        self.assertNotIn(baseline_raw, intent_raw)
        self.assertNotIn(projection_raw, intent_raw)

  def test_public_full_rejects_cross_mismatched_artifacts_before_local_phases(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-full-artifact-reject-") as temporary:
      root = Path(temporary)
      with patch.object(keycloakctl_cli, "ROOT", root), \
           patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
               "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                              "engine": {"enum": ["podman", "docker"]}}}):
        config, config_raw, baseline_path, projection_path = self._full_artifact_fixture(root)
        config_path = root / "runtime.json"
        config_path.write_bytes(config_raw)
        state = keycloakctl_cli.create_run(config, config_raw=config_raw)
        projection_path.write_bytes(projection_path.read_bytes() + b" ")
        with (patch.object(keycloakctl_cli, "perform_local_preflight") as preflight,
              patch.object(keycloakctl_cli, "perform_build") as build,
              patch.object(keycloakctl_cli, "perform_test") as test,
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors):
          result = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(2, result)
        self.assertIn("invalid artifacts or bindings", errors.getvalue())
        preflight.assert_not_called()
        build.assert_not_called()
        test.assert_not_called()
        run_dir = root / "target/keycloakctl/runs" / state["run_id"]
        self.assertFalse((run_dir / "run-intent.json").exists())

  def test_public_full_rejects_changed_valid_artifacts_without_overwriting_sealed_state(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-full-artifact-conflict-") as temporary:
      root = Path(temporary)
      with patch.object(keycloakctl_cli, "ROOT", root), \
           patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
               "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                              "engine": {"enum": ["podman", "docker"]}}}):
        config, config_raw, baseline_path, projection_path = self._full_artifact_fixture(root)
        config_path = root / "runtime.json"
        config_path.write_bytes(config_raw)
        (root / ".gitignore").write_text("target/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.email=test@example.invalid",
                        "-c", "user.name=Test", "commit", "-qm", "fixture"], check=True)
        state = keycloakctl_cli.create_run(config, config_raw=config_raw)
        build_record = {"version": 1, "run_id": state["run_id"], "status": "complete",
                        "images": {"provider": {"image_id": "sha256:" + "1" * 64},
                            "rp-fixture": {"image_id": "sha256:" + "2" * 64}},
                 "receipt": {"version": 1, "run_id": state["run_id"], "status": "complete"},
                 "records": {"provider": {"image_id": "sha256:" + "1" * 64},
                             "rp-fixture": {"image_id": "sha256:" + "2" * 64}}}
        test_record = {"version": 1, "run_id": state["run_id"], "status": "complete",
                       "test_source_sha256": "a" * 64}
        with (patch.object(keycloakctl_cli, "perform_local_preflight"),
              patch.object(keycloakctl_cli, "perform_build"),
              patch.object(keycloakctl_cli, "perform_test"),
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build_record),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test_record),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as first_errors):
          first = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(0, first, first_errors.getvalue())
        run_dir = root / "target/keycloakctl/runs" / state["run_id"]
        intent_path = run_dir / "run-intent.json"
        manifest_path = run_dir / "source-manifest.json"
        prior_intent, prior_manifest = intent_path.read_bytes(), manifest_path.read_bytes()
        baseline_original = baseline_path.read_bytes()
        projection_original = projection_path.read_bytes()
        changed = json.loads(projection_original)
        changed["cases"]["LOGIN-01"]["expected_observations"] = ["different but schema-valid projection"]
        projection_raw = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
        projection_path.write_bytes(projection_raw)
        baseline = json.loads(baseline_original)
        baseline["case_inventory"]["sha256"] = sha256(projection_raw).hexdigest()
        baseline_path.write_text(json.dumps(baseline) + "\n", encoding="utf-8")
        with (patch.object(keycloakctl_cli, "perform_local_preflight") as preflight,
              patch.object(keycloakctl_cli, "perform_build") as build,
              patch.object(keycloakctl_cli, "perform_test") as test,
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build_record),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test_record),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors):
          result = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(2, result)
        self.assertIn("run-intent readback conflict", errors.getvalue())
        preflight.assert_not_called()
        build.assert_not_called()
        test.assert_not_called()
        self.assertEqual(prior_intent, intent_path.read_bytes())
        self.assertEqual(prior_manifest, manifest_path.read_bytes())

        baseline_path.write_bytes(baseline_original)
        projection_path.write_bytes(projection_original)
        (root / "tracked-source.txt").write_text("changed source after sealing\\n", encoding="utf-8")
        with (patch.object(keycloakctl_cli, "perform_local_preflight") as preflight,
              patch.object(keycloakctl_cli, "perform_build") as build,
              patch.object(keycloakctl_cli, "perform_test") as test,
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build_record),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test_record),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors):
          result = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
        self.assertEqual(2, result)
        self.assertIn("run-intent readback conflict", errors.getvalue())
        preflight.assert_not_called()
        build.assert_not_called()
        test.assert_not_called()
        self.assertEqual(prior_intent, intent_path.read_bytes())
        self.assertEqual(prior_manifest, manifest_path.read_bytes())

  def test_public_full_rejects_tampered_sealed_hashes_before_local_phases(self):
    fields = ("build_sha256", "test_source_sha256", "cli_helper_sha256", "build_receipt_sha256",
              "test_receipt_sha256", "provider_image_id", "rp_fixture_image_id")
    for field in fields:
      with self.subTest(field=field), tempfile.TemporaryDirectory(
          prefix="keycloakctl-full-intent-hash-") as temporary:
        root = Path(temporary)
        with patch.object(keycloakctl_cli, "ROOT", root), \
             patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
                 "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                                "engine": {"enum": ["podman", "docker"]}}}):
          config, config_raw, baseline_path, projection_path = self._full_artifact_fixture(root)
          config_path = root / "runtime.json"
          config_path.write_bytes(config_raw)
          (root / ".gitignore").write_text("target/\n", encoding="utf-8")
          subprocess.run(["git", "init", "-q", str(root)], check=True)
          subprocess.run(["git", "-C", str(root), "add", ".gitignore"], check=True)
          subprocess.run(["git", "-C", str(root), "-c", "user.email=test@example.invalid",
                          "-c", "user.name=Test", "commit", "-qm", "fixture"], check=True)
          state = keycloakctl_cli.create_run(config, config_raw=config_raw)
          build = {"version": 1, "run_id": state["run_id"], "status": "complete",
                   "images": {"provider": {"image_id": "sha256:" + "1" * 64},
                            "rp-fixture": {"image_id": "sha256:" + "2" * 64}},
                 "receipt": {"version": 1, "run_id": state["run_id"], "status": "complete"},
                 "records": {"provider": {"image_id": "sha256:" + "1" * 64},
                             "rp-fixture": {"image_id": "sha256:" + "2" * 64}}}
          test = {"version": 1, "run_id": state["run_id"], "status": "complete",
                  "test_source_sha256": "a" * 64}
          with (patch.object(keycloakctl_cli, "perform_local_preflight"),
                patch.object(keycloakctl_cli, "perform_build"),
                patch.object(keycloakctl_cli, "perform_test"),
                patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
                patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as first_errors):
            first = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
          self.assertEqual(0, first, first_errors.getvalue())

          run_dir = root / "target/keycloakctl/runs" / state["run_id"]
          intent_path, manifest_path = run_dir / "run-intent.json", run_dir / "source-manifest.json"
          original_intent = intent_path.read_bytes()
          manifest_before = manifest_path.read_bytes()
          malformed = "not-a-sha256"
          different_valid = ("sha256:" + "b" * 64 if field.endswith("image_id") else "b" * 64)
          for tampered_value in (malformed, different_valid):
            with self.subTest(field=field, value=tampered_value):
              intent = json.loads(original_intent)
              intent[field] = tampered_value
              if tampered_value == different_valid:
                pattern = r"\Asha256:[0-9a-f]{64}\Z" if field.endswith("image_id") else r"\A[0-9a-f]{64}\Z"
                self.assertRegex(tampered_value, pattern)
                self.assertNotEqual(original_intent, keycloakctl_cli.canonical_json(intent))
              tampered_intent = keycloakctl_cli.canonical_json(intent)
              intent_path.write_bytes(tampered_intent)
              with (patch.object(keycloakctl_cli, "perform_local_preflight") as preflight,
                    patch.object(keycloakctl_cli, "perform_build") as build_phase,
                    patch.object(keycloakctl_cli, "perform_test") as test_phase,
                    patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
                    patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors):
                result = self._run_full_with_artifacts(state, config_path, baseline_path, projection_path)
              self.assertEqual(2, result)
              self.assertIn("run-intent readback conflict", errors.getvalue())
              preflight.assert_not_called()
              build_phase.assert_not_called()
              test_phase.assert_not_called()
              self.assertEqual(tampered_intent, intent_path.read_bytes())
              self.assertEqual(manifest_before, manifest_path.read_bytes())

  def test_public_full_new_run_accepts_exact_pretty_config_bytes(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-full-raw-config-") as temporary:
      root = Path(temporary)
      with patch.object(keycloakctl_cli, "ROOT", root), \
           patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
               "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                              "engine": {"enum": ["podman", "docker"]}}}):
        config = {"version": 1, "profile": "dev", "engine": "podman"}
        config_raw = (json.dumps(config, indent=2) + "\n").encode("ascii")
        config_path = root / "config.json"
        config_path.write_bytes(config_raw)
        _, _, baseline_path, projection_path = self._full_artifact_fixture(root, config_raw)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        (root / ".gitignore").write_text("target/\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
        build = {"version": 1, "run_id": "", "status": "complete",
                 "images": {"provider": {"image_id": "sha256:" + "1" * 64},
                            "rp-fixture": {"image_id": "sha256:" + "2" * 64}},
                 "receipt": {"version": 1, "run_id": "", "status": "complete"},
                 "records": {"provider": {"image_id": "sha256:" + "1" * 64},
                             "rp-fixture": {"image_id": "sha256:" + "2" * 64}}}
        test = {"version": 1, "run_id": "", "status": "complete",
                "test_source_sha256": "a" * 64}
        with (patch.object(keycloakctl_cli, "perform_local_preflight"),
              patch.object(keycloakctl_cli, "perform_build"),
              patch.object(keycloakctl_cli, "perform_test"),
              patch.object(keycloakctl_cli, "read_build_bundle", side_effect=lambda state: {
                  **build, "run_id": state["run_id"]}),
              patch.object(keycloakctl_cli, "read_test_receipt", side_effect=lambda state, _bundle: {
                  **test, "run_id": state["run_id"]}),
              redirect_stdout(io.StringIO()) as output,
              redirect_stderr(io.StringIO()) as errors):
          result = keycloakctl_cli.main(["full", "--profile", "dev", "--new-run",
                                         "--config", str(config_path),
                                         "--baseline", str(baseline_path),
                                         "--projection", str(projection_path)])
        self.assertEqual(0, result, errors.getvalue())
        run_id = output.getvalue().splitlines()[0]
        self.assertRegex(run_id, r"\A[0-9a-f]{32}\Z")
        with keycloakctl_cli.open_directory(("target", "keycloakctl", "runs", run_id)) as directory:
          manifest = keycloakctl_cli.parse_json(keycloakctl_cli.read_regular("manifest.json", dir_fd=directory))
        self.assertEqual(sha256(config_raw).hexdigest(), manifest["config_sha256"])

  def test_public_full_cli_runs_local_steps_and_seals_intent_without_live_flag(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-full-local-") as temporary:
      root = Path(temporary)
      with patch.object(keycloakctl_cli, "ROOT", root), \
           patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
               "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                              "engine": {"enum": ["podman", "docker"]}}}):
        config = {"version": 1, "profile": "dev", "engine": "podman"}
        config_path = root / "config.json"
        config_raw = keycloakctl_cli.canonical_json(config)
        config_path.write_bytes(config_raw)
        _, _, baseline_path, projection_path = self._full_artifact_fixture(root, config_raw)
        (root / ".gitignore").write_text("target/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        tracked = root / "tracked-source.txt"
        tracked.write_text("committed source\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "tracked-source.txt"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
        tracked.write_text("dirty tracked source\n", encoding="utf-8")
        untracked = root / "untracked-build-input.bin"
        untracked.write_bytes(b"build input sentinel bytes")
        state = keycloakctl_cli.create_run(config)
        build = {"version": 1, "run_id": state["run_id"], "status": "complete",
                 "images": {"provider": {"image_id": "sha256:" + "1" * 64},
                            "rp-fixture": {"image_id": "sha256:" + "2" * 64}},
                 "receipt": {"version": 1, "run_id": state["run_id"], "status": "complete"},
                 "records": {"provider": {"image_id": "sha256:" + "1" * 64},
                             "rp-fixture": {"image_id": "sha256:" + "2" * 64}}}
        test = {"version": 1, "run_id": state["run_id"], "status": "complete",
                "test_source_sha256": "a" * 64}
        calls = []
        actual_validator = keycloakctl_cli.validate_full_intent_input_selection
        with (patch.object(keycloakctl_cli, "validate_full_intent_input_selection",
                           side_effect=lambda *a, **kw: (calls.append("validator"), actual_validator(*a, **kw))[1]),
              patch.object(keycloakctl_cli, "perform_local_preflight", side_effect=lambda *a: calls.append("preflight")),
              patch.object(keycloakctl_cli, "perform_build", side_effect=lambda *a: calls.append("build")),
              patch.object(keycloakctl_cli, "perform_test", side_effect=lambda *a: calls.append("test")),
              patch.object(keycloakctl_cli, "perform_preflight", side_effect=AssertionError("remote preflight reached")),
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
              patch.object(keycloakctl_cli, "attempt_phase", side_effect=AssertionError("phase dispatcher used")),
              redirect_stdout(io.StringIO()) as output):
          result = keycloakctl_cli.main(["full", "--profile", "dev", "--run-id", state["run_id"],
                                         "--config", str(config_path),
                                         "--baseline", str(baseline_path),
                                         "--projection", str(projection_path)])
        self.assertEqual(0, result)
        self.assertEqual(["validator", "preflight", "build", "test"], calls)
        self.assertIn("no remote operations performed", output.getvalue())
        with keycloakctl_cli.open_directory(("target", "keycloakctl", "runs", state["run_id"])) as run_directory:
          receipt = keycloakctl_cli.parse_json(keycloakctl_cli.read_regular("run-intent.json", dir_fd=run_directory))
        self.assertEqual("local-only", receipt["scope"])
        self.assertEqual("verified", receipt["status"])
        self.assertEqual(sha256(keycloakctl_cli.canonical_json(build)).hexdigest(), receipt["build_sha256"])
        self.assertEqual(test["test_source_sha256"], receipt["test_source_sha256"])
        self.assertEqual(9, receipt["source_manifest_count"])
        with keycloakctl_cli.open_directory(("target", "keycloakctl", "runs", state["run_id"])) as run_directory:
          source_raw = keycloakctl_cli.read_regular("source-manifest.json", dir_fd=run_directory)
          source = keycloakctl_cli.parse_json(source_raw)
        self.assertEqual(receipt["source_manifest_sha256"], sha256(source_raw).hexdigest())
        files = {entry["path"]: entry for entry in source["files"]}
        self.assertEqual({".gitignore", "tracked-source.txt", "untracked-build-input.bin", "config.json",
                          "keycloakctl", "scripts/keycloakctl_cli.py", "scripts/lifecycle.py",
                          "config/keycloakctl/config.schema.json",
                          "config/keycloakctl/issue74-artifact.schema.json"}, set(files))
        self.assertEqual("0644", files["tracked-source.txt"]["mode"])
        self.assertEqual(sha256(b"dirty tracked source\n").hexdigest(), files["tracked-source.txt"]["sha256"])
        self.assertEqual(sha256(b"build input sentinel bytes").hexdigest(), files["untracked-build-input.bin"]["sha256"])
        self.assertNotIn(b"build input sentinel bytes", source_raw)
        self.assertNotIn(b"dirty tracked source", source_raw)
        self.assertEqual(0o600, (root / "target/keycloakctl/runs" / state["run_id"] / "source-manifest.json").stat().st_mode & 0o777)
        (root / "target/keycloakctl/runs/generated-output.txt").write_text("generated", encoding="utf-8")
        self.assertNotIn("target/keycloakctl/runs/generated-output.txt", files)
        intent_path = root / "target/keycloakctl/runs" / state["run_id"] / "run-intent.json"
        intent_raw = intent_path.read_bytes()
        manifest_path = root / "target/keycloakctl/runs" / state["run_id"] / "source-manifest.json"
        manifest_path.write_bytes(b"{}\\n")
        with (patch.object(keycloakctl_cli, "perform_local_preflight"),
              patch.object(keycloakctl_cli, "perform_build"),
              patch.object(keycloakctl_cli, "perform_test"),
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as conflict_errors):
          conflict_result = keycloakctl_cli.main(["full", "--profile", "dev", "--run-id", state["run_id"],
                                                  "--config", str(config_path),
                                                  "--baseline", str(baseline_path),
                                                  "--projection", str(projection_path)])
        self.assertEqual(2, conflict_result)
        self.assertIn("run-intent readback conflict", conflict_errors.getvalue())
        self.assertEqual(b"{}\\n", manifest_path.read_bytes())
        self.assertEqual(intent_raw, intent_path.read_bytes())
        with self.assertRaises(SystemExit):
          keycloakctl_cli.main(["full", "--profile", "readiness", "--new-run"])
        with self.assertRaises(SystemExit):
          keycloakctl_cli.main(["full", "--profile", "dev", "--run-id", state["run_id"], "--allow-live"])

  def test_public_full_rejects_tracked_and_untracked_changes_during_local_phases(self):
    with tempfile.TemporaryDirectory(prefix="keycloakctl-full-source-change-") as temporary:
      root = Path(temporary)
      with patch.object(keycloakctl_cli, "ROOT", root), \
           patch.object(keycloakctl_cli, "config_schema", return_value={"required": ["version", "profile"],
               "properties": {"version": {"const": 1}, "profile": {"enum": ["dev", "ci"]},
                              "engine": {"enum": ["podman", "docker"]}}}):
        (root / ".gitignore").write_text("target/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        tracked = root / "tracked.txt"
        tracked.write_text("stable\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", ".gitignore", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
        config = {"version": 1, "profile": "dev", "engine": "podman"}
        config_path = root / "config.json"
        config_raw = keycloakctl_cli.canonical_json(config)
        config_path.write_bytes(config_raw)
        _, _, baseline_path, projection_path = self._full_artifact_fixture(root, config_raw)
        state = keycloakctl_cli.create_run(config)
        untracked = root / "input.txt"
        untracked.write_text("before\n", encoding="utf-8")
        build = {"version": 1, "run_id": state["run_id"], "status": "complete",
                 "images": {"provider": {"image_id": "sha256:" + "1" * 64},
                            "rp-fixture": {"image_id": "sha256:" + "2" * 64}},
                 "receipt": {"version": 1, "run_id": state["run_id"], "status": "complete"},
                 "records": {"provider": {"image_id": "sha256:" + "1" * 64},
                             "rp-fixture": {"image_id": "sha256:" + "2" * 64}}}
        test = {"version": 1, "run_id": state["run_id"], "status": "complete",
                "test_source_sha256": "a" * 64}
        def mutate_inputs(*_args):
          tracked.write_text("changed\n", encoding="utf-8")
          untracked.write_text("after\n", encoding="utf-8")
        with (patch.object(keycloakctl_cli, "perform_local_preflight"),
              patch.object(keycloakctl_cli, "perform_build"),
              patch.object(keycloakctl_cli, "perform_test", side_effect=mutate_inputs),
              patch.object(keycloakctl_cli, "read_build_bundle", return_value=build),
              patch.object(keycloakctl_cli, "read_test_receipt", return_value=test),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors):
          result = keycloakctl_cli.main(["full", "--profile", "dev", "--run-id", state["run_id"],
                                         "--config", str(config_path),
                                         "--baseline", str(baseline_path),
                                         "--projection", str(projection_path)])
        self.assertEqual(2, result)
        self.assertIn("source inputs changed during full run", errors.getvalue())
        run_dir = root / "target/keycloakctl/runs" / state["run_id"]
        self.assertFalse((run_dir / "source-manifest.json").exists())
        self.assertFalse((run_dir / "run-intent.json").exists())


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

  def test_acceptance_entrypoint_records_preflight_failure_without_legacy_lifecycle_dispatch(self):
    marker = self.cwd / "lifecycle-run-invoked"
    lifecycle_script = self.repo / "scripts/lifecycle.py"
    lifecycle_script.write_text("\n".join((
        "from pathlib import Path",
        "def fingerprint_source(include_build_artifacts=False): return {}",
        "def local_source_provenance(root=None): return {'source_revision': '0' * 40, 'worktree_clean': True, 'worktree_diff_sha256': '0' * 64, 'worktree_untracked_file_count': 0}",
        "def run_python_tests(): return 0",
        "def verify_surefire(): return 0",
        "def verify_provider(): return 0",
        "def _image_inventory(engine): return set()",
        "def _cleanup_owned_images(engine, baseline_ids, run_id, **kwargs): return {'status': 'pass', 'inconclusive_image_count': 0}",
        "if __name__ == '__main__':",
        f"  Path({str(marker)!r}).write_text(' '.join(__import__('sys').argv[1:]))",
        "  raise SystemExit(0)",
        "")), encoding="utf-8")
    self.install_fixture_test()
    self.write_java_acceptance_artifacts(self.repo)

    result = self.cli("acceptance", "--profile", "offline")

    self.assertEqual(2, result.returncode)
    self.assertIn("acceptance stage failed; receipt:", result.stderr)
    self.assertFalse(marker.exists(), "keycloakctl acceptance must own stages instead of delegating lifecycle profile run")
    receipt_path = Path(result.stderr.strip().split("receipt: ", 1)[1])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("offline", receipt["profile"])
    self.assertEqual("failed", receipt["status"])
    self.assertEqual([("preflight", "fail"), ("cleanup", "not_run")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])

  def test_acceptance_offline_profile_keeps_built_images_and_skips_cleanup(self):
    root = self.cwd / "acceptance-profile-root"
    root.mkdir()
    source = {"tree_sha256": "a" * 64, "source_revision": "b" * 40}
    events = []

    def record_fake_build(state, config):
      records = {}
      with keycloakctl_cli.open_directory((*keycloakctl_cli.RUNS, state["run_id"])) as directory:
        for name, image_id in (("provider", "sha256:" + "1" * 64),
                               ("rp-fixture", "sha256:" + "2" * 64)):
          record = {"version": 1, "run_id": state["run_id"], "status": "verified",
                    "image_id": image_id, "source_sha256": "a" * 64,
                    "config_sha256": state["config_sha256"]}
          keycloakctl_cli.write_exclusive(directory, f"{name}.json", keycloakctl_cli.canonical_json(record))
          records[name] = record
        bundle = {"version": 1, "run_id": state["run_id"], "status": "complete", "images": records}
        keycloakctl_cli.write_exclusive(directory, "build.json", keycloakctl_cli.canonical_json(bundle))
      events.append("provider-image-build")
    with patch.object(keycloakctl_cli, "ROOT", root), \
         patch.object(keycloakctl_cli, "acceptance_source_provenance", return_value=source), \
         patch.object(keycloakctl_cli, "perform_local_preflight", side_effect=lambda *_: events.append("preflight")), \
         patch.object(lifecycle, "_image_inventory", return_value={"baseline"}), \
         patch.object(keycloakctl_cli, "surefire_report_snapshot", return_value={}), \
         patch.object(keycloakctl_cli, "run_acceptance_command", side_effect=lambda name, *_: events.append(name) or 0), \
         patch.object(keycloakctl_cli, "verify_surefire_reports", return_value=0), \
         patch.object(keycloakctl_cli, "verify_provider_registration", return_value=0), \
         patch.object(keycloakctl_cli, "perform_build", side_effect=record_fake_build), \
         patch.object(keycloakctl_cli, "perform_test", side_effect=lambda *_: events.append("image-smoke")), \
         patch.object(keycloakctl_cli, "verify_diff_check", return_value=0), \
         patch.object(lifecycle, "_cleanup_owned_images") as cleanup:
      result = keycloakctl_cli.run_acceptance("offline")
      receipt_path = next((root / "target/keycloakctl/acceptance").glob("*.json"))
      receipt = json.loads(receipt_path.read_text())
      state = keycloakctl_cli.read_run(receipt["run_id"])
      bundle = keycloakctl_cli.read_build_bundle(state)
    self.assertEqual(0, result)
    self.assertEqual("complete", receipt["status"])
    self.assertEqual(source, receipt["source"])
    self.assertEqual(["preflight", "java-tests", "surefire", "provider-service-registration",
                      "python-tests", "python-compile", "provider-image-build",
                      "rp-fixture-image-build", "image-smoke", "rp-fixture-smoke",
                      "diff-check", "cleanup"], [stage["name"] for stage in receipt["stages"]])
    self.assertEqual("not_run", receipt["stages"][-1]["status"])
    self.assertEqual(["pass"] * 11 + ["not_run"], [stage["status"] for stage in receipt["stages"]])
    self.assertEqual({"provider", "rp-fixture"}, set(bundle["records"]))
    self.assertEqual({"sha256:" + "1" * 64, "sha256:" + "2" * 64},
                     {record["image_id"] for record in bundle["records"].values()})
    self.assertEqual(["preflight", "maven", "python-tests", "python-compile",
                      "provider-image-build", "image-smoke"], events)
    cleanup.assert_not_called()

  def test_acceptance_stage_failures_are_durable_and_cleanup_remains_explicit(self):
    root = self.cwd / "acceptance-failure-root"
    root.mkdir()
    with patch.object(keycloakctl_cli, "ROOT", root), \
         patch.object(keycloakctl_cli, "acceptance_source_provenance", return_value={"tree_sha256": "d" * 64}), \
         patch.object(keycloakctl_cli, "perform_local_preflight"), \
         patch.object(lifecycle, "_image_inventory", return_value={"base-id"}), \
         patch.object(keycloakctl_cli, "surefire_report_snapshot", return_value={}), \
         patch.object(keycloakctl_cli, "run_acceptance_command", return_value=0), \
         patch.object(keycloakctl_cli, "verify_surefire_reports", return_value=0), \
         patch.object(keycloakctl_cli, "verify_provider_registration", return_value=0), \
         patch.object(keycloakctl_cli, "perform_build"), \
         patch.object(keycloakctl_cli, "perform_test", side_effect=RuntimeError("stage failure")), \
         patch.object(keycloakctl_cli, "read_build_bundle", return_value=None), \
         patch.object(lifecycle, "_cleanup_owned_images") as cleanup:
      result = keycloakctl_cli.run_acceptance("offline")
    self.assertEqual(2, result)
    receipt_path = next((root / "target/keycloakctl/acceptance").glob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("failed", receipt["status"])
    self.assertEqual([("preflight", "pass"), ("java-tests", "pass"), ("surefire", "pass"),
                      ("provider-service-registration", "pass"), ("python-tests", "pass"),
                      ("python-compile", "pass"), ("provider-image-build", "pass"),
                      ("rp-fixture-image-build", "pass"), ("image-smoke", "fail"),
                      ("cleanup", "not_run")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])
    cleanup.assert_not_called()

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

  def test_acceptance_python_stage_uses_the_canonical_lifecycle_runner(self):
    with patch.object(lifecycle, "run_python_tests", return_value=0) as runner:
      result = keycloakctl_cli.run_acceptance_command("python-tests")
    self.assertEqual(0, result)
    runner.assert_called_once_with()

  def test_contributor_acceptance_instructions_match_retained_image_contract(self):
    instructions = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    self.assertIn("cleanup is recorded as `not_run`", instructions)
    self.assertIn("retains its built images", instructions)
    self.assertIn("`./keycloakctl images cleanup`", instructions)
    self.assertNotIn("confirm every stage and cleanup readback passed", instructions)
    self.assertNotIn("then removes only exact run-owned images", instructions)

  def test_acceptance_diff_check_rejects_committed_pr_whitespace(self):
    base = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
    bad_source = self.repo / "scripts/committed_with_trailing_whitespace.py"
    bad_source.write_text("value = 'candidate' \n", encoding="utf-8")
    subprocess.run(["git", "-C", str(self.repo), "add", str(bad_source)], check=True)
    subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "candidate whitespace"], check=True)
    with patch.object(keycloakctl_cli, "ROOT", self.repo), patch.dict(os.environ, {"PR_BASE_SHA": base}):
      self.assertNotEqual(0, keycloakctl_cli.verify_diff_check())

  def test_acceptance_diff_check_rejects_untracked_whitespace(self):
    (self.repo / "untracked_with_trailing_whitespace.txt").write_text(
        "candidate has trailing whitespace \n", encoding="utf-8")
    with (patch.object(keycloakctl_cli, "ROOT", self.repo),
          patch.dict(os.environ, {"PR_BASE_SHA": ""}),
          redirect_stdout(io.StringIO()) as output,
          redirect_stderr(io.StringIO()) as errors):
      self.assertNotEqual(0, keycloakctl_cli.verify_diff_check())
    self.assertIn("untracked_with_trailing_whitespace.txt:1: trailing whitespace",
                  output.getvalue() + errors.getvalue())

  def test_acceptance_rejects_surefire_reports_untouched_by_maven(self):
    self.write_java_acceptance_artifacts(self.repo)
    snapshot = keycloakctl_cli.surefire_report_snapshot()
    self.assertEqual(2, keycloakctl_cli.verify_surefire_reports(snapshot))

  def test_acceptance_stops_after_maven_when_surefire_reports_are_missing(self):
    root = self.cwd / "missing-surefire-root"
    root.mkdir()
    with patch.object(keycloakctl_cli, "ROOT", root):
      self.assertEqual(2, keycloakctl_cli.verify_surefire_reports({}))

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

    with patch.object(keycloakctl_cli, "ROOT", root):
      self.assertEqual(0, keycloakctl_cli.verify_provider_registration())

  def test_acceptance_python_stage_failure_is_read_back_as_failed_receipt(self):
    root = self.cwd / "acceptance-failure-root"
    root.mkdir()
    with patch.object(keycloakctl_cli, "ROOT", root), \
         patch.object(keycloakctl_cli, "acceptance_source_provenance", return_value={"tree_sha256": "c" * 64}), \
         patch.object(keycloakctl_cli, "perform_local_preflight"), \
         patch.object(lifecycle, "_image_inventory", return_value={"baseline"}), \
         patch.object(keycloakctl_cli, "surefire_report_snapshot", return_value={}), \
         patch.object(keycloakctl_cli, "run_acceptance_command", side_effect=lambda name, *_: 2 if name == "python-tests" else 0), \
         patch.object(keycloakctl_cli, "verify_surefire_reports", return_value=0), \
         patch.object(keycloakctl_cli, "verify_provider_registration", return_value=0), \
         patch.object(lifecycle, "_cleanup_owned_images") as cleanup:
      result = keycloakctl_cli.run_acceptance("offline")
    self.assertEqual(2, result)
    receipt_path = next((root / "target/keycloakctl/acceptance").glob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("failed", receipt["status"])
    self.assertEqual([("preflight", "pass"), ("java-tests", "pass"), ("surefire", "pass"),
                      ("provider-service-registration", "pass"), ("python-tests", "fail"),
                      ("cleanup", "not_run")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])
    cleanup.assert_not_called()

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
    with patch.object(lifecycle, "run", return_value=0), \
         patch.object(lifecycle, "extract_verified_wheelhouse", return_value=0), \
         patch.object(lifecycle.subprocess, "run", return_value=subprocess.CompletedProcess(
             [], 0, "", "Ran 0 tests in 0.000s\\n")):
      self.assertEqual(2, lifecycle.run_python_tests())

  def test_acceptance_rejects_ci_profile_in_public_cli(self):
    result = self.cli("acceptance", "--profile", "ci")
    self.assertEqual(2, result.returncode)
    self.assertEqual("", result.stdout)
    self.assertIn("invalid arguments", result.stderr)

  def test_acceptance_offline_profile_receipt_is_the_stage_inventory(self):
    # Assert the coordinator's real receipt, not a parallel helper's partial list.
    # Exercise argparse, the real coordinator and receipt writer; mock external stages.
    receipt_marker = "issue74-receipt-env-marker-5e901a82d14f"
    code = """import json
from pathlib import Path
from unittest.mock import patch
from scripts import keycloakctl_cli as cli
from scripts import lifecycle
root = Path.cwd() / 'public-cli-root'
root.mkdir()
import shutil
shutil.copytree(%r, root / 'config' / 'keycloakctl')
events=[]
with patch.object(cli, 'ROOT', root), \
     patch.object(cli, 'acceptance_source_provenance', return_value={'tree_sha256':'a'*64,'source_revision':'b'*40}), \
     patch.object(cli, 'perform_local_preflight', side_effect=lambda *_: events.append('preflight')), \
     patch.object(lifecycle, '_image_inventory', return_value={'baseline'}), \
     patch.object(cli, 'surefire_report_snapshot', return_value={}), \
     patch.object(cli, 'run_acceptance_command', side_effect=lambda name,*_: events.append(name) or 0), \
     patch.object(cli, 'verify_surefire_reports', return_value=0), \
     patch.object(cli, 'verify_provider_registration', return_value=0), \
     patch.object(cli, 'perform_build', side_effect=lambda *_: events.append('provider-image-build')), \
     patch.object(cli, 'perform_test', side_effect=lambda *_: events.append('image-smoke')), \
     patch.object(cli, 'verify_diff_check', return_value=0), \
     patch.object(cli, 'read_build_bundle', return_value=None), \
     patch.object(lifecycle, '_cleanup_owned_images', return_value={'status':'pass','inconclusive_image_count':0}):
  raise SystemExit(cli.main(['acceptance','--profile','offline']))
""" % str(ROOT / "config/keycloakctl")
    result = subprocess.run([sys.executable, "-c", code], cwd=self.cwd,
                            env={**self.env, "PYTHONPATH": str(ROOT),
                                 "KEYCLOAKCTL_TEST_SECRET": receipt_marker},
                            capture_output=True, text=True, timeout=10)
    self.assertEqual(0, result.returncode, result.stderr)
    self.assertNotIn(receipt_marker, result.stdout)
    self.assertNotIn(receipt_marker, result.stderr)
    self.assertIn("acceptance verified:", result.stdout)
    receipt_path = Path(result.stdout.strip().splitlines()[-1].removeprefix("acceptance verified: "))
    self.assertNotIn(receipt_marker.encode(), receipt_path.read_bytes())
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("offline", receipt["profile"])
    self.assertEqual("complete", receipt["status"])
    self.assertEqual({"tree_sha256": "a" * 64, "source_revision": "b" * 40}, receipt["source"])
    self.assertEqual([("preflight", "pass"), ("java-tests", "pass"), ("surefire", "pass"),
                      ("provider-service-registration", "pass"), ("python-tests", "pass"),
                      ("python-compile", "pass"), ("provider-image-build", "pass"),
                      ("rp-fixture-image-build", "pass"), ("image-smoke", "pass"),
                      ("rp-fixture-smoke", "pass"), ("diff-check", "pass"), ("cleanup", "not_run")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])

  def test_acceptance_failure_writes_durable_failed_stage_receipt(self):
    root = self.cwd / "acceptance-python-compile-failure"
    root.mkdir()
    with patch.object(keycloakctl_cli, "ROOT", root), \
         patch.object(keycloakctl_cli, "acceptance_source_provenance", return_value={"tree_sha256": "e" * 64}), \
         patch.object(keycloakctl_cli, "perform_local_preflight"), \
         patch.object(lifecycle, "_image_inventory", return_value={"baseline"}), \
         patch.object(keycloakctl_cli, "surefire_report_snapshot", return_value={}), \
         patch.object(keycloakctl_cli, "run_acceptance_command", side_effect=lambda name, *_: 2 if name == "python-compile" else 0), \
         patch.object(keycloakctl_cli, "verify_surefire_reports", return_value=0), \
         patch.object(keycloakctl_cli, "verify_provider_registration", return_value=0), \
         patch.object(lifecycle, "_cleanup_owned_images") as cleanup:
      self.assertEqual(2, keycloakctl_cli.run_acceptance("offline"))
    receipt_path = next((root / "target/keycloakctl/acceptance").glob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    self.assertEqual("failed", receipt["status"])
    self.assertEqual([("preflight", "pass"), ("java-tests", "pass"), ("surefire", "pass"),
                      ("provider-service-registration", "pass"), ("python-tests", "pass"),
                      ("python-compile", "fail"), ("cleanup", "not_run")],
                     [(stage["name"], stage["status"]) for stage in receipt["stages"]])
    cleanup.assert_not_called()

  def test_acceptance_refuses_live_profiles(self):
    for profile in ("ci", "wallet-login-qualification", "remote-test-host"):
      result = self.cli("acceptance", "--profile", profile)
      self.assertEqual(2, result.returncode)
      self.assertEqual("", result.stdout)
      self.assertIn("invalid arguments", result.stderr)

  def test_image_retention_commands_use_keycloakctl_dispatch(self):
    from unittest.mock import call
    commands = (
        (("cleanup",),),
        (("--engine", "docker", "cleanup", "--max-age-days", "7"),),
        (("pin", "sha256:" + "1" * 64, "integration-test"),),
        (("unpin", "sha256:" + "1" * 64, "integration-test"),),
        (("extend", "sha256:" + "1" * 64, "14"),),
    )
    with (patch("scripts.image_lifecycle.main", return_value=0) as legacy_main,
          patch("scripts.image_lifecycle.selected_engine", return_value="docker") as selected_engine,
          patch("scripts.image_lifecycle.cleanup_images", return_value={"removed": 0}) as cleanup_images,
          patch("scripts.image_lifecycle.pin_image") as pin_image,
          patch("scripts.image_lifecycle.unpin_image") as unpin_image,
          patch("scripts.image_lifecycle.extend_image") as extend_image,
          patch.dict(os.environ, {"DECENT_IMAGE_RETENTION_DAYS": "5"}),
          redirect_stdout(io.StringIO())):
      for (args,) in commands:
        self.assertEqual(0, keycloakctl_cli.main(["images", *args]))
    legacy_main.assert_not_called()
    selected_engine.assert_has_calls([call(None), call("docker"), call(None), call(None), call(None)])
    cleanup_images.assert_has_calls([
        call("docker", max_age_days=5), call("docker", max_age_days=7)])
    pin_image.assert_called_once_with("docker", "sha256:" + "1" * 64, "integration-test")
    unpin_image.assert_called_once_with("docker", "sha256:" + "1" * 64, "integration-test")
    extend_image.assert_called_once_with("docker", "sha256:" + "1" * 64, 14)

  def test_image_fingerprints_is_available_on_public_cli(self):
    self.assertEqual(tuple(sorted(lifecycle.IMAGE_BUILD_ARTIFACTS_BY_TARGET)),
                     keycloakctl_cli.IMAGE_FINGERPRINT_TARGETS)
    fingerprints = {"image_source_sha256": "a" * 64,
                    "image_artifacts_sha256": "b" * 64}
    for field, expected in (
        ("image_source_sha256", fingerprints["image_source_sha256"]),
        ("image_artifacts_sha256", fingerprints["image_artifacts_sha256"])):
      output = io.StringIO()
      with (patch.object(lifecycle, "fingerprint_source", return_value=fingerprints) as fingerprint,
            redirect_stdout(output)):
        result = keycloakctl_cli.main([
            "image-fingerprints", "--target", "runtime", "--field", field])
      self.assertEqual(0, result)
      self.assertEqual(expected + "\n", output.getvalue())
      fingerprint.assert_called_once_with(include_build_artifacts=True,
                                          image_target="runtime")
      fingerprint.reset_mock()

  def test_issue73_historical_proposal_does_not_misstate_current_issue_text(self):
    proposal = (ROOT / "docs/acceptance/issue-73-environment-baseline-proposal.md").read_text(
        encoding="utf-8")
    self.assertIn("At the time this proposal was drafted", proposal)
    self.assertIn("historical context rather than current issue wording", proposal)
    self.assertNotIn("The live #73 body currently describes one run manifest", proposal)

  def test_foundation_full_examples_include_required_artifact_inputs(self):
    foundation = (ROOT / "docs/acceptance/keycloakctl-foundation.md").read_text(
        encoding="utf-8")
    examples = [line for line in foundation.splitlines()
                if line.startswith("./keycloakctl full ")]
    self.assertEqual(2, len(examples))
    for example in examples:
      self.assertIn('--baseline "$BASELINE_FILE"', example)
      self.assertIn('--projection "$PROJECTION_FILE"', example)
    self.assertIn("access-controlled baseline/projection files supplied for this run", foundation)

  def test_issue74_migration_map_distinguishes_available_phases_from_acceptance_ci(self):
    migration_map = (ROOT / "docs/acceptance/issue-74-offline-migration-map.md").read_text(
        encoding="utf-8")
    self.assertIn("`keycloakctl build`", migration_map)
    self.assertIn("`keycloakctl test`", migration_map)
    self.assertIn("`./keycloakctl image-fingerprints --target ... --field ...`", migration_map)
    self.assertIn("`./keycloakctl images cleanup|pin|unpin|extend`", migration_map)
    self.assertIn("same `keycloakctl acceptance --profile offline` profile", migration_map)
    self.assertNotIn("no keycloakctl-owned build receipt", migration_map)
    for relative in (
        "README.md",
        "CONTRIBUTING.md",
        "docs/acceptance/issue-26-image-lifecycle.md",
    ):
      docs = (ROOT / relative).read_text(encoding="utf-8")
      self.assertIn("./keycloakctl images", docs, relative)
      self.assertNotIn("scripts/image_lifecycle.py cleanup", docs, relative)
    for relative in (
        "docs/acceptance/issue-6-postconsume-runtime.md",
        "docs/acceptance/issue-7-store-recovery.md",
        "docs/acceptance/issue-7-user-readback-recovery-profile.md",
        "docs/acceptance/issue-26-image-lifecycle.md",
    ):
      docs = (ROOT / relative).read_text(encoding="utf-8")
      self.assertIn("keycloakctl image-fingerprints", docs, relative)
      self.assertNotIn("scripts/lifecycle.py image-fingerprints", docs, relative)

  def test_issue74_migration_map_reports_artifact_validator_dependency_evidence(self):
    migration_map = (ROOT / "docs/acceptance/issue-74-offline-migration-map.md").read_text(
        encoding="utf-8")
    self.assertIn("`requirements/issue8-oidc.lock`", migration_map)
    self.assertIn("`.github/workflows/acceptance.yml`", migration_map)
    self.assertIn("Python 3.11.13", migration_map)
    self.assertEqual(10, sum(line.startswith(tuple(f"| {number}." for number in range(1, 11)))
                             for line in migration_map.splitlines()))
    self.assertIn("all 11 artifact validation tests", migration_map)
    self.assertIn("all 86 `scripts.test_keycloakctl` tests", migration_map)
    self.assertIn("snapshots repository-relative tracked and untracked regular files and contained symlinks after an explicit generated/non-input exclusion list",
                  migration_map)
    self.assertIn("Ignored-but-nonexcluded build inputs are included", migration_map)
    self.assertIn("The standalone legacy `scripts/lifecycle.py python-tests` command is distinct from", migration_map)
    self.assertIn("Live operations were not performed", migration_map)
    self.assertIn("| 4. Full local build/test/image acceptance and CI no-remote-side-effect gates | At source revision `da7213ad3e9839da030812c13c4fda90b7865cd1`, the offline acceptance receipt `target/keycloakctl/acceptance/e678cf35aada4dacbdb19f161fcc328b.json` records all local stages passed and cleanup `not_run`. The source-level workflow guard now asserts read-only `contents` permission, checkout credentials disabled, no secret/token references, exactly the three expected SHA-pinned checkout/Java/Python setup actions, and exactly the hash-pinned dependency install plus `./keycloakctl acceptance --profile offline` run commands. This is configuration evidence, not proof of hosted CI execution; the broader criterion remains incomplete. | Partial (local acceptance and workflow configuration subclaims only) |",
                  migration_map)
    self.assertIn("| 10. Ownership boundary and strict artifact validation | Strict baseline/projection validation remains input-only. This increment additionally proves closed persisted local run-intent validation for source/CLI-helper, image-ID, and complete same-run build/test receipt bindings before resumed local phases; it does not provision, authenticate approval, or implement target/operator/scope/window authorization. | Partial (bounded validation subclaims only) |",
                  migration_map)
    self.assertNotIn("runtime/isolated-test lock remains blocked", migration_map)
    self.assertNotIn("isolated canonical test path do not have it", migration_map)

  def test_public_help_spells_out_command_and_authorization_contract(self):
    top = self.cli("--help")
    self.assertEqual(0, top.returncode, top.stderr)
    for verb in ("setup", "validate-config", "validate-artifacts", "acceptance", "preflight", "build",
                 "test", "publish", "deploy", "configure", "integration-test", "verify readiness",
                 "verify qualification", "teardown", "promote", "full", "image-fingerprints", "images"):
      with self.subTest(verb=verb):
        self.assertIn(verb, top.stdout)
    top_text = " ".join(top.stdout.split())
    for text in ("Profiles: `dev` and `ci` are local profiles", "readiness", "qualification", "full --new-run",
                 "full --run-id RUN_ID", "verify current active owner approval out of band",
                 "exact artifact hashes, target, operations/cases, and windows",
                 "--approval-ref REF", "--approval-sha256 HASH", "--allow-live",
                 "audit references only", "not authentication or scope verification",
                 "remote preflight adapter", "stop before publish",
                 "separate existing registry publication gate"):
      with self.subTest(text=text):
        self.assertIn(text, top_text)

    for command in ("publish", "deploy", "configure", "integration-test", "teardown",
                    "verify readiness", "verify qualification"):
      result = self.cli(*command.split(), "--help")
      help_text = " ".join(result.stdout.split())
      with self.subTest(command=command):
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("approval-ref REF", help_text)
        self.assertIn("approval-sha256 HASH", help_text)
        self.assertIn("not authentication", help_text)
    full = self.cli("full", "--help")
    full_text = " ".join(full.stdout.split())
    self.assertEqual(0, full.returncode, full.stderr)
    self.assertIn("--new-run", full_text)
    self.assertIn("--run-id RUN_ID", full_text)
    self.assertIn("stop before remote mutations", full_text)
    promote = self.cli("promote", "--help")
    promote_text = " ".join(promote.stdout.split())
    self.assertEqual(0, promote.returncode, promote.stderr)
    self.assertIn("--allow-publish", promote_text)
    self.assertIn("not environment owner approval", promote_text)

  def test_cli_help_labels_deferred_profile_plans_as_historical(self):
    result = self.cli("--help")
    self.assertEqual(0, result.returncode, result.stderr)
    self.assertIn("dev: setup -> build -> test", result.stdout)
    self.assertIn("Profile plans available in the phase model (not all phases are implemented):", result.stdout)
    self.assertIn("readiness: setup -> preflight", result.stdout)
    self.assertIn("qualification: setup -> preflight", result.stdout)
    for command in ("publish", "deploy", "configure", "integration-test", "verify", "teardown"):
      with self.subTest(command=command):
        self.assertIn(f"{command:<19} deferred/unavailable:", result.stdout)
    self.assertIn("promote             deferred; publication is unavailable", result.stdout)

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

  def test_valid_remote_setup_does_not_leak_accepted_config_sentinel_to_state_or_output(self):
    for profile in ("readiness", "qualification"):
      with self.subTest(profile=profile):
        # This sentinel is a sink canary in an accepted non-secret config value,
        # not a claimed credential field or a test of credential-provider integration.
        sentinel = f"canary-{profile[:3]}-7f93c4b06c21"
        config = json.loads((ROOT / f"config/keycloakctl/{profile}.json").read_text(
            encoding="utf-8"))
        config["remote"]["target_user"] = sentinel
        config_path = self.config_file(config)

        result = self.cli("setup", "--config", config_path)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertRegex(result.stdout, r"\A[0-9a-f]{32}\n\Z")
        self.assertNotIn(sentinel, result.stdout)
        self.assertNotIn(sentinel, result.stderr)

        for state_root in (self.repo / "target", self.repo / ".keycloakctl"):
          self.assertTrue(state_root.exists(), f"setup should create {state_root.name} state")
          for path in state_root.rglob("*"):
            if path.is_file():
              self.assertNotIn(sentinel.encode(), path.read_bytes())

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
                 "verify readiness", "verify qualification", "teardown", "promote", "full", "images",
                 "image-fingerprints", "dev", "ci", "Issue #74 remains incomplete"):
      with self.subTest(help=text):
        self.assertIn(text, result.stdout)
    self.assertIn("builds/smokes", result.stdout)
    self.assertIn("offline acceptance profile", result.stdout)

    self.prepare_build_inputs()
    self.use_unavailable_engine()
    run_id = self.setup_run("--profile", "dev")
    dev = ("--run-id", run_id)
    original = (self.run_directory(run_id) / "manifest.json").read_bytes()
    self.rejection(2, "invalid phase order; next phase is build", "test", *dev)
    auth = ("--allow-live", "--approval-ref", "opaque ref", "--approval-sha256", "b" * 64)
    self.rejection(2, "phase is not supported by run profile", "publish", *dev, *auth)
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
  image = next(value for value in args if value.startswith("sha256:"))
  if image.startswith("sha256:" + "1" * 64):
    with open(os.environ["STEP_LOG"], "a") as out: out.write("image-smoke\\n")
    print("Keycloak 26.8.0\\nJVM: 21")
  else:
    with open(os.environ["STEP_LOG"], "a") as out: out.write("rp-fixture-smoke\\n")
    print("RP fixture smoke passed")
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
    self.assertEqual(["run", "--rm", "--network=none", "sha256:" + "2" * 64, "--smoke"],
                     smoke_commands[1])

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
      result = self.cli("preflight", "--run-id", run_id, "--config", path, "--allow-live",
                      "--approval-ref", "fixture-ref", "--approval-sha256", "a" * 64)
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
    result = self.cli("preflight", "--run-id", run_id, "--config", path, "--allow-live",
                      "--approval-ref", "fixture-ref", "--approval-sha256", "a" * 64)
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
        result = self.cli("preflight", "--run-id", run_id, "--config", path, "--allow-live",
                          "--approval-ref", "fixture-ref", "--approval-sha256", "a" * 64)
        self.assertEqual((2, "", f"error: preflight {message}\n"),
                         (result.returncode, result.stdout, result.stderr))
        self.assertEqual(before, self.storage_snapshot())

  def test_remote_preflight_requires_authorization_before_any_remote_probe(self):
    config = self.live_config("qualification")
    path = self.config_file(config)
    run_id = self.setup_run("--config", path)
    self.install_preflight_adapters()
    for flags, expected in (
        ((), "preflight requires --allow-live on this invocation"),
        (("--allow-live",), "preflight requires an approval reference and 64-character SHA-256"),
    ):
      result = self.cli("preflight", "--run-id", run_id, "--config", path, *flags)
      self.assertEqual((2, "", f"error: {expected}\n"),
                       (result.returncode, result.stdout, result.stderr))
      self.assertFalse((self.cwd / "tailscale.jsonl").exists())
      self.assertFalse((self.cwd / "tool.jsonl").exists())

  def test_preflight_requires_an_explicit_expected_tailscale_dns_name(self):
    config = self.live_config()
    del config["remote"]["target_dns_name"]
    path = self.config_file(config)
    run_id = self.setup_run("--config", path)
    self.install_preflight_adapters()

    result = self.cli("preflight", "--run-id", run_id, "--config", path, "--allow-live",
                      "--approval-ref", "fixture-ref", "--approval-sha256", "a" * 64)

    self.assertEqual((2, "", "error: preflight requires matching operator inputs and route attestation\n"),
                     (result.returncode, result.stdout, result.stderr))

  def test_full_accepts_only_local_profiles_and_requires_one_run_selector(self):
    base = ("full", "--profile", "dev")
    unknown = "f" * 32
    self.rejection(2, "invalid arguments; see --help", *base)
    self.rejection(2, "invalid arguments; see --help", *base, "--run-id", unknown, "--new-run")
    artifact_args = ("--baseline", "baseline.json", "--projection", "projection.json")
    self.rejection(2, "unknown run ID", *base, "--run-id", unknown, "--config", str(self.cwd / "config.json"),
                   *artifact_args)
    self.rejection(2, "invalid arguments; see --help", "full", "--profile", "invalid", "--new-run")
    self.rejection(2, "invalid arguments; see --help", *base, "--new-run", "--allow-live")
    self.assertFalse((self.repo / "target").exists())
    self.assertFalse((self.repo / ".keycloakctl").exists())

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

  def test_full_resume_accepts_only_the_same_local_run(self):
    run_id = "a" * 32
    self.rejection(2, "unknown run ID", "full", "--profile", "dev", "--run-id", run_id,
                   "--config", str(self.cwd / "config.json"), "--baseline", "baseline.json",
                   "--projection", "projection.json")
    self.rejection(2, "invalid arguments; see --help", "full", "--profile", "qualification",
                   "--run-id", run_id)
    self.assertFalse((self.repo / "target").exists())
    self.assertFalse((self.repo / ".keycloakctl").exists())

  def test_live_approval_reference_and_digest_are_required_as_a_non_echoed_pair(self):
    run_id = self.setup_run("--profile", "readiness")
    prefix = ("deploy", "--run-id", run_id, "--allow-live")
    self.rejection(2, "deploy requires an approval reference and 64-character SHA-256",
                   *prefix, "--approval-ref", "marker-ref")
    self.rejection(2, "deploy requires an approval reference and 64-character SHA-256",
                   *prefix, "--approval-sha256", "a" * 64)
    self.rejection(2, "deploy requires an approval reference and 64-character SHA-256",
                   *prefix, "--approval-ref", "marker-ref", "--approval-sha256", "bad")
    result = self.cli(*prefix, "--approval-ref", "marker-ref", "--approval-sha256", "e" * 64)
    self.assertEqual(2, result.returncode)
    self.assertIn("invalid phase order", result.stderr)
    self.assertNotIn("marker-ref", result.stdout + result.stderr)
    self.assertNotIn("e" * 64, result.stdout + result.stderr)

  def test_full_profile_parser_accepts_readiness_and_qualification(self):
    for profile in ("readiness", "qualification"):
      with self.subTest(profile=profile):
        parsed = keycloakctl_cli.make_parser().parse_args(
            ["full", "--profile", profile, "--new-run", "--config", "runtime.json",
             "--baseline", "baseline.json", "--projection", "cases.json"])
        self.assertEqual(profile, parsed.profile)

  def test_live_and_publish_authorization_are_distinct_and_not_persisted(self):
    config = self.live_config("qualification")
    qual = ("--run-id", self.setup_run("--config", self.config_file(config)))
    ready = ("--run-id", self.setup_run("--profile", "readiness"))
    original = self.storage_snapshot()
    for command, run in (("publish", qual), ("deploy", qual), ("configure", qual),
                         ("integration-test", qual), ("teardown", qual),
                         ("verify readiness", ready), ("verify qualification", qual)):
      with self.subTest(command=command):
        args = (*command.split(), *run)
        denied = f"{command} requires --allow-live on this invocation"
        self.rejection(2, f"{command} requires --allow-live on this invocation", *args)
        self.rejection(2, f"{command} requires an approval reference and 64-character SHA-256",
                       *args, "--allow-live")
        authorized = ("teardown requires exact run-owned deployment readback" if command == "teardown"
                      else "invalid phase order; next phase is preflight")
        self.rejection(2, authorized, *args, "--allow-live", "--approval-ref", "audit-ref",
                       "--approval-sha256", "a" * 64)
        self.rejection(2, f"{command} requires --allow-live on this invocation", *args)

    self.rejection(2, "phase is not supported by run profile", "verify", "readiness", *qual,
                   "--allow-live", "--approval-ref", "opaque ref", "--approval-sha256", "c" * 64)
    self.rejection(2, "phase is not supported by run profile", "integration-test", *ready,
                   "--allow-live", "--approval-ref", "opaque ref", "--approval-sha256", "c" * 64)
    self.rejection(2, "phase is not supported by run profile", "verify", "qualification", *ready,
                   "--allow-live", "--approval-ref", "opaque ref", "--approval-sha256", "c" * 64)
    self.rejection(2, "invalid phase order; next phase is preflight", "verify", "qualification", *qual,
                   "--allow-live", "--approval-ref", "opaque ref", "--approval-sha256", "c" * 64)
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
    path = self.config_file({"version": 1, "profile": "dev", "client_secret": marker})
    self.rejection(2, "invalid configuration", "setup", "--config", path)
    self.rejection(2, "invalid configuration", "full", "--profile", "dev", "--new-run", "--config", path,
                   "--baseline", "baseline.json", "--projection", "projection.json")
    self.rejection(2, "invalid arguments; see --help", "setup", "--profile", marker)
    self.assertEqual({}, self.storage_snapshot())
    self.assertFalse((self.repo / "target").exists())
    self.assertFalse((self.repo / ".keycloakctl").exists())

  def test_public_setup_rejects_sensitive_unknown_fields_before_state_or_output(self):
    examples = {profile: json.loads((self.repo / f"config/keycloakctl/{profile}.json").read_text())
                for profile in ("dev", "ci", "readiness", "qualification")}
    cases = []
    for profile, example in examples.items():
      cases.append((profile, "top-level", {**example, "password": f"marker-{profile}-password-8ce7"}))
      cases.append((profile, "top-level", {**example, "client_secret": f"marker-{profile}-client-secret-a934"}))
      if "remote" in example:
        cases.append((profile, "nested", {**example, "remote": {
            **example["remote"], "token": f"marker-{profile}-remote-token-53d1"}}))
        cases.append((profile, "nested", {**example, "remote": {
            **example["remote"], "api_key": f"marker-{profile}-remote-api-key-731c"}}))

    for profile, field_group, config in cases:
      with self.subTest(profile=profile, field_group=field_group, keys=set(config)):
        marker_values = [value for key, value in config.items()
                         if key in ("password", "client_secret")]
        marker_values += [value for key, value in config.get("remote", {}).items()
                          if key in ("token", "api_key")]
        result = self.cli("setup", "--config", self.config_file(config))
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("error: invalid configuration\n", result.stderr)
        for marker in marker_values:
          self.assertNotIn(marker, result.stdout + result.stderr)
        self.assertFalse((self.repo / "target/keycloakctl/runs").exists())
        self.assertFalse((self.repo / "target/keycloakctl/acceptance").exists())
        self.assertFalse((self.repo / ".keycloakctl/run-ids").exists())
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
                       "preflight", "--run-id", run_id, "--config", path, "--allow-live",
                       "--approval-ref", "fixture-ref", "--approval-sha256", "a" * 64)
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
    auth = ("--allow-live", "--approval-ref", "opaque ref", "--approval-sha256", "d" * 64)
    result = self.cli("teardown", "--run-id", run_id, *auth)
    self.assertEqual((2, "", "error: teardown requires exact run-owned deployment readback\n"),
                     (result.returncode, result.stdout, result.stderr))
    self.assertEqual(original, state_path.read_bytes())
    forged = {**json.loads(original), "completed": ["setup", "preflight", "build", "test",
                                                       "publish", "deploy"]}
    raw = json.dumps(forged, separators=(",", ":")).encode() + b"\n"
    self.reservation(run_id).write_text(sha256(raw).hexdigest(), encoding="ascii")
    state_path.write_bytes(raw)
    auth = ("--allow-live", "--approval-ref", "opaque ref", "--approval-sha256", "d" * 64)
    result = self.cli("teardown", "--run-id", run_id, *auth)
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


class ArtifactValidationCliTest(unittest.TestCase):
  CASE_IDS = ["LOGIN-01", "TLS-01", "TLS-02", *(f"NEG-{index:02d}" for index in range(1, 8))]

  def setUp(self):
    self.scratch = tempfile.TemporaryDirectory(prefix="keycloakctl-artifacts-")
    self.addCleanup(self.scratch.cleanup)
    self.root = Path(self.scratch.name)
    self.repo = self.root / "repo"
    (self.repo / "scripts").mkdir(parents=True)
    (self.repo / "config/keycloakctl").mkdir(parents=True)
    shutil.copy2(ROOT / "keycloakctl", self.repo / "keycloakctl")
    shutil.copy2(ROOT / "scripts/keycloakctl_cli.py", self.repo / "scripts/keycloakctl_cli.py")
    shutil.copy2(ROOT / "config/keycloakctl/issue74-artifact.schema.json",
                 self.repo / "config/keycloakctl/issue74-artifact.schema.json")
    shutil.copy2(ROOT / "config/keycloakctl/config.schema.json",
                 self.repo / "config/keycloakctl/config.schema.json")
    self.bin = self.root / "bin"
    self.bin.mkdir()
    python311 = self.bin / "python3.11"
    python311.write_text("#!/bin/sh\nexec " + sys.executable + ' "$@"\n', encoding="utf-8")
    python311.chmod(0o755)
    self.config_raw = b'{"version":1,"profile":"readiness","engine":"podman"}\n'
    self.baseline = {
        "document_type": "environment-baseline", "schema_version": 1,
        "baseline_id": "env-2026-01", "revision": 1,
        "created_at": "2026-11-27T12:00:00Z", "supersedes": None,
        "runtime_config": {"sha256": sha256(self.config_raw).hexdigest(), "artifact_ref": "restricted/config-v1"},
        "case_inventory": {"sha256": "1" * 64, "artifact_ref": "restricted/cases-v1", "case_ids": self.CASE_IDS},
        "target": {"tailscale_node_id": "node-17", "dns_name": "keycloak.example.net",
                   "ip_address": "192.0.2.17", "os_account": "operator"},
        "access_policy": {"caller_principals": ["operator@example.net"],
                          "ssh_acl_attestation": {"sha256": "2" * 64, "artifact_ref": "restricted/acl"},
                          "operator_scope_ref": "restricted/operators"},
        "route": {"route_id": "route-17", "configuration_sha256": "3" * 64,
                  "public_origin": "https://keycloak.example.net:8443/",
                  "forwarded_header_contract_sha256": "4" * 64,
                  "owner_attestation_ref": "restricted/route"},
        "software_constraints": {"keycloak_source_ref": "source/keycloak", "rp_fixture_source_ref": "source/rp",
                                 "realm_config_sha256": "5" * 64, "oidc_client_config_sha256": "6" * 64},
        "profiles": {"readiness": {"readiness_state": "pending", "plan_ref": "plans/readiness",
                                    "plan_sha256": "7" * 64},
                      "qualification": {"readiness_state": "pending", "plan_ref": "plans/qualification",
                                        "plan_sha256": "8" * 64}},
        "secret_roles": [{"role": "runtime credential", "custodian": "operator"}],
        "clock_policy": {"source": "host-os-utc", "require_os_sync": True, "max_drift_seconds": 30},
        "retention_seconds": 86400,
        "resource_policy": {"fresh_disposable_identity": True,
                            "teardown_policy": {"sha256": "9" * 64, "artifact_ref": "restricted/teardown"}},
        "owner_review_ref": "restricted/owner-review"
    }
    self.projection = {
        "document_type": "case-inventory-projection", "schema_version": 1,
        "canonicalization": "RFC8785-JCS-UTF8-no-BOM-no-trailing-newline",
        "source_issue": {"number": 66, "url": "https://github.com/jetpen/decent-keycloak/issues/66",
                         "source_snapshot": {"sha256": "a" * 64, "artifact_ref": "restricted/issue-66"}},
        "case_ids": list(self.CASE_IDS),
        "cases": {case_id: {"definition_projection": f"projection/{case_id}",
                             "expected_observations": ["expected bounded observation"]}
                   for case_id in self.CASE_IDS}
    }
    self.baseline["case_inventory"]["sha256"] = sha256(self.projection_bytes()).hexdigest()
    self.config_path = self.root / "runtime.json"
    self.config_path.write_bytes(self.config_raw)
    self.baseline_path = self.root / "baseline.json"
    self.projection_path = self.root / "projection.json"
    self.write_artifacts()

  def projection_bytes(self):
    return json.dumps(self.projection, sort_keys=True, separators=(",", ":")).encode()

  def write_artifacts(self, *, baseline=None, projection=None, baseline_raw=None, projection_raw=None):
    self.baseline_path.write_bytes(baseline_raw if baseline_raw is not None else
                                   (json.dumps(self.baseline if baseline is None else baseline) + "\n").encode())
    projection_value = self.projection if projection is None else projection
    self.projection_path.write_bytes(projection_raw if projection_raw is not None else
                                     json.dumps(projection_value, sort_keys=True,
                                                separators=(",", ":")).encode())

  def cli(self, *args):
    return subprocess.run([str(self.repo / "keycloakctl"), *args], cwd=self.root,
                          capture_output=True, text=True, env={**os.environ,
                              "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(self.root),
                              "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", "")})

  def validate(self):
    return self.cli("validate-artifacts", "--baseline", str(self.baseline_path),
                    "--projection", str(self.projection_path), "--config", str(self.config_path))

  def assert_rejected_without_leak(self, marker=None):
    before = (self.baseline_path.read_bytes(), self.projection_path.read_bytes(), self.config_path.read_bytes())
    result = self.validate()
    after = (self.baseline_path.read_bytes(), self.projection_path.read_bytes(), self.config_path.read_bytes())
    self.assertEqual(before, after)
    self.assertEqual(2, result.returncode, (result.stdout, result.stderr))
    self.assertEqual("", result.stdout)
    self.assertEqual("error: invalid artifacts or bindings\n", result.stderr)
    if marker:
      self.assertNotIn(marker, result.stdout + result.stderr)

  def test_public_cli_accepts_valid_baseline_projection_and_exact_config_bytes(self):
    result = self.validate()
    self.assertEqual((0, "artifacts valid\n", ""), (result.returncode, result.stdout, result.stderr))

  def test_projection_must_use_exact_canonical_utf8_bytes(self):
    projection = json.loads(self.projection_bytes())
    projection["cases"]["LOGIN-01"]["expected_observations"] = ["café observation"]
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    self.assertIn("café".encode("utf-8"), canonical)
    self.assertNotIn(b"\\u00e9", canonical)
    self.write_artifacts(projection_raw=canonical)
    baseline = dict(self.baseline)
    baseline["case_inventory"] = dict(self.baseline["case_inventory"])
    baseline["case_inventory"]["sha256"] = sha256(canonical).hexdigest()
    self.write_artifacts(baseline=baseline, projection_raw=canonical)
    positive = self.validate()
    self.assertEqual((0, "artifacts valid\n", ""),
                     (positive.returncode, positive.stdout, positive.stderr))

    malformed = {
        "reordered keys": json.dumps(dict(reversed(list(projection.items()))),
                                      separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        "whitespace": json.dumps(projection, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8"),
        "BOM": b"\xef\xbb\xbf" + canonical,
        "trailing newline": canonical + b"\n",
        "escaped Unicode": canonical.replace("café".encode("utf-8"), b"caf\\u00e9"),
    }
    for name, raw in malformed.items():
      with self.subTest(name=name):
        baseline = dict(self.baseline)
        baseline["case_inventory"] = dict(self.baseline["case_inventory"])
        baseline["case_inventory"]["sha256"] = sha256(raw).hexdigest()
        self.write_artifacts(baseline=baseline, projection_raw=raw)
        self.assert_rejected_without_leak()

  def test_schema_is_draft_2020_12_and_uses_standard_format_validation(self):
    import jsonschema
    schema = json.loads((self.repo / "config/keycloakctl/issue74-artifact.schema.json").read_text())
    self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    self.assertTrue(validator.is_valid(self.baseline))
    invalid = json.loads(json.dumps(self.baseline))
    invalid["target"]["ip_address"] = "999.2.3.4"
    self.assertFalse(validator.is_valid(invalid))

  def test_duplicate_keys_are_rejected_without_echoing_raw_content(self):
    marker = "secret-marker-74-artifact"
    self.write_artifacts(baseline_raw=(b'{"document_type":"environment-baseline","token":"' +
                                      marker.encode() + b'","token":"x"}'))
    self.assert_rejected_without_leak(marker)

  def test_malformed_and_oversized_artifacts_fail_with_fixed_diagnostic(self):
    marker = "oversized-secret-marker-no-output"
    self.write_artifacts(baseline_raw=b"{" + marker.encode() + b"x" * 65536)
    self.assert_rejected_without_leak(marker)
    self.write_artifacts(baseline_raw=b"{ malformed json }")
    self.assert_rejected_without_leak()

  def test_unknown_fields_and_float_or_nonfinite_json_numbers_are_rejected(self):
    invalid = dict(self.baseline)
    invalid["unrecognized"] = "closed"
    self.write_artifacts(baseline=invalid)
    self.assert_rejected_without_leak()
    raw = json.dumps(self.baseline, separators=(",", ":")).encode()
    for number in (b"1.0", b"NaN", b"Infinity"):
      with self.subTest(number=number):
        changed = raw.replace(b'"retention_seconds":86400', b'"retention_seconds":' + number)
        self.write_artifacts(baseline_raw=changed)
        self.assert_rejected_without_leak()

  def test_case_inventory_order_and_exact_ten_case_projection_are_enforced(self):
    invalid = json.loads(json.dumps(self.projection))
    invalid["case_ids"][0], invalid["case_ids"][1] = invalid["case_ids"][1], invalid["case_ids"][0]
    self.write_artifacts(projection=invalid)
    self.assert_rejected_without_leak()
    invalid = json.loads(json.dumps(self.projection))
    del invalid["cases"]["NEG-07"]
    self.write_artifacts(projection=invalid)
    self.assert_rejected_without_leak()

  def test_cross_artifact_hash_and_runtime_config_exact_bytes_are_bound(self):
    bad = json.loads(json.dumps(self.baseline))
    bad["case_inventory"]["sha256"] = "b" * 64
    self.write_artifacts(baseline=bad)
    self.assert_rejected_without_leak()
    self.write_artifacts()
    self.config_path.write_bytes(self.config_raw + b" ")
    self.assert_rejected_without_leak()

  def test_format_checker_registers_and_enforces_date_time_and_uri(self):
    import jsonschema
    from jsonschema.exceptions import FormatError

    checker = jsonschema.FormatChecker()
    self.assertIn("date-time", checker.checkers)
    self.assertIn("uri", checker.checkers)
    for value, format_name in (("2026-02-30T12:00:00Z", "date-time"),
                               ("https://bad host.example", "uri")):
      with self.subTest(value=value, format=format_name):
        with self.assertRaises(FormatError):
          checker.check(value, format_name)

  def test_cli_rejects_invalid_date_time_and_non_public_https_origins(self):
    invalid = json.loads(json.dumps(self.baseline))
    invalid["created_at"] = "2026-02-30T12:00:00Z"
    self.write_artifacts(baseline=invalid)
    self.assert_rejected_without_leak()

    for origin in ("http://keycloak.example.net/", "https://user@keycloak.example.net/",
                   "https://keycloak.example.net/path", "https://keycloak.example.net/?token=x",
                   "https://keycloak.example.net/#fragment", "mailto:operator@example.net"):
      with self.subTest(origin=origin):
        invalid = json.loads(json.dumps(self.baseline))
        invalid["route"]["public_origin"] = origin
        self.write_artifacts(baseline=invalid)
        self.assert_rejected_without_leak()

    valid = json.loads(json.dumps(self.baseline))
    valid["route"]["public_origin"] = "https://keycloak.example.net:8443/"
    self.write_artifacts(baseline=valid)
    result = self.validate()
    self.assertEqual((0, "artifacts valid\n", ""), (result.returncode, result.stdout, result.stderr))

  def test_schema_rejects_invalid_address_format_and_secret_value_fields(self):
    invalid = json.loads(json.dumps(self.baseline))
    invalid["target"]["ip_address"] = "999.2.3.4"
    self.write_artifacts(baseline=invalid)
    self.assert_rejected_without_leak()
    marker = "do-not-print-or-persist-this-secret-74"
    invalid = json.loads(json.dumps(self.baseline))
    invalid["runtime_secret"] = marker
    self.write_artifacts(baseline=invalid)
    self.assert_rejected_without_leak(marker)
    self.assertEqual([], list((self.repo / "target").glob("**/*")) if (self.repo / "target").exists() else [])


if __name__ == "__main__":
  unittest.main()
