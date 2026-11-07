"""Offline safety and contract tests for the remote test-host helper."""

import subprocess
import sys
import unittest
from unittest import mock

from scripts import remote_test_host


class RemoteTestHostContractTests(unittest.TestCase):
  def test_run_scoped_target_tag_never_overwrites_latest(self):
    tag = remote_test_host.target_tag("a" * 32)
    self.assertEqual("decent-keycloak:lifecycle-" + "a" * 32, tag)
    self.assertNotEqual("decent-keycloak:latest", tag)

  def test_target_helper_command_invokes_stdin_python_with_run_identity(self):
    command = remote_test_host.target_helper_command(
        "operator@remote-test.example", "deploy", "a" * 32,
        "sha256:" + "b" * 64, host="remote-test.example")
    remote_args = remote_test_host.shlex.split(command[3])
    self.assertEqual(["tailscale", "ssh", "operator@remote-test.example"], command[:3])
    self.assertEqual(["python3", "-c"], remote_args[:2])
    self.assertIn("b64decode(", remote_args[2])
    self.assertEqual(["deploy", "a" * 32, "sha256:" + "b" * 64,
        "remote-test.example"], remote_args[-4:])

  def test_embedded_target_command_runs_target_dispatch_and_emits_sanitized_result(self):
    command = remote_test_host.target_helper_command(
        "ben@host.tailnet.invalid", "preflight", "a" * 32,
        "sha256:" + "b" * 64, host="host.tailnet.invalid")
    remote_args = remote_test_host.shlex.split(command[3])
    remote_args[-4] = "unsupported"
    result = subprocess.run([sys.executable, *remote_args[1:]],
        text=True, capture_output=True, check=False)
    self.assertEqual(2, result.returncode)
    self.assertEqual({"ok": False, "category": "unknown_target_operation"},
        remote_test_host.json.loads(result.stdout))
    self.assertNotIn("Traceback", result.stderr)

  def test_validates_lifecycle_run_id_and_full_immutable_image_id(self):
    remote_test_host.validate_identity("a" * 32, "sha256:" + "b" * 64)
    for run_id, image_id in (("latest", "sha256:" + "b" * 64),
        ("a" * 32, "short"), ("../" + "a" * 29, "sha256:" + "b" * 64)):
      with self.subTest(run_id=run_id, image_id=image_id):
        with self.assertRaises(ValueError):
          remote_test_host.validate_identity(run_id, image_id)

  def test_target_image_inspection_normalizes_podmans_bare_immutable_id(self):
    image_id = "sha256:" + "b" * 64
    result = remote_test_host.subprocess.CompletedProcess([], 0, "b" * 64 + "\n", "")
    with mock.patch.object(remote_test_host, "_target_run", return_value=result):
      self.assertTrue(remote_test_host._target_inspect_image(image_id))

  def test_plan_is_tailnet_only_and_run_scoped(self):
    steps = remote_test_host.operation_plan("a" * 32, "sha256:" + "b" * 64)
    self.assertEqual(["transfer", "deploy", "probe", "teardown"],
        [step["operation"] for step in steps])
    self.assertTrue(all(step["run_id"] == "a" * 32 for step in steps))
    self.assertTrue(all(step["image_id"] == "sha256:" + "b" * 64 for step in steps))
    self.assertTrue(all(step["tailnet_only"] for step in steps))
    self.assertNotIn("funnel", repr(steps).lower())

  def test_orchestration_tears_down_after_probe_failure(self):
    calls = []
    def record(name, result=None):
      calls.append(name)
      if isinstance(result, Exception):
        raise result
      return result
    with unittest.mock.patch.object(remote_test_host, "transfer_image",
        side_effect=lambda *_args: record("transfer")), \
        unittest.mock.patch.object(remote_test_host, "run_target",
            side_effect=lambda _target, operation, *_args, **_kwargs: record(operation)), \
        unittest.mock.patch.object(remote_test_host, "probe_discovery",
            side_effect=lambda _host: record("probe", RuntimeError("probe failed"))):
      with self.assertRaisesRegex(RuntimeError, "probe failed"):
        remote_test_host.remote_lifecycle("ben@host", "host", "a" * 32,
            "sha256:" + "b" * 64)
    self.assertEqual(["transfer", "deploy", "probe", "teardown"], calls)

  def test_orchestration_tears_down_if_receipt_callback_fails_after_transfer(self):
    calls = []
    def record_step(name, status, _detail):
      calls.append((name, status))
      if name == "remote-image-transfer" and status == "pass":
        raise OSError("receipt write failed")
    with mock.patch.object(remote_test_host, "transfer_image", return_value={}), \
        mock.patch.object(remote_test_host, "run_target",
            side_effect=lambda _target, operation, *_args, **_kwargs: calls.append((operation, "called"))):
      with self.assertRaisesRegex(OSError, "receipt write failed"):
        remote_test_host.remote_lifecycle("ben@host.tailnet.invalid", "host.tailnet.invalid",
            "a" * 32, "sha256:" + "b" * 64, on_step=record_step)
    self.assertIn(("teardown", "called"), calls)
    self.assertIn(("remote-teardown", "pass"), calls)

  def test_deploy_generates_bootstrap_secret_target_side_without_putting_it_in_argv(self):
    run_id, image_id, secret = "a" * 32, "sha256:" + "b" * 64, "target-secret-value"
    record = {"Id": "c" * 64, "Image": image_id, "Config": {"Labels": {
        "io.decent.lifecycle.run-id": run_id,
        "io.decent.lifecycle.image-id": image_id}}}
    calls = []
    def target_run(args, *, input_stream=None, env=None, **_kwargs):
      calls.append((args, dict(env) if env else None))
      code = 1 if args[:3] == ["podman", "container", "exists"] else 0
      return remote_test_host.subprocess.CompletedProcess(args, code, "", "")
    with mock.patch.object(remote_test_host, "_assert_target_identity", return_value="host.tailnet"), \
        mock.patch.object(remote_test_host, "_target_image_ref_id", return_value=image_id), \
        mock.patch.object(remote_test_host, "_target_container", side_effect=[None, record]), \
        mock.patch.object(remote_test_host, "_target_serve_status", return_value="no serve config"), \
        mock.patch.object(remote_test_host, "_target_run", side_effect=target_run), \
        mock.patch.object(remote_test_host.secrets, "token_urlsafe", return_value=secret):
      result = remote_test_host._target_operation("deploy", run_id, image_id, "host.tailnet")
    self.assertTrue(result["ok"])
    self.assertTrue(any(env and env.get("KC_BOOTSTRAP_ADMIN_PASSWORD") == secret
        for _args, env in calls))
    self.assertNotIn(secret, repr([args for args, _env in calls]))
    self.assertFalse(any("funnel" in " ".join(args).lower() for args, _env in calls))

  def test_teardown_refuses_container_whose_run_or_image_identity_differs(self):
    run_id, image_id = "a" * 32, "sha256:" + "b" * 64
    record = {"Id": "c" * 64, "Image": image_id, "Config": {"Labels": {
        "io.decent.lifecycle.run-id": "d" * 32,
        "io.decent.lifecycle.image-id": image_id}}}
    with mock.patch.object(remote_test_host, "_assert_target_identity", return_value="host.tailnet.invalid"), \
        mock.patch.object(remote_test_host, "_target_container", return_value=record), \
        mock.patch.object(remote_test_host, "_target_run") as run:
      with self.assertRaisesRegex(RuntimeError, "ownership_mismatch"):
        remote_test_host._target_operation("teardown", run_id, image_id,
            "host.tailnet.invalid")
    run.assert_not_called()

  def test_teardown_does_not_claim_serve_absence_when_container_is_gone(self):
    with mock.patch.object(remote_test_host, "_assert_target_identity", return_value="host.tailnet.invalid"), \
        mock.patch.object(remote_test_host, "_target_container", return_value=None), \
        mock.patch.object(remote_test_host, "_target_serve_status", return_value="some serve route"):
      with self.assertRaisesRegex(RuntimeError, "serve_ownership_unverified"):
        remote_test_host._target_operation("teardown", "a" * 32,
            "sha256:" + "b" * 64, "host.tailnet.invalid")

  def test_discovery_probe_retries_until_service_ready_with_bounded_attempts(self):
    host = "host.tailnet.invalid"
    payload = remote_test_host.json.dumps({
        "issuer": "https://" + host + "/realms/master"}).encode()
    class Response:
      status = 200
      def __enter__(self):
        return self
      def __exit__(self, *_args):
        return False
      def read(self):
        return payload
    with mock.patch.object(remote_test_host.urllib.request, "urlopen",
        side_effect=[OSError("not ready"), Response()]) as open_url, \
        mock.patch("time.sleep") as sleep:
      result = remote_test_host.probe_discovery(host, attempts=2)
    self.assertEqual({"http_status": 200, "issuer_matches": True}, result)
    self.assertEqual(2, open_url.call_count)
    sleep.assert_called_once()

  def test_teardown_verifies_exact_container_id_absence_after_removal(self):
    run_id, image_id, container_id = "a" * 32, "sha256:" + "b" * 64, "c" * 64
    record = {"Id": container_id, "Image": image_id, "Config": {"Labels": {
        "io.decent.lifecycle.run-id": run_id,
        "io.decent.lifecycle.image-id": image_id}}}
    commands = []
    def target_run(args, **_kwargs):
      commands.append(args)
      result = 1 if args[:3] == ["podman", "container", "exists"] and args[-1] == container_id else 0
      return remote_test_host.subprocess.CompletedProcess(args, result, "", "")
    with mock.patch.object(remote_test_host, "_assert_target_identity", return_value="host.tailnet"), \
        mock.patch.object(remote_test_host, "_target_container", side_effect=[record, None]), \
        mock.patch.object(remote_test_host, "_target_serve_status",
            side_effect=["https://host.tailnet (tailnet only)\n|-- / proxy http://127.0.0.1:8080",
                "no serve config"]), \
        mock.patch.object(remote_test_host, "_target_image_ref_id", return_value=None), \
        mock.patch.object(remote_test_host, "_target_run", side_effect=target_run):
      result = remote_test_host._target_operation("teardown", run_id, image_id,
          "host.tailnet")
    self.assertTrue(result["container_absent"])
    self.assertTrue(result["serve_absent"])
    self.assertTrue(result["run_image_refs_absent"])
    self.assertEqual([], result["removed_image_refs"])
    self.assertIn(["podman", "rm", "--force", container_id], commands)
    self.assertIn(["podman", "container", "exists", container_id], commands)

  def test_serve_route_ownership_requires_exact_single_tailnet_route(self):
    host = "host.tailnet.invalid"
    owned_route = ("https://host.tailnet.invalid (tailnet only)\n"
        "|-- / proxy http://127.0.0.1:8080")
    self.assertTrue(remote_test_host._target_serve_owned_only(owned_route, host))
    self.assertTrue(remote_test_host._target_serve_owned_only(
        "Available within your tailnet:\nhttps://host.tailnet.invalid:443/\n"
        "|-- proxy http://127.0.0.1:8080", host))
    self.assertFalse(remote_test_host._target_serve_owned_only(
        owned_route + "\n|-- /metrics proxy http://127.0.0.1:9090", host))
    self.assertFalse(remote_test_host._target_serve_owned_only(
        owned_route.replace(host, host + ".evil"), host))

  def test_teardown_removes_and_verifies_only_run_scoped_image_refs(self):
    run_id, image_id = "a" * 32, "sha256:" + "b" * 64
    refs = [remote_test_host.target_tag(run_id), remote_test_host.source_tag(run_id)]
    states = {ref: [image_id, None] for ref in refs}
    commands = []
    def inspect_ref(ref):
      return states[ref].pop(0)
    def target_run(args, **_kwargs):
      commands.append(args)
      return remote_test_host.subprocess.CompletedProcess(args, 0, "", "")
    with mock.patch.object(remote_test_host, "_target_image_ref_id", side_effect=inspect_ref), \
        mock.patch.object(remote_test_host, "_target_run", side_effect=target_run):
      removed = remote_test_host._target_remove_run_image_refs(run_id, image_id)
    self.assertEqual(refs, removed)
    self.assertEqual([["podman", "image", "rm", ref] for ref in refs], commands)

  def test_teardown_preserves_run_scoped_image_ref_with_different_image_id(self):
    run_id, image_id = "a" * 32, "sha256:" + "b" * 64
    with mock.patch.object(remote_test_host, "_target_image_ref_id", return_value="sha256:" + "c" * 64), \
        mock.patch.object(remote_test_host, "_target_run") as run:
      with self.assertRaisesRegex(RuntimeError, "ownership_mismatch"):
        remote_test_host._target_remove_run_image_refs(run_id, image_id)
    run.assert_not_called()

  def test_run_target_requires_verified_remote_teardown_readbacks(self):
    output = remote_test_host.json.dumps({"ok": True,
        "container_absent": True, "serve_absent": True}).encode()
    result = remote_test_host.subprocess.CompletedProcess([], 0, output, b"")
    with mock.patch.object(remote_test_host.subprocess, "run", return_value=result):
      with self.assertRaisesRegex(RuntimeError, "readback_incomplete"):
        remote_test_host.run_target("ben@host.tailnet.invalid", "teardown",
            "a" * 32, "sha256:" + "b" * 64, host="host.tailnet.invalid")

  def test_target_identity_mismatch_prevents_any_teardown_inspection(self):
    with mock.patch.object(remote_test_host, "_assert_target_identity",
        side_effect=RuntimeError("target_identity_mismatch")), \
        mock.patch.object(remote_test_host, "_target_container") as container, \
        mock.patch.object(remote_test_host, "_target_run") as run:
      with self.assertRaisesRegex(RuntimeError, "target_identity_mismatch"):
        remote_test_host._target_operation("teardown", "a" * 32,
            "sha256:" + "b" * 64, "host.tailnet.invalid")
    container.assert_not_called()
    run.assert_not_called()

  def test_target_script_never_accepts_a_bootstrap_password_argument(self):
    self.assertNotIn("bootstrap_password", remote_test_host.TARGET_ARGUMENTS)


if __name__ == "__main__":
  unittest.main()
