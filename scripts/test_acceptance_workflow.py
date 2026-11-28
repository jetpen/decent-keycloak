"""Workflow guardrails for the wallet-login acceptance job."""

from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]


class AcceptanceWorkflowTest(unittest.TestCase):
  def test_checkout_does_not_persist_github_token_into_build_steps(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    checkout = workflow.split("      - name: Check out source\n", 1)[1].split(
        "      - name: Set up Java 21\n", 1)[0]

    self.assertIn("uses: actions/checkout@", checkout)
    self.assertIn("persist-credentials: false", checkout)

  def test_workflow_is_limited_to_read_only_setup_and_offline_acceptance(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    lines = workflow.splitlines()
    permissions = workflow.split("permissions:\n", 1)[1].split("\nconcurrency:", 1)[0]
    self.assertEqual("  contents: read\n", permissions)

    uses = [line.strip()[6:] for line in lines if line.strip().startswith("uses:")]
    self.assertEqual([
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        "actions/setup-java@b843ebf9b913146b38da2eaa7aeddf76074ae1ad # v6.1.0",
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0",
    ], uses)

    run_commands = [line.strip()[5:] for line in lines if line.strip().startswith("run:")]
    self.assertEqual([
        "python -m pip install --require-hashes -r requirements/issue8-oidc.lock",
        "./keycloakctl acceptance --profile offline",
    ], run_commands)
    self.assertIn("persist-credentials: false", workflow)
    self.assertNotIn("secrets.", workflow)
    self.assertNotIn("GITHUB_TOKEN", workflow)

  def test_pr_workflow_checks_commits_while_local_runs_check_the_worktree(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    lifecycle = (ROOT / "scripts/lifecycle.py").read_text()
    events = workflow.split("permissions:", 1)[0]

    self.assertNotIn("  push:", events)
    self.assertIn("  pull_request:", events)
    self.assertIn('os.environ.get("PR_BASE_SHA")', lifecycle)
    self.assertIn('f"{pull_request_base}...HEAD"', lifecycle)
    self.assertIn('["git", "diff", "--check", "HEAD"]', lifecycle)
    self.assertIn('["git", "ls-files", "--others", "--exclude-standard", "-z"]', lifecycle)
    self.assertIn('"--no-index", "--check"', lifecycle)

  def test_provider_image_build_uses_repository_dockerfile_path(self):
    lifecycle = (ROOT / "scripts/lifecycle.py").read_text()

    self.assertIn('"--file", "container/Dockerfile"', lifecycle)
    self.assertIn('"--target", "runtime"', lifecycle)

  def test_provider_image_build_is_network_isolated(self):
    lifecycle = (ROOT / "scripts/lifecycle.py").read_text()

    self.assertEqual(2, lifecycle.count('"--network=none"'))

  def test_resolver_sources_are_run_scoped_and_cleaned_up(self):
    lifecycle = (ROOT / "scripts/lifecycle.py").read_text()

    self.assertIn("tempfile.TemporaryDirectory", lifecycle)
    self.assertIn("--materialize-sources", lifecycle)
    self.assertIn("source_parent.cleanup()", lifecycle)
    self.assertIn("finally:", lifecycle)

  def test_local_checks_use_the_shared_lifecycle_instead_of_duplicate_image_builds(self):
    readme = (ROOT / "README.md").read_text()
    local_checks = readme.split("## Build and verify locally", 1)[1].split(
        "## Build an installable local image", 1)[0]

    self.assertIn("./keycloakctl acceptance --profile offline", local_checks)
    self.assertNotIn("podman build ", local_checks)
  def test_acceptance_job_does_not_set_up_an_unused_container_engine(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()

    self.assertNotIn("docker/setup-buildx-action", workflow)
    self.assertNotIn("CONTAINER_ENGINE:", workflow)
    self.assertIn("- name: Run keycloakctl acceptance stages", workflow)

  def test_acceptance_workflow_uses_the_shared_offline_profile(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    lifecycle = (ROOT / "scripts/lifecycle.py").read_text()

    self.assertIn("run: ./keycloakctl acceptance --profile offline", workflow)
    self.assertIn('"scripts.test_lifecycle"', lifecycle)
    self.assertIn("python-tests", lifecycle)
    self.assertIn("python-compile", lifecycle)

  def test_acceptance_workflow_requests_java_21_without_a_patch_pin(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()

    self.assertIn("java-version: '21'", workflow)
    self.assertNotIn("21.0.12.1+1", workflow)


if __name__ == "__main__":
  unittest.main()
