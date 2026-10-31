"""Workflow guardrails for the wallet-login acceptance job."""

from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]


class AcceptanceWorkflowTest(unittest.TestCase):
  def test_checkout_does_not_persist_github_token_into_build_steps(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    checkout = workflow.split("      - name: Check out source\n", 1)[1].split(
        "      - name: Set up the supported JDK\n", 1)[0]

    self.assertIn("uses: actions/checkout@", checkout)
    self.assertIn("persist-credentials: false", checkout)

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
    local_checks = readme.split("## Local checks", 1)[1].split(
        "## Issue #6 expiry-profile", 1)[0]

    self.assertIn("python3.11 scripts/lifecycle.py run offline", local_checks)
    self.assertNotIn("podman build ", local_checks)
  def test_acceptance_workflow_uses_the_shared_ci_profile(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    lifecycle = (ROOT / "scripts/lifecycle.py").read_text()

    self.assertIn("run: python scripts/lifecycle.py run ci", workflow)
    self.assertIn('"scripts.test_lifecycle"', lifecycle)
    self.assertIn("python-tests", lifecycle)
    self.assertIn("python-compile", lifecycle)


if __name__ == "__main__":
  unittest.main()
