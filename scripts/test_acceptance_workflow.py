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

  def test_push_validation_checks_all_commits_since_the_previous_ref(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    validation = workflow.split("      - name: Validate the submitted diff\n", 1)[1]

    self.assertIn("PUSH_BASE_SHA: ${{ github.event.before }}", validation)
    pr_base = 'if [ -n "$PR_BASE_SHA" ]'
    push_base = 'elif [ -n "$PUSH_BASE_SHA" ]'
    self.assertLess(validation.index(pr_base), validation.index(push_base))
    self.assertIn('git diff --check "$PR_BASE_SHA...HEAD"', validation)
    self.assertIn('git diff --check "$PUSH_BASE_SHA...HEAD"', validation)
    self.assertIn('"0000000000000000000000000000000000000000"', validation)
    self.assertIn("git diff --check HEAD^ HEAD", validation)

  def test_provider_image_build_uses_repository_dockerfile_path(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    build = workflow.split("      - name: Build and check the immutable-base provider image\n", 1)[1]
    self.assertIn("--file container/Dockerfile", build)

  def test_provider_image_build_is_network_isolated(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    build = workflow.split("      - name: Build and check the immutable-base provider image\n", 1)[1]
    command = build.split("docker buildx build", 1)[1].split("version_output", 1)[0]

    self.assertIn("--network=none", command)

  def test_documented_local_image_builds_are_network_isolated(self):
    readme = (ROOT / "README.md").read_text()
    local_checks = readme.split("## Local checks", 1)[1].split(
        "### Disposable local integration probe", 1)[0]
    build_commands = [line for line in local_checks.splitlines()
        if line.lstrip().startswith("podman build ")]

    self.assertEqual(2, len(build_commands))
    self.assertTrue(all("--network=none" in command for command in build_commands))

  def test_acceptance_job_and_documented_commands_have_same_unique_modules(self):
    workflow = (ROOT / ".github/workflows/acceptance.yml").read_text()
    readme = (ROOT / "README.md").read_text()
    import re

    commands = re.findall(r"python3(?:\.11)? -m unittest \\\n(.*?) -q", readme, re.DOTALL)
    self.assertEqual(2, len(commands), "README must document both interpreter variants")
    documented_lists = [re.findall(r"scripts\.test_[a-z0-9_]+", command) for command in commands]
    for documented in documented_lists:
      self.assertEqual(len(documented), len(set(documented)), "documented test modules must be unique")
    job = workflow.split("      - name: Run the Python acceptance harness\n", 1)[1].split(
        "      - name: Compile Python sources\n", 1)[0]
    configured = re.findall(r"scripts\.test_[a-z0-9_]+", job)
    self.assertEqual(len(configured), len(set(configured)))
    for documented in documented_lists:
      self.assertEqual(set(documented), set(configured))


if __name__ == "__main__":
  unittest.main()
