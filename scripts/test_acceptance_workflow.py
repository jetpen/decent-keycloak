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
