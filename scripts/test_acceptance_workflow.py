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

  def test_both_documented_unittest_commands_include_workflow_guard(self):
    import re

    readme = (ROOT / "README.md").read_text()
    commands = []
    for line in readme.splitlines():
      if line.startswith("python") and " -m unittest" in line:
        commands.append([])
      elif commands and line.strip() == "```":
        continue
      elif commands and line.strip().endswith("-q"):
        commands[-1].append(line)
      elif commands and line.strip():
        commands[-1].append(line)
    self.assertGreaterEqual(len(commands), 2)
    for command_lines in commands:
      self.assertIn("scripts.test_acceptance_workflow", " ".join(command_lines))


if __name__ == "__main__":
  unittest.main()
