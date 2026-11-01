"""Allowlisted test-only hostile-peer cases and repository-owned runtime inputs."""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ISSUE5_ADVERSARIAL_CASES = (
    ('malformed_result', 'hostile-peer-malformed'),
    ('history_incomplete', 'hostile-peer-history-incomplete'),
    ('ambiguous_registry_result', 'hostile-peer-ambiguous'),
    ('mixed_legacy_rotated_head', 'hostile-peer-mixed-head'),
)
ISSUE5_ADVERSARIAL_CASE_NAMES = frozenset(case for case, _label in ISSUE5_ADVERSARIAL_CASES)
ISSUE5_ADVERSARIAL_FIXTURE_LABELS = frozenset(label for _case, label in ISSUE5_ADVERSARIAL_CASES)


def input_hashes():
  """Return hashes for every repository-owned runtime/test payload input."""
  files = {
      'runtime_patcher': ROOT / 'container/patch_resolver_runtime.py',
      'pinned_lookup_outcomes': ROOT / 'container/pinned_lookup_outcomes.py',
      'rotation_helper': ROOT / 'container/rotation_registry_roundtrip.py',
      'adversarial_fixture': ROOT / 'scripts/test_pinned_adversarial_identity_peer.py',
      'adversarial_case_constants': Path(__file__),
  }
  return {name: {
      'file': str(path.relative_to(ROOT)),
      'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
  } for name, path in files.items()}
