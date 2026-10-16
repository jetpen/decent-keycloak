from __future__ import annotations

import unittest
from pathlib import Path

PROJECT = Path(__file__).parents[1]


class OwnerRotationEnvelopeTest(unittest.TestCase):
  @staticmethod
  def function_source(source: str, name: str) -> str:
    import ast
    module = ast.parse(source)
    node = next(item for item in module.body
        if isinstance(item, ast.FunctionDef) and item.name == name)
    segment = ast.get_source_segment(source, node)
    if segment is None:
      raise AssertionError(f'missing source segment for {name}')
    return segment

  def test_disposable_rotation_uses_exact_versioned_predecessor_state_hash(self):
    helper = (PROJECT / 'scripts/rotation_registry_roundtrip.py').read_text()
    module = __import__('ast').parse(helper)
    node = next(item for item in module.body
        if isinstance(item, __import__('ast').AsyncFunctionDef) and item.name == 'rotate_and_confirm')
    rotate_source = __import__('ast').get_source_segment(helper, node)
    self.assertIsNotNone(rotate_source)
    assert rotate_source is not None
    self.assertIn('predecessor_signed_update(', rotate_source)
    self.assertIn('state_fields(predecessor)', rotate_source)
    self.assertIn('draft_identity_bundle(', rotate_source)
    self.assertIn('OPERATION_OWNER_KEY_ROTATION', rotate_source)
    self.assertIn('predecessor_state_hash=predecessor_hash', rotate_source)
    self.assertIn('finalized_envelope_cbor=envelope', rotate_source)
    self.assertIn('put_identity(', rotate_source)
    self.assertIn('get_identity_record(', rotate_source)
    self.assertIn('observed.seq == expected_seq', rotate_source)
    self.assertIn('observed.owner_public_key_hex == expected_key', rotate_source)
    main = self.function_source(helper, 'main')
    self.assertIn('trio.run(rotate_and_confirm, args)', main)


if __name__ == '__main__':
  unittest.main()
