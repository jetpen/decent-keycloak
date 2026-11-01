"""Offline loopback regression for fresh-reader owner-key rotation resolution."""
from __future__ import annotations

import argparse
import socket
import sys
import tempfile
import unittest
from pathlib import Path

import trio
from decent_identity.identity_resolver import get_identity_record
from decent_registry.crypto_utils import (
  load_ed25519_keypair_from_privkey_pem_path,
  write_ed25519_private_key_pem,
)
from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
from decent_registry.durable_store import LMDBDatastore
from decent_registry.registry_service import RegistryService

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rotation_registry_roundtrip import rotate_and_confirm


def peer_address(registry: Libp2pKadDHT) -> str:
  address = registry.get_listen_multiaddr()
  if '/p2p/' not in address:
    address = f'{address}/p2p/{registry.host.get_id().to_string()}'
  return address


def free_port() -> int:
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(('127.0.0.1', 0))
    return sock.getsockname()[1]


async def rotation_roundtrip(tmp_path: Path, repeat: bool = False,
    failure: str | None = None, subprocess_repeat: bool = False):
  identifier = 'rotation-roundtrip@example.invalid'
  old_key = tmp_path / 'old-owner.pem'
  new_key = tmp_path / 'new-owner.pem'
  write_ed25519_private_key_pem(old_key)
  write_ed25519_private_key_pem(new_key)
  _, expected_key = load_ed25519_keypair_from_privkey_pem_path(str(new_key))
  async with Libp2pKadDHT(
    durable_store=LMDBDatastore(path=tmp_path / 'seed.lmdb'),
  ) as seed, Libp2pKadDHT(
    dht_mode=DHTMode.CLIENT,
    durable_store=LMDBDatastore(path=tmp_path / 'publisher.lmdb'),
  ) as publisher:
    bootstrap = peer_address(seed)
    await publisher.bootstrap(bootstrap)
    await RegistryService(dht=publisher).put_identity(
      owner_name_hex=identifier.encode('utf-8').hex(),
      owner_privkey_pem_path=str(old_key), seq=1,
    )
    args = argparse.Namespace(
      identifier=identifier, old_key=old_key, new_key=new_key,
      host='127.0.0.1', port=free_port(), bootstrap=bootstrap,
      datastore=tmp_path / 'rotation-client.lmdb',
      envelope=tmp_path / 'rotation-envelope.cbor',
      readback=tmp_path / 'rotation-readback.txt',
      checkpoint=tmp_path / 'rotation-checkpoint.json',
    )
    await rotate_and_confirm(args)
    # A second independent fresh client must authenticate the remote chain too.
    result = await get_identity_record(
      identifier=identifier, host='127.0.0.1', port=0, bootstrap=[bootstrap],
    )
    assert result is not None
    assert result.seq == 2
    assert result.owner_public_key_hex == bytes(expected_key).hex()
    assert args.envelope.read_bytes()
    assert args.readback.read_text().splitlines() == ['2', bytes(expected_key).hex()]
    if repeat:
      successor_key = tmp_path / 'successor-owner.pem'
      write_ed25519_private_key_pem(successor_key)
      _, successor_public = load_ed25519_keypair_from_privkey_pem_path(str(successor_key))
      repeated = argparse.Namespace(
        identifier=identifier, old_key=new_key, new_key=successor_key,
        authorizing_keys=[old_key], host='127.0.0.1', port=free_port(), bootstrap=bootstrap,
        datastore=tmp_path / 'repeated-client.lmdb',
        envelope=tmp_path / 'repeated-envelope.cbor',
        readback=tmp_path / 'repeated-readback.txt',
        checkpoint=tmp_path / 'repeated-checkpoint.json',
      )
      if failure is not None:
        from unittest.mock import AsyncMock, patch
        if failure == 'missing_quorum':
          repeated.authorizing_keys = []
          expected_error = ValueError
          message = 'insufficient quorum'
        elif failure == 'missing_history':
          expected_error = RuntimeError
          message = 'complete predecessor history is required'
        elif failure in {'duplicate_key', 'wrong_key'}:
          repeated.authorizing_keys = [old_key, old_key] if failure == 'duplicate_key' else [successor_key]
          expected_error = ValueError
          message = ('duplicate rotation authorization key' if failure == 'duplicate_key'
            else 'rotation authorization key is not a predecessor signer')
        elif failure == 'tampered_history':
          expected_error = ValueError
          message = 'invalid legacy owner signature'
        else:
          raise AssertionError('unknown test scenario')
        import contextlib
        with contextlib.ExitStack() as stack:
          publish = stack.enter_context(patch(
            'decent_identity.identity_resolver.put_identity', new_callable=AsyncMock))
          if failure == 'missing_history':
            stack.enter_context(patch.object(RegistryService, 'get_identity_envelope_by_hash',
              new_callable=AsyncMock, return_value=None))
          if failure == 'tampered_history':
            original_read = RegistryService.get_identity_envelope_by_hash
            async def tampered_read(service, **kwargs):
              value = await original_read(service, **kwargs)
              assert value is not None
              return value[:-1] + bytes([value[-1] ^ 1])
            stack.enter_context(patch.object(RegistryService, 'get_identity_envelope_by_hash', tampered_read))
          with unittest.TestCase().assertRaisesRegex(expected_error, message):
            await rotate_and_confirm(repeated)
          publish.assert_not_awaited()
        assert not repeated.envelope.exists()
        assert not repeated.readback.exists()
        unchanged = await get_identity_record(
          identifier=identifier, host='127.0.0.1', port=free_port(), bootstrap=[bootstrap])
        assert unchanged is not None and unchanged.seq == 2
        assert unchanged.owner_public_key_hex == bytes(expected_key).hex()
        return
      if subprocess_repeat:
        import json
        import os
        import subprocess
        command = [sys.executable, str(Path(__file__).with_name('rotation_registry_roundtrip.py')),
          '--identifier', identifier, '--old-key', str(new_key), '--new-key', str(successor_key),
          '--authorizing-key', str(old_key), '--host', '127.0.0.1', '--port', str(repeated.port),
          '--bootstrap', bootstrap, '--datastore', str(repeated.datastore),
          '--envelope', str(repeated.envelope), '--readback', str(repeated.readback),
          '--checkpoint', str(repeated.checkpoint)]
        environment = {key: os.environ[key] for key in ('PATH', 'PYTHONPATH', 'LD_LIBRARY_PATH', 'TMPDIR')
          if key in os.environ}
        environment['LANG'] = 'C.UTF-8'
        result = await trio.to_thread.run_sync(lambda: subprocess.run(
          command, env=environment, capture_output=True, timeout=60, check=False))
        failure_checkpoint = repeated.checkpoint.read_text() if repeated.checkpoint.exists() else 'missing'
        assert result.returncode == 0, f'scrubbed subprocess rotation failed: {failure_checkpoint}'
        assert json.loads(repeated.checkpoint.read_text()) == {'stage': 'complete', 'status': 'passed'}
      else:
        await rotate_and_confirm(repeated)
      fresh = await get_identity_record(
        identifier=identifier, host='127.0.0.1', port=free_port(), bootstrap=[bootstrap],
      )
      assert fresh is not None
      assert fresh.seq == 3
      assert fresh.owner_public_key_hex == bytes(successor_public).hex()
      assert repeated.readback.read_text().splitlines() == ['3', bytes(successor_public).hex()]
      from decent_registry.signed_envelope import decode_multisignature_envelope
      from decent_registry.encoding import decode_multisignature_signed_update
      first_envelope = decode_multisignature_envelope(args.envelope.read_bytes())
      second_envelope = decode_multisignature_envelope(repeated.envelope.read_bytes())
      first_auth = decode_multisignature_signed_update(first_envelope.signed_update_bytes)[4]
      second_auth = decode_multisignature_signed_update(second_envelope.signed_update_bytes)[4]
      assert [second_auth[key] for key in (4, 5, 6)] == [first_auth[key] for key in (4, 5, 6)]
      assert {proof[1] for proof in second_envelope.proofs} == {'new-owner', 'old-owner'}


class RotationRegistryRoundtripTest(unittest.TestCase):
  def test_legacy_identity_rotation_publishes_and_resolves_successor(self):
    with tempfile.TemporaryDirectory(prefix='rotation-roundtrip-') as directory:
      trio.run(rotation_roundtrip, Path(directory))


  def test_repeated_rotation_preserves_authorization_and_resolves_sequence_three(self):
    with tempfile.TemporaryDirectory(prefix='rotation-repeat-') as directory:
      trio.run(rotation_roundtrip, Path(directory), True)


  def test_repeated_rotation_through_scrubbed_subprocess(self):
    with tempfile.TemporaryDirectory(prefix='rotation-subprocess-') as directory:
      trio.run(rotation_roundtrip, Path(directory), True, None, True)

  def test_missing_quorum_cannot_publish_or_change_current_identity(self):
    with tempfile.TemporaryDirectory(prefix='rotation-no-quorum-') as directory:
      trio.run(rotation_roundtrip, Path(directory), True, 'missing_quorum')

  def test_missing_history_cannot_publish_or_change_current_identity(self):
    with tempfile.TemporaryDirectory(prefix='rotation-no-history-') as directory:
      trio.run(rotation_roundtrip, Path(directory), True, 'missing_history')


  def test_duplicate_keys_cannot_publish_or_change_current_identity(self):
    with tempfile.TemporaryDirectory(prefix='rotation-duplicate-key-') as directory:
      trio.run(rotation_roundtrip, Path(directory), True, 'duplicate_key')

  def test_nonmember_key_cannot_publish_or_change_current_identity(self):
    with tempfile.TemporaryDirectory(prefix='rotation-wrong-key-') as directory:
      trio.run(rotation_roundtrip, Path(directory), True, 'wrong_key')

  def test_tampered_history_cannot_publish_or_change_current_identity(self):
    with tempfile.TemporaryDirectory(prefix='rotation-tampered-history-') as directory:
      trio.run(rotation_roundtrip, Path(directory), True, 'tampered_history')


if __name__ == '__main__':
  unittest.main()
