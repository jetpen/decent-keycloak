"""Loopback hostile-peer tests through the pinned Identity resolver path.

These tests deliberately bypass Registry publication by serving raw DHT GET_VALUE
records from local libp2p hosts. They characterize fail-closed resolver behavior;
they do not qualify a deployed Registry or Keycloak provider runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import asynccontextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

LIBP2P_SOURCE = os.environ.get("RESOLVER_TEST_LIBP2P_SOURCE")
if LIBP2P_SOURCE:
  sys.path.insert(0, LIBP2P_SOURCE)
REGISTRY_SOURCE = os.environ.get("RESOLVER_TEST_REGISTRY_SOURCE")
if REGISTRY_SOURCE:
  sys.path.insert(0, REGISTRY_SOURCE)
IDENTITY_SOURCE = os.environ.get("RESOLVER_TEST_IDENTITY_SOURCE")
if IDENTITY_SOURCE:
  sys.path.insert(0, IDENTITY_SOURCE)

import trio
import varint
from libp2p import new_host
from libp2p.custom_types import TProtocol
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.kad_dht.pinned_lookup_outcomes import DHTLookupUnavailable
from libp2p.kad_dht.pb.kademlia_pb2 import Message
from libp2p.peer.peerstore import env_to_send_in_RPC
from multiaddr import Multiaddr
from unittest.mock import patch

import decent_registry.dht.libp2p_dht as registry_module
from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.encoding import (
  OPERATION_ORDINARY_UPDATE,
  RECORD_KIND_IDENTITY,
  encode_multisignature_signed_update,
  encode_signed_update,
)
from decent_registry.signed_envelope import (
  encode_multisignature_envelope,
  encode_signed_envelope,
)
from decent_registry.verification import (
  make_signed_update_signature,
  verify_ed25519_signature,
)
from issue5_adversarial_cases import (
  ISSUE5_ADVERSARIAL_CASE_NAMES as ADVERSARIAL_CASE_NAMES,
)

DHT_PROTOCOL = TProtocol("/ipfs/kad/1.0.0")
MAX_RPC_FRAME = 4 * 1024 * 1024


async def _read_rpc_frame(stream: Any) -> bytes:
  length = bytearray()
  while len(length) < 5:
    byte = await stream.read(1)
    if not byte:
      raise EOFError("DHT request ended before frame length")
    length.extend(byte)
    if byte[0] < 0x80:
      break
  else:
    raise ValueError("DHT request frame length is overlong")

  frame_length = varint.decode_bytes(bytes(length))
  if frame_length < 1 or frame_length > MAX_RPC_FRAME:
    raise ValueError("DHT request frame length is outside the test bound")

  payload = bytearray()
  while len(payload) < frame_length:
    chunk = await stream.read(frame_length - len(payload))
    if not chunk:
      raise EOFError("DHT request ended before its frame was complete")
    payload.extend(chunk)
  return bytes(payload)


class AdversarialRegistryPeer:
  """Serve raw, preselected DHT values over a real loopback libp2p host."""

  def __init__(self, values: dict[bytes, bytes], on_request=None) -> None:
    self._values = {bytes(key): bytes(value) for key, value in values.items()}
    self._on_request = on_request
    self._host = new_host(enable_tcp=True)
    self._host_context: Any | None = None
    self._closer_peers: tuple["AdversarialRegistryPeer", ...] = ()
    self.requests: list[tuple[int, bytes]] = []

  async def start(self) -> None:
    self._host.set_stream_handler(DHT_PROTOCOL, self._handle_stream)
    self._host_context = self._host.run(
      listen_addrs=[Multiaddr("/ip4/127.0.0.1/tcp/0")]
    )
    await self._host_context.__aenter__()

  @property
  def bootstrap_address(self) -> str:
    addresses = self._host.get_addrs()
    if not addresses:
      raise RuntimeError("loopback peer has no listening address")
    return f"{addresses[0]}/p2p/{self._host.get_id()}"

  def advertise(self, peers: list["AdversarialRegistryPeer"]) -> None:
    self._closer_peers = tuple(peer for peer in peers if peer is not self)

  async def close(self) -> None:
    if self._host_context is not None:
      context, self._host_context = self._host_context, None
      await context.__aexit__(None, None, None)
    await self._host.close()

  async def _handle_stream(self, stream: Any) -> None:
    try:
      request = Message()
      request.ParseFromString(await _read_rpc_frame(stream))
      self.requests.append((request.type, bytes(request.key)))
      if self._on_request is not None:
        self._on_request(request.type, bytes(request.key))

      response = Message()
      response.type = request.type
      response.key = request.key
      response.senderRecord, _ = env_to_send_in_RPC(self._host)

      if request.type == Message.MessageType.GET_VALUE:
        value = self._values.get(bytes(request.key))
        if value is not None:
          response.record.key = request.key
          response.record.value = value
          response.record.timeReceived = str(time.time())
      elif request.type == Message.MessageType.FIND_NODE:
        for peer in self._closer_peers:
          peer_proto = response.closerPeers.add()
          peer_proto.id = peer._host.get_id().to_bytes()
          peer_proto.addrs.extend(
            address.to_bytes() for address in peer._host.get_addrs()
          )
          peer_proto.signedRecord, _ = env_to_send_in_RPC(peer._host)
      else:
        return

      payload = response.SerializeToString()
      await stream.write(varint.encode(len(payload)) + payload)
    finally:
      await stream.close()


@asynccontextmanager
async def _adversarial_peers(values: list[dict[bytes, bytes]], on_request=None):
  peers: list[AdversarialRegistryPeer] = []
  try:
    for index, value_map in enumerate(values):
      callback = None if on_request is None else (
          lambda message_type, key, index=index: on_request(index, message_type, key))
      peer = AdversarialRegistryPeer(value_map, on_request=callback)
      await peer.start()
      peers.append(peer)
    for peer in peers:
      peer.advertise(peers)
    yield peers
  finally:
    close_errors = []
    for peer in reversed(peers):
      try:
        await peer.close()
      except Exception as exc:
        close_errors.append(exc)
    if close_errors:
      raise RuntimeError("one or more loopback Registry peers failed to close") from close_errors[0]


def _legacy_identity_envelope(owner_name: bytes, key_pair: Any) -> bytes:
  signed_update = encode_signed_update(
    record_fields={1: owner_name, 2: key_pair.public_key.to_bytes()},
    payload={},
    seq=1,
  )
  signature = make_signed_update_signature(
    signed_update_bytes_canonical=signed_update,
    owner_private_key=key_pair.private_key,
  )
  return encode_signed_envelope(
    signed_update_bytes=signed_update,
    signature=signature,
  )


def _unlinked_identity_successor(owner_name: bytes, key_pair: Any) -> tuple[bytes, bytes, bytes]:
  owner_public_key = key_pair.public_key.to_bytes()
  update = encode_multisignature_signed_update(
    record_fields={1: owner_name, 2: owner_public_key},
    payload={},
    seq=2,
    authorization={
      1: 1,
      2: RECORD_KIND_IDENTITY,
      3: OPERATION_ORDINARY_UPDATE,
      4: 1,
      5: 1,
      6: [{1: "owner", 2: owner_public_key}],
      7: hashlib.sha256(b"unavailable predecessor fixture").digest(),
    },
  )
  signature = make_signed_update_signature(
    signed_update_bytes_canonical=update,
    owner_private_key=key_pair.private_key,
  )
  envelope = encode_multisignature_envelope(
    signed_update_bytes=update,
    proofs=[{1: "owner", 2: signature}],
  )
  return envelope, update, signature


class ThreadedAdversarialPeers:
  def __init__(self, peer_values: list[dict[bytes, bytes]], on_request=None) -> None:
    self._peer_values = peer_values
    self._on_request = on_request
    self._ready = threading.Event()
    self._stop = threading.Event()
    self._thread: threading.Thread | None = None
    self._peers: list[AdversarialRegistryPeer] = []
    self.addresses: list[str] = []
    self.error: BaseException | None = None

  def start(self) -> list[str]:
    def run_server() -> None:
      async def serve() -> None:
        async with _adversarial_peers(self._peer_values, self._on_request) as peers:
          self._peers = peers
          self.addresses = [peer.bootstrap_address for peer in peers]
          self._ready.set()
          await trio.to_thread.run_sync(self._stop.wait)

      try:
        trio.run(serve)
      except BaseException as exc:
        self.error = exc
        self._ready.set()

    self._thread = threading.Thread(target=run_server, daemon=True)
    self._thread.start()
    if not self._ready.wait(timeout=10):
      self._stop.set()
      if self._thread is not None:
        self._thread.join(timeout=10)
        if self._thread.is_alive():
          raise TimeoutError("loopback Registry peers did not stop after startup timeout")
      raise TimeoutError("loopback Registry peers did not become ready")
    if self.error is not None:
      raise RuntimeError("loopback Registry peer startup failed") from self.error
    return self.addresses

  def requests(self) -> tuple[tuple[tuple[int, bytes], ...], ...]:
    return tuple(tuple(peer.requests) for peer in self._peers)

  def close(self) -> None:
    self._stop.set()
    if self._thread is not None:
      self._thread.join(timeout=10)
      if self._thread.is_alive():
        raise TimeoutError("loopback Registry peers did not stop")
    if self.error is not None:
      raise RuntimeError("loopback Registry peer stopped with an error") from self.error


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
  temporary = path.with_name(path.name + ".tmp")
  temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
  os.replace(temporary, path)


def _linked_rotation_values(owner_name, old_owner, successor):
  from decent_registry.encoding import OPERATION_OWNER_KEY_ROTATION
  from decent_registry.multisig_bundle import draft_identity_bundle
  from decent_registry.signed_envelope import decode_signed_envelope

  predecessor = _legacy_identity_envelope(owner_name, old_owner)
  previous_update, _ = decode_signed_envelope(predecessor)
  previous_hash = hashlib.sha256(previous_update).digest()
  bundle = draft_identity_bundle(
    owner_name=owner_name, owner_public_key=successor.public_key.to_bytes(), seq=2,
    signer_set=[{1: 'old', 2: old_owner.public_key.to_bytes()},
      {1: 'new', 2: successor.public_key.to_bytes()},
      {1: 'cosigner', 2: create_new_key_pair().public_key.to_bytes()}],
    threshold=2, epoch=1, predecessor_state_hash=previous_hash,
    operation=OPERATION_OWNER_KEY_ROTATION,
  )
  proof = make_signed_update_signature(
    signed_update_bytes_canonical=bundle.signed_update_bytes,
    owner_private_key=old_owner.private_key,
  )
  envelope = encode_multisignature_envelope(
    signed_update_bytes=bundle.signed_update_bytes, proofs=[{1: None, 2: proof}],
  )
  object_key = hashlib.sha256(owner_name).digest()
  current_key = f'/decent-registry/identity/{object_key.hex()}'.encode()
  history_key = b'/decent-registry/history/' + object_key + previous_hash
  return {current_key: envelope, history_key: predecessor}


def _adversarial_fixture_values(case_name: str, owner_name: bytes, seed: bytes):
  if case_name not in ADVERSARIAL_CASE_NAMES:
    raise ValueError("unsupported hostile-peer fixture case")
  record_key = f"/decent-registry/identity/{hashlib.sha256(owner_name).hexdigest()}".encode()
  owner_pair = create_new_key_pair(seed)
  if case_name == "malformed_result":
    return [{record_key: bytes([0xff]) + b"malformed-identity-envelope"}], seed
  if case_name == "history_incomplete":
    envelope, _, _ = _unlinked_identity_successor(owner_name, owner_pair)
    return [{record_key: envelope}], seed
  if case_name == "ambiguous_registry_result":
    alternate_pair = create_new_key_pair(secrets.token_bytes(32))
    return [
      {record_key: _legacy_identity_envelope(owner_name, owner_pair)},
      {record_key: _legacy_identity_envelope(owner_name, alternate_pair)},
    ], seed
  if case_name == "mixed_legacy_rotated_head":
    rotated = _linked_rotation_values(owner_name, owner_pair, create_new_key_pair())
    return [{record_key: _legacy_identity_envelope(owner_name, owner_pair)},
      {record_key: rotated[record_key]}], seed
  raise ValueError("unsupported hostile-peer fixture case")


def _serve_adversarial_peer(argv: list[str]) -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument("--config", required=True)
  parser.add_argument("--ready-file", required=True)
  parser.add_argument("--status-file", required=True)
  parser.add_argument("--stop-file", required=True)
  args = parser.parse_args(argv)
  config = json.loads(Path(args.config).read_text(encoding="utf-8"))
  case_name = config.get("case")
  identity_id = config.get("identity_id")
  key_file = Path(config.get("key_file", ""))
  if (case_name not in ADVERSARIAL_CASE_NAMES
      or not isinstance(identity_id, str) or not identity_id or len(identity_id) > 255
      or not key_file.is_absolute()):
    raise ValueError("invalid hostile-peer fixture configuration")

  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

  seed = secrets.token_bytes(32)
  owner_name = identity_id.encode("utf-8")
  peer_values, _ = _adversarial_fixture_values(case_name, owner_name, seed)
  private_key = Ed25519PrivateKey.from_private_bytes(seed)
  key_bytes = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
  )
  descriptor = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
  with os.fdopen(descriptor, "wb") as key_stream:
    key_stream.write(key_bytes)
  key_file.chmod(0o600)

  status_file = Path(args.status_file)
  stop_file = Path(args.stop_file)
  ready_file = Path(args.ready_file)
  counts = [0] * len(peer_values)
  count_lock = threading.Lock()
  target_key = f"/decent-registry/identity/{hashlib.sha256(owner_name).hexdigest()}".encode()

  def observe(index: int, message_type: int, requested_key: bytes) -> None:
    if message_type == Message.MessageType.GET_VALUE and requested_key == target_key:
      with count_lock:
        counts[index] += 1
        _atomic_json(status_file, {
          "peer_count": len(counts), "exact_key_gets": list(counts)})

  _atomic_json(status_file, {"peer_count": len(counts), "exact_key_gets": list(counts)})
  server = ThreadedAdversarialPeers(peer_values, on_request=observe)
  bootstrap_addresses = server.start()
  _atomic_json(ready_file, {
    "bootstrap_peers": bootstrap_addresses, "peer_count": len(bootstrap_addresses)})
  try:
    while not stop_file.exists():
      if server.error is not None:
        raise RuntimeError("hostile-peer fixture service failed")
      time.sleep(0.05)
  finally:
    server.close()
    with count_lock:
      _atomic_json(status_file, {"peer_count": len(counts), "exact_key_gets": list(counts)})


def serve_adversarial_peer(argv: list[str]) -> None:
  try:
    _serve_adversarial_peer(argv)
  except BaseException:
    # Do not leak synthetic identities, private keys, DHT values, or raw exceptions.
    raise SystemExit(2) from None


class AdversarialRegistryResolverTest(unittest.TestCase):
  def setUp(self) -> None:
    if not all((LIBP2P_SOURCE, REGISTRY_SOURCE, IDENTITY_SOURCE)):
      self.skipTest("pinned libp2p, Identity, and Registry paths are required")

  def test_service_mode_publishes_readiness_and_stops_cleanly(self) -> None:
    identity_id = 'service-fixture@example.invalid'
    with tempfile.TemporaryDirectory(prefix='issue5-peer-service-') as temp:
      root = Path(temp)
      config = root / 'fixture.json'
      ready = root / 'ready.json'
      status = root / 'status.json'
      stop = root / 'stop'
      private_key = root / 'owner.pem'
      config.write_text(json.dumps({
        'case': 'ambiguous_registry_result', 'identity_id': identity_id,
        'key_file': str(private_key)}, sort_keys=True), encoding='utf-8')
      process = subprocess.Popen([
        sys.executable, str(Path(__file__).resolve()), 'serve',
        '--config', str(config), '--ready-file', str(ready),
        '--status-file', str(status), '--stop-file', str(stop),
      ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
      try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not ready.exists():
          if process.poll() is not None:
            self.fail('hostile-peer fixture exited before readiness')
          time.sleep(0.05)
        self.assertTrue(ready.exists(), 'hostile-peer fixture readiness timeout')
        readiness = json.loads(ready.read_text(encoding='utf-8'))
        bootstrap_peers = readiness['bootstrap_peers']
        self.assertEqual(2, readiness['peer_count'])
        self.assertEqual(2, len(bootstrap_peers))
        self.assertTrue(all(address.startswith('/ip4/127.0.0.1/tcp/')
            for address in bootstrap_peers))
        self.assertEqual(0o600, stat.S_IMODE(private_key.stat().st_mode))
        self.assertEqual({'peer_count': 2, 'exact_key_gets': [0, 0]},
            json.loads(status.read_text(encoding='utf-8')))
      finally:
        stop.touch(mode=0o600, exist_ok=True)
        try:
          process.wait(timeout=10)
        except subprocess.TimeoutExpired:
          process.kill()
          process.wait(timeout=5)
          self.fail('hostile-peer fixture did not stop')
      self.assertEqual(0, process.returncode)

  def _resolve(self, owner_name: bytes, peer_values: list[dict[bytes, bytes]]):
    from decent_identity.cli import main as identity_cli_main

    requested_key = (
      f"/decent-registry/identity/{hashlib.sha256(owner_name).hexdigest()}"
    ).encode()
    peer_server = ThreadedAdversarialPeers(peer_values)
    bootstrap = peer_server.start()
    captured_unavailable: list[DHTLookupUnavailable] = []
    original = Libp2pKadDHT._read_dht_value
    original_exit = Libp2pKadDHT.__aexit__

    async def capture_unavailable(adapter, *args, **kwargs):
      try:
        return await original(adapter, *args, **kwargs)
      except DHTLookupUnavailable as exc:
        captured_unavailable.append(exc)
        raise

    async def close_host_after_exit(adapter, *args):
      try:
        await original_exit(adapter, *args)
      finally:
        # The pinned context manager exits its Host.run context without
        # explicitly closing the libp2p Host; close it to bound test sockets.
        await adapter._host.close()

    stdout = io.StringIO()
    stderr = io.StringIO()
    argv = [
      "get",
      "--identifier",
      owner_name.decode("utf-8"),
      "--host",
      "127.0.0.1",
      "--port",
      "0",
    ]
    for _ in range(3):
      for address in bootstrap:
        argv.extend(("--bootstrap", address))
    exit_code = None
    try:
      with patch.object(Libp2pKadDHT, "_read_dht_value", capture_unavailable), patch.object(
        Libp2pKadDHT, "__aexit__", close_host_after_exit
      ):
        with redirect_stdout(stdout), redirect_stderr(stderr):
          try:
            identity_cli_main(argv)
          except SystemExit as exc:
            exit_code = exc.code
    finally:
      peer_server.close()
    return (
      (exit_code, stdout.getvalue(), stderr.getvalue(), len(captured_unavailable)),
      requested_key,
      peer_server.requests(),
    )

  def _assert_cli_unavailable(self, result) -> None:
    self.assertEqual(1, result[0])
    self.assertEqual("", result[1])
    self.assertTrue(result[2].endswith("get failed\n"), result[2])
    self.assertEqual(1, result[3])

  def _observe_validation(self, requested_key: bytes):
    original = registry_module._RegistryDHTValueValidator.validate
    observed: list[tuple[str, bytes]] = []

    def record_then_validate(validator, key, value):
      if key == requested_key.decode("utf-8"):
        observed.append((key, bytes(value)))
      return original(validator, key, value)

    return patch.object(
      registry_module._RegistryDHTValueValidator,
      "validate",
      record_then_validate,
    ), observed

  def test_malformed_identity_bytes_from_loopback_peer_are_unavailable(self):
    owner_name = b"synthetic-issue5-malformed"
    requested_key = (
      f"/decent-registry/identity/{hashlib.sha256(owner_name).hexdigest()}"
    ).encode()
    hostile_bytes = b"\xff\x00not-canonical-cbor"
    observer, validated_values = self._observe_validation(requested_key)

    with observer:
      result, actual_key, peer_requests = self._resolve(
        owner_name, [{requested_key: hostile_bytes}]
      )

    get_requests = [
      (peer_index, key)
      for peer_index, requests in enumerate(peer_requests)
      for message_type, key in requests
      if message_type == Message.MessageType.GET_VALUE
    ]
    self.assertEqual(actual_key, requested_key)
    self.assertEqual([(0, requested_key)], get_requests)
    self.assertEqual([(requested_key.decode(), hostile_bytes)], validated_values)
    self._assert_cli_unavailable(result)

  def test_non_genesis_identity_without_history_is_unavailable(self):
    owner_name = b"synthetic-issue5-history"
    record_key = hashlib.sha256(owner_name).digest()
    requested_key = (
      f"/decent-registry/identity/{record_key.hex()}"
    ).encode()
    key_pair = create_new_key_pair()
    envelope, signed_update, signature = _unlinked_identity_successor(
      owner_name, key_pair
    )
    self.assertTrue(
      verify_ed25519_signature(
        owner_public_key=key_pair.public_key.to_bytes(),
        signed_update_bytes_canonical=signed_update,
        signature=signature,
      )
    )
    observer, validated_values = self._observe_validation(requested_key)

    with observer:
      result, actual_key, peer_requests = self._resolve(
        owner_name, [{requested_key: envelope}]
      )

    get_requests = [
      (peer_index, key)
      for peer_index, requests in enumerate(peer_requests)
      for message_type, key in requests
      if message_type == Message.MessageType.GET_VALUE
    ]
    self.assertEqual(actual_key, requested_key)
    self.assertEqual([(0, requested_key)], [item for item in get_requests if item[1] == requested_key])
    self.assertEqual(1, sum(key.startswith(b'/decent-registry/history/') for _, key in get_requests))
    self.assertEqual([(requested_key.decode(), envelope)], validated_values)
    self._assert_cli_unavailable(result)

  def test_mixed_legacy_rotated_fixture_contains_unlinked_higher_head(self):
    owner_name = b'synthetic-fixture-mixed-head'
    seed = secrets.token_bytes(32)
    peer_values, returned_seed = _adversarial_fixture_values(
      'mixed_legacy_rotated_head', owner_name, seed)
    record_key = hashlib.sha256(owner_name).digest()
    current_key = f'/decent-registry/identity/{record_key.hex()}'.encode()
    self.assertEqual(seed, returned_seed)
    self.assertEqual(2, len(peer_values))
    legacy = peer_values[0][current_key]
    rotated = peer_values[1][current_key]
    self.assertNotEqual(legacy, rotated)
    self.assertNotIn(b'/decent-registry/history/' + record_key, peer_values[1])
    from decent_registry.encoding import decode_canonical_signed_update
    from decent_registry.signed_envelope import decode_signed_envelope, decode_multisignature_envelope
    legacy_update, _ = decode_signed_envelope(legacy)
    rotated_update = decode_multisignature_envelope(rotated).signed_update_bytes
    self.assertEqual(1, decode_canonical_signed_update(legacy_update)[3])
    self.assertEqual(2, decode_canonical_signed_update(rotated_update)[3])

  def test_mixed_peer_fixture_does_not_let_legacy_hide_unlinked_rotated_head(self):
    owner_name = b'synthetic-fixture-mixed-peer'
    peer_values, _ = _adversarial_fixture_values(
      'mixed_legacy_rotated_head', owner_name, secrets.token_bytes(32))
    requested_key = next(iter(peer_values[0]))
    result, actual_key, requests = self._resolve(owner_name, peer_values)
    self.assertEqual(requested_key, actual_key)
    self._assert_cli_unavailable(result)
    peer_head_reads = [key for peer in requests for message_type, key in peer
        if message_type == Message.MessageType.GET_VALUE and key == requested_key]
    history_reads = [key for peer in requests for message_type, key in peer
        if message_type == Message.MessageType.GET_VALUE
        and key.startswith(b'/decent-registry/history/')]
    self.assertEqual(2, len(peer_head_reads))
    self.assertTrue(history_reads)

  def test_equal_sequence_heads_from_two_peers_are_seen_and_rejected(self):
    owner_name = b"synthetic-issue5-conflict"
    record_key = hashlib.sha256(owner_name).digest()
    requested_key = (
      f"/decent-registry/identity/{record_key.hex()}"
    ).encode()
    first = _legacy_identity_envelope(owner_name, create_new_key_pair())
    second = _legacy_identity_envelope(owner_name, create_new_key_pair())
    self.assertNotEqual(first, second)

    from decent_registry.record_validator import RecordValidator

    validator = RecordValidator()
    validator.validate_identity_get(record_key=record_key, envelope_cbor=first)
    validator.validate_identity_get(record_key=record_key, envelope_cbor=second)

    original = registry_module._RegistryDHTValueValidator.select
    selected_values: list[tuple[str, tuple[bytes, ...]]] = []

    def observe_selection(registry_validator, key, values):
      if key == requested_key.decode("utf-8"):
        selected_values.append((key, tuple(bytes(value) for value in values)))
      return original(registry_validator, key, values)

    with patch.object(
      registry_module._RegistryDHTValueValidator,
      "select",
      observe_selection,
    ):
      result, actual_key, peer_requests = self._resolve(
        owner_name,
        [{requested_key: first}, {requested_key: second}],
      )

    get_requests = [
      (peer_index, key)
      for peer_index, requests in enumerate(peer_requests)
      for message_type, key in requests
      if message_type == Message.MessageType.GET_VALUE
    ]
    self.assertEqual(actual_key, requested_key)
    self.assertEqual(
      [(0, requested_key), (1, requested_key)],
      sorted(get_requests),
    )
    self.assertEqual(1, len(selected_values))
    self.assertEqual(requested_key.decode(), selected_values[0][0])
    self.assertCountEqual(
      [first, second],
      selected_values[0][1],
    )
    self._assert_cli_unavailable(result)


  def test_fresh_cli_authenticates_complete_owner_rotation_history(self):
    owner_name = b'synthetic-linked-rotation'
    successor = create_new_key_pair()
    values = _linked_rotation_values(owner_name, create_new_key_pair(), successor)
    result, _, _ = self._resolve(owner_name, [values])
    self.assertEqual(0, result[0])
    record = json.loads(result[1])
    self.assertEqual(2, record['seq'])
    self.assertEqual(successor.public_key.to_bytes().hex(), record['owner_public_key_hex'])

  def test_mixed_legacy_and_rotated_heads_do_not_return_masking_legacy_value(self):
    owner_name = b'synthetic-mixed-legacy-rotated-heads'
    old_owner = create_new_key_pair()
    successor = create_new_key_pair()
    rotated = _linked_rotation_values(owner_name, old_owner, successor)
    record_key = hashlib.sha256(owner_name).digest()
    current_key = f'/decent-registry/identity/{record_key.hex()}'.encode()
    legacy = _legacy_identity_envelope(owner_name, old_owner)

    for peer_values in (
        [{current_key: legacy}, rotated],
        [rotated, {current_key: legacy}],
    ):
      with self.subTest(rotated_peer_first=current_key in peer_values[0]):
        result, actual_key, peer_requests = self._resolve(owner_name, peer_values)
        self.assertEqual(0, result[0], result[2])
        record = json.loads(result[1])
        self.assertEqual(actual_key, current_key)
        self.assertEqual(2, record['seq'])
        self.assertEqual(successor.public_key.to_bytes().hex(), record['owner_public_key_hex'])
        key_reads = [key for peer in peer_requests for kind, key in peer
            if kind == Message.MessageType.GET_VALUE and key == current_key]
        history_prefix = b'/decent-registry/history/' + record_key
        history_reads = [key for peer in peer_requests for kind, key in peer
            if kind == Message.MessageType.GET_VALUE and key.startswith(history_prefix)]
        self.assertEqual(4, len(key_reads))
        self.assertEqual(
            [2, 2],
            [sum(kind == Message.MessageType.GET_VALUE and key == current_key
                for kind, key in peer) for peer in peer_requests],
        )
        self.assertTrue(history_reads, 'rotated peer head must be checked against fetched signed history')

  def test_mixed_legacy_and_tampered_rotated_head_stay_unavailable(self):
    import cbor2
    owner_name = b'synthetic-mixed-tampered-head'
    old_owner = create_new_key_pair()
    rotated = _linked_rotation_values(owner_name, old_owner, create_new_key_pair())
    record_key = hashlib.sha256(owner_name).digest()
    current_key = f'/decent-registry/identity/{record_key.hex()}'.encode()
    history_key = next(key for key in rotated if key.startswith(b'/decent-registry/history/'))
    predecessor = cbor2.loads(rotated[history_key])
    predecessor[2] = bytes([predecessor[2][0] ^ 1]) + predecessor[2][1:]
    rotated[history_key] = cbor2.dumps(predecessor, canonical=True)
    legacy = _legacy_identity_envelope(owner_name, old_owner)

    result, _, _ = self._resolve(owner_name, [{current_key: legacy}, rotated])

    self._assert_cli_unavailable(result)

  def test_conflicting_rotations_with_complete_history_stay_unavailable(self):
    owner_name = b'synthetic-linked-rotation-conflict'
    old_owner = create_new_key_pair()
    first = _linked_rotation_values(owner_name, old_owner, create_new_key_pair())
    second = _linked_rotation_values(owner_name, old_owner, create_new_key_pair())
    result, _, _ = self._resolve(owner_name, [first, second])
    self._assert_cli_unavailable(result)

  def test_rotation_with_tampered_predecessor_signature_stays_unavailable(self):
    import cbor2

    owner_name = b'synthetic-linked-rotation-invalid-history'
    values = _linked_rotation_values(owner_name, create_new_key_pair(), create_new_key_pair())
    history_key = next(key for key in values if key.startswith(b'/decent-registry/history/'))
    predecessor = cbor2.loads(values[history_key])
    predecessor[2] = bytes([predecessor[2][0] ^ 1]) + predecessor[2][1:]
    values[history_key] = cbor2.dumps(predecessor, canonical=True)
    result, _, _ = self._resolve(owner_name, [values])
    self._assert_cli_unavailable(result)


if __name__ == "__main__":
  if len(sys.argv) > 1 and sys.argv[1] == "serve":
    serve_adversarial_peer(sys.argv[2:])
  else:
    unittest.main()
