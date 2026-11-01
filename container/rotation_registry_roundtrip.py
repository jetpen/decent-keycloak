"""Publish a Registry rotation; evidence is written only after exact fresh-peer readback."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping


ROTATION_CHECKPOINT_STAGES = frozenset({
    'owner_key_load', 'predecessor_envelope_read', 'predecessor_state_read',
    'predecessor_validation', 'successor_key_generation', 'rotation_bundle_build',
    'rotation_signature', 'rotation_validation', 'envelope_write', 'registry_publish', 'fresh_readback',
    'complete',
})
ROTATION_CHECKPOINT_STATUSES = frozenset({'running', 'failed', 'passed'})
ROTATION_FAILURE_CATEGORIES = frozenset({
    'predecessor_unavailable', 'predecessor_key_mismatch',
    'predecessor_envelope_invalid', 'predecessor_state_mismatch',
    'predecessor_history_unavailable', 'rotation_proof_count_invalid',
    'rotation_proof_signer_invalid', 'rotation_proof_invalid',
    'rotation_sequence_invalid', 'successor_key_not_authorized',
    'readback_not_confirmed', 'registry_state_unavailable',
    'registry_state_precondition_failed', 'registry_validation_error',
    'io_error', 'timeout', 'runtime_error', 'other',
})
_ROTATION_FAILURE_MESSAGES = {
    'Registry predecessor Identity is unavailable': 'predecessor_unavailable',
    'Registry predecessor key does not match old-owner fixture': 'predecessor_key_mismatch',
    'Registry predecessor envelope is malformed': 'predecessor_envelope_invalid',
    'predecessor SignedUpdate does not match Registry state': 'predecessor_state_mismatch',
    'complete predecessor history is required for owner rotation': 'predecessor_history_unavailable',
    'authenticated Identity predecessor history is unavailable': 'predecessor_history_unavailable',
    'durable Identity history is required for owner-key rotation': 'predecessor_history_unavailable',
    'legacy owner rotation requires exactly one proof': 'rotation_proof_count_invalid',
    'legacy owner rotation proof signer_id must be null': 'rotation_proof_signer_invalid',
    'invalid legacy owner rotation proof': 'rotation_proof_invalid',
    'rotation seq must be exactly predecessor seq plus one': 'rotation_sequence_invalid',
    'successor Owner Public Key must be in successor Signer Set': 'successor_key_not_authorized',
    'separate Identity resolver did not confirm expected sequence and owner key': 'readback_not_confirmed',
}


def classify_rotation_failure(exc: Exception) -> str:
    """Project helper failures into fixed categories without retaining messages."""
    class_categories = {
        'IdentityHistoryUnavailable': 'predecessor_history_unavailable',
        'IdentityStateUnavailable': 'registry_state_unavailable',
        'IdentityStatePreconditionFailed': 'registry_state_precondition_failed',
    }
    category = class_categories.get(type(exc).__name__)
    if category is None:
        category = _ROTATION_FAILURE_MESSAGES.get(str(exc))
    if category is None:
        if isinstance(exc, TimeoutError):
            category = 'timeout'
        elif isinstance(exc, OSError):
            category = 'io_error'
        elif isinstance(exc, ValueError):
            category = 'registry_validation_error'
        elif isinstance(exc, RuntimeError):
            category = 'runtime_error'
        else:
            category = 'other'
    return category if category in ROTATION_FAILURE_CATEGORIES else 'other'


def write_rotation_checkpoint(path: Path, stage: str, status: str,
    failure_category: str | None = None) -> None:
    if stage not in ROTATION_CHECKPOINT_STAGES or status not in ROTATION_CHECKPOINT_STATUSES:
        raise ValueError('unsupported rotation checkpoint state')
    if status == 'failed':
        if failure_category not in ROTATION_FAILURE_CATEGORIES:
            raise ValueError('unsupported rotation failure category')
    elif failure_category is not None:
        raise ValueError('successful or running checkpoint cannot carry a failure category')
    record = {'stage': stage, 'status': status}
    if failure_category is not None:
        record['failure_category'] = failure_category
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(record, sort_keys=True), encoding='ascii')
    os.replace(temporary, path)


def read_rotation_checkpoint(path: Path) -> dict[str, str] | None:
    try:
        record = json.loads(Path(path).read_text(encoding='ascii'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(record, dict):
        return None
    if set(record) not in ({'stage', 'status'}, {'stage', 'status', 'failure_category'}):
        return None
    if record.get('stage') not in ROTATION_CHECKPOINT_STAGES:
        return None
    if record.get('status') not in ROTATION_CHECKPOINT_STATUSES:
        return None
    category = record.get('failure_category')
    if record['status'] == 'failed':
        if category not in ROTATION_FAILURE_CATEGORIES:
            return None
    elif category is not None:
        return None
    return record


def _mark_rotation_stage(args: argparse.Namespace, stage: str) -> None:
    args._rotation_stage = stage
    checkpoint = getattr(args, 'checkpoint', None)
    if checkpoint is not None:
        write_rotation_checkpoint(checkpoint, stage, 'running')


def predecessor_signed_update(envelope: bytes, identifier: bytes, owner_key: bytes, seq: int) -> bytes:
    import cbor2
    from decent_registry.encoding import decode_canonical_signed_update
    from decent_registry.signed_envelope import decode_multisignature_envelope

    try:
        outer = cbor2.loads(envelope)
    except Exception as exc:
        raise RuntimeError("Registry predecessor envelope is malformed") from exc
    if isinstance(outer, dict) and set(outer) == {1, 2}:
        signed_update = outer[1]
    else:
        signed_update = decode_multisignature_envelope(envelope).signed_update_bytes
    if not isinstance(signed_update, bytes):
        raise RuntimeError("Registry predecessor SignedUpdate is not bytes")
    update = decode_canonical_signed_update(signed_update)
    if (update[1] != {1: identifier, 2: owner_key}
            or update[2] != {} or update[3] != seq):
        raise RuntimeError("predecessor SignedUpdate does not match Registry state")
    return signed_update


def state_fields(state: Any) -> tuple[int, bytes]:
    if isinstance(state, Mapping):
        seq = state.get("seq")
        public_key = state.get("owner_public_key")
    else:
        seq = getattr(state, "seq", None)
        public_key = getattr(state, "owner_public_key", None)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise RuntimeError("Registry predecessor sequence is invalid")
    if isinstance(public_key, str):
        try:
            public_key = bytes.fromhex(public_key)
        except ValueError as exc:
            raise RuntimeError("Registry predecessor owner key is malformed") from exc
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise RuntimeError("Registry predecessor owner key is invalid")
    return seq, bytes(public_key)


def fresh_readback_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def authenticated_predecessor_state(service: Any, owner_name_hex: str, envelope: bytes):
    """Replay bounded accepted history via public, hash-addressed Registry reads."""
    import cbor2
    from decent_registry.encoding import decode_multisignature_signed_update
    from decent_registry.signed_envelope import decode_multisignature_envelope
    from decent_registry.verification import validate_multisignature_history

    chain = [envelope]
    seen = set()
    for _ in range(64):
        outer = cbor2.loads(chain[0])
        if isinstance(outer, dict) and set(outer) == {1, 2}:
            break
        update = decode_multisignature_signed_update(
            decode_multisignature_envelope(chain[0]).signed_update_bytes)
        predecessor_hash = update[4][7]
        if predecessor_hash == bytes(32):
            break
        if predecessor_hash in seen:
            raise RuntimeError('complete predecessor history is required for owner rotation')
        seen.add(predecessor_hash)
        previous = await service.get_identity_envelope_by_hash(
            owner_name_hex=owner_name_hex, state_hash=predecessor_hash)
        if previous is None:
            raise RuntimeError('complete predecessor history is required for owner rotation')
        chain.insert(0, previous)
    else:
        raise RuntimeError('complete predecessor history is required for owner rotation')
    return validate_multisignature_history(
        record_key=hashlib.sha256(bytes.fromhex(owner_name_hex)).digest(), envelopes=chain)


async def rotate_and_confirm(args: argparse.Namespace) -> None:
    import trio
    from decent_identity.identity_resolver import get_identity_record, put_identity
    from decent_registry.crypto_utils import load_ed25519_keypair_from_privkey_pem_path
    from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
    from decent_registry.durable_store import LMDBDatastore
    from decent_registry.encoding import OPERATION_OWNER_KEY_ROTATION
    from decent_registry.multisig_bundle import draft_identity_bundle
    from decent_registry.registry_service import RegistryService
    from decent_registry.signed_envelope import encode_multisignature_envelope
    from decent_registry.verification import make_signed_update_signature, validate_multisignature_update
    from libp2p.crypto.ed25519 import create_new_key_pair

    _mark_rotation_stage(args, 'owner_key_load')
    old_private, old_public = load_ed25519_keypair_from_privkey_pem_path(str(args.old_key))
    new_private, new_public = load_ed25519_keypair_from_privkey_pem_path(str(args.new_key))
    old_public = bytes(old_public)
    new_public = bytes(new_public)
    if old_public == new_public:
        raise RuntimeError("old and successor owner keys must differ")
    owner_name = args.identifier.encode("utf-8")
    owner_name_hex = owner_name.hex()

    async with Libp2pKadDHT(
        listen=f"/ip4/{args.host}/tcp/{args.port}",
        dht_mode=DHTMode.CLIENT,
        durable_store=LMDBDatastore(path=args.datastore),
    ) as writer:
        await writer.bootstrap(args.bootstrap)
        service = RegistryService(dht=writer)
        _mark_rotation_stage(args, 'predecessor_envelope_read')
        predecessor_envelope = await service.get_identity_envelope(owner_name_hex=owner_name_hex)
        _mark_rotation_stage(args, 'predecessor_state_read')
        predecessor = await service.get_identity(owner_name_hex=owner_name_hex)
        if predecessor_envelope is None or predecessor is None:
            raise RuntimeError("Registry predecessor Identity is unavailable")
        _mark_rotation_stage(args, 'predecessor_validation')
        predecessor_seq, current_public = state_fields(predecessor)
        if current_public != old_public:
            raise RuntimeError("Registry predecessor key does not match old-owner fixture")
        if (getattr(predecessor, "signed_update_bytes", None) is not None
                and getattr(predecessor, "state_hash", None) is not None):
            predecessor_update = bytes(predecessor.signed_update_bytes)
            predecessor_hash = bytes(predecessor.state_hash)
            if predecessor_hash != hashlib.sha256(predecessor_update).digest():
                raise RuntimeError("validated predecessor hash differs from SignedUpdate bytes")
        else:
            predecessor_update = predecessor_signed_update(
                predecessor_envelope, owner_name, current_public, predecessor_seq
            )
            predecessor_hash = hashlib.sha256(predecessor_update).digest()

        # Only the legacy transition establishes a new authorization policy.
        # Later owner-key rotations preserve the authenticated predecessor policy.
        multisignature_predecessor = getattr(predecessor, 'authorization', None) is not None
        if multisignature_predecessor:
            predecessor = await authenticated_predecessor_state(
                service, owner_name_hex, predecessor_envelope)
            if (predecessor.seq != predecessor_seq or predecessor.owner_public_key != old_public
                    or predecessor.signed_update_bytes != predecessor_update
                    or predecessor.state_hash != predecessor_hash):
                raise RuntimeError('predecessor SignedUpdate does not match Registry state')
            signer_set = [{1: signer_id, 2: public_key}
                for signer_id, public_key in predecessor.signer_set]
            threshold = predecessor.threshold
            epoch = predecessor.epoch
        else:
            _mark_rotation_stage(args, 'successor_key_generation')
            successor_cosigner = create_new_key_pair()
            signer_set = [
                {1: 'new-owner', 2: new_public},
                {1: 'old-owner', 2: old_public},
                {1: 'successor-cosigner', 2: successor_cosigner.public_key.to_bytes()},
            ]
            threshold = 2
            epoch = 1
        _mark_rotation_stage(args, 'rotation_bundle_build')
        bundle = draft_identity_bundle(
            owner_name=owner_name,
            owner_public_key=new_public,
            seq=predecessor_seq + 1,
            signer_set=signer_set,
            threshold=threshold,
            epoch=epoch,
            predecessor_state_hash=predecessor_hash,
            operation=OPERATION_OWNER_KEY_ROTATION,
        )
        _mark_rotation_stage(args, 'rotation_signature')
        if multisignature_predecessor:
            private_keys = {old_public: old_private}
            for path in getattr(args, 'authorizing_keys', ()):
                private, public = load_ed25519_keypair_from_privkey_pem_path(str(path))
                public = bytes(public)
                if public in private_keys:
                    raise ValueError('duplicate rotation authorization key')
                if public not in {bytes(entry[2]) for entry in signer_set}:
                    raise ValueError('rotation authorization key is not a predecessor signer')
                private_keys[public] = private
            proofs = [{1: entry[1], 2: make_signed_update_signature(
                signed_update_bytes_canonical=bundle.signed_update_bytes,
                owner_private_key=private_keys[bytes(entry[2])])}
                for entry in signer_set if bytes(entry[2]) in private_keys]
        else:
            proofs = [{1: None, 2: make_signed_update_signature(
                signed_update_bytes_canonical=bundle.signed_update_bytes,
                owner_private_key=old_private)}]
        envelope = encode_multisignature_envelope(
            signed_update_bytes=bundle.signed_update_bytes, proofs=proofs,
        )
        _mark_rotation_stage(args, 'rotation_validation')
        validate_multisignature_update(
            record_key=hashlib.sha256(owner_name).digest(), envelope_cbor=envelope,
            current_state=predecessor if multisignature_predecessor else None,
            legacy_envelope_cbor=None if multisignature_predecessor else predecessor_envelope,
        )
        _mark_rotation_stage(args, 'envelope_write')
        args.envelope.write_bytes(envelope)

    _mark_rotation_stage(args, 'registry_publish')
    await put_identity(
        identifier=args.identifier,
        host=args.host,
        port=args.port,
        bootstrap=[args.bootstrap],
        finalized_envelope_cbor=envelope,
    )

    _mark_rotation_stage(args, 'fresh_readback')
    expected_seq = predecessor_seq + 1
    expected_key = new_public.hex()
    observed = None
    for attempt in range(30):
        observed = await get_identity_record(
            identifier=args.identifier,
            host=args.host,
            port=fresh_readback_port(),
            bootstrap=[args.bootstrap],
        )
        if (observed is not None and observed.seq == expected_seq
                and observed.owner_public_key_hex == expected_key):
            break
        observed = None
        if attempt < 29:
            await trio.sleep(1)
    if observed is None:
        raise RuntimeError("separate Identity resolver did not confirm expected sequence and owner key")
    args.readback.write_text(f"{observed.seq}\n{observed.owner_public_key_hex}\n", encoding="ascii")
    _mark_rotation_stage(args, 'complete')


def main() -> None:
    import trio

    parser = argparse.ArgumentParser()
    parser.add_argument("--identifier", required=True)
    parser.add_argument("--old-key", type=Path, required=True)
    parser.add_argument("--new-key", type=Path, required=True)
    parser.add_argument('--authorizing-key', dest='authorizing_keys', type=Path, action='append', default=[],
        help='additional private key of an authenticated predecessor signer (repeatable)')
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--datastore", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--readback", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path)
    args = parser.parse_args()
    args.datastore.parent.mkdir(parents=True, exist_ok=True)
    args.envelope.parent.mkdir(parents=True, exist_ok=True)
    args.readback.parent.mkdir(parents=True, exist_ok=True)
    try:
        trio.run(rotate_and_confirm, args)
        if args.checkpoint is not None:
            write_rotation_checkpoint(args.checkpoint, 'complete', 'passed')
    except Exception as exc:
        stage = getattr(args, '_rotation_stage', 'owner_key_load')
        category = classify_rotation_failure(exc)
        if args.checkpoint is not None:
            try:
                write_rotation_checkpoint(args.checkpoint, stage, 'failed', category)
            except Exception:
                pass
        print('rotation_helper_failure=' + category)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
