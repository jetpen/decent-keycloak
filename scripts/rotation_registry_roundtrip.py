"""Publish a Registry rotation; evidence is written only after exact fresh-peer readback."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any, Mapping


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
    from decent_registry.verification import make_signed_update_signature
    from libp2p.crypto.ed25519 import create_new_key_pair

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
        predecessor_envelope = await service.get_identity_envelope(owner_name_hex=owner_name_hex)
        predecessor = await service.get_identity(owner_name_hex=owner_name_hex)
        if predecessor_envelope is None or predecessor is None:
            raise RuntimeError("Registry predecessor Identity is unavailable")
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

        successor_cosigner = create_new_key_pair()
        bundle = draft_identity_bundle(
            owner_name=owner_name,
            owner_public_key=new_public,
            seq=predecessor_seq + 1,
            signer_set=[
                {1: "new-owner", 2: new_public},
                {1: "old-owner", 2: old_public},
                {1: "successor-cosigner", 2: successor_cosigner.public_key.to_bytes()},
            ],
            threshold=2,
            epoch=1,
            predecessor_state_hash=predecessor_hash,
            operation=OPERATION_OWNER_KEY_ROTATION,
        )
        old_owner_proof = make_signed_update_signature(
            signed_update_bytes_canonical=bundle.signed_update_bytes,
            owner_private_key=old_private,
        )
        envelope = encode_multisignature_envelope(
            signed_update_bytes=bundle.signed_update_bytes,
            proofs=[{1: None, 2: old_owner_proof}],
        )
        args.envelope.write_bytes(envelope)

    await put_identity(
        identifier=args.identifier,
        host=args.host,
        port=args.port,
        bootstrap=[args.bootstrap],
        finalized_envelope_cbor=envelope,
    )

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


def main() -> None:
    import trio

    parser = argparse.ArgumentParser()
    parser.add_argument("--identifier", required=True)
    parser.add_argument("--old-key", type=Path, required=True)
    parser.add_argument("--new-key", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--datastore", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--readback", type=Path, required=True)
    args = parser.parse_args()
    args.datastore.parent.mkdir(parents=True, exist_ok=True)
    args.envelope.parent.mkdir(parents=True, exist_ok=True)
    args.readback.parent.mkdir(parents=True, exist_ok=True)
    trio.run(rotate_and_confirm, args)


if __name__ == "__main__":
    main()
