"""Live Registry roundtrip coverage for the owner-key rotation helper."""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest
from decent_identity.identity_resolver import get_identity_record
from decent_registry.crypto_utils import write_ed25519_private_key_pem
from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.durable_store import LMDBDatastore
from decent_registry.registry_service import RegistryService

from scripts.rotation_registry_roundtrip import rotate_and_confirm


def peer_address(registry: Libp2pKadDHT) -> str:
    address = registry.get_listen_multiaddr()
    if "/p2p/" not in address:
        address = f"{address}/p2p/{registry.host.get_id().to_string()}"
    return address


@pytest.mark.trio
async def test_legacy_identity_rotation_publishes_and_resolves_successor(tmp_path: Path):
    identifier = "rotation-roundtrip@example.invalid"
    owner_name = identifier.encode("utf-8")
    old_key = tmp_path / "old-owner.pem"
    new_key = tmp_path / "new-owner.pem"
    write_ed25519_private_key_pem(old_key)
    write_ed25519_private_key_pem(new_key)
    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "registry.lmdb"),
    ) as registry:
        bootstrap = peer_address(registry)
        service = RegistryService(dht=registry)
        await service.put_identity(
            owner_name_hex=owner_name.hex(),
            owner_privkey_pem_path=str(old_key),
            seq=1,
        )
        args = argparse.Namespace(
            identifier=identifier,
            old_key=old_key,
            new_key=new_key,
            host="127.0.0.1",
            port=0,
            bootstrap=bootstrap,
            datastore=tmp_path / "rotation-client.lmdb",
            envelope=tmp_path / "rotation-envelope.cbor",
            readback=tmp_path / "rotation-readback.txt",
        )
        await rotate_and_confirm(args)
        result = await get_identity_record(
            identifier=identifier,
            host="127.0.0.1",
            port=0,
            bootstrap=[bootstrap],
        )
        assert result is not None
        assert result.seq == 2
        assert result.owner_public_key_hex == args.readback.read_text().splitlines()[1]
        assert result.owner_public_key_hex
        assert args.envelope.read_bytes()
        assert args.readback.read_text().splitlines()[0] == "2"
