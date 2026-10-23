#!/usr/bin/env python3
"""Apply the repository-owned outcome overlay to locked resolver sources."""
from __future__ import annotations

import argparse
import ast
import shutil
from pathlib import Path

OVERLAY = Path(__file__).resolve().with_name("pinned_lookup_outcomes.py")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"pinned source anchor mismatch for {label}: {count}")
    return text.replace(old, new, 1)


def patch_value_store(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from .pb.kademlia_pb2 import Message, Record\n",
        "from .pb.kademlia_pb2 import Message, Record\n"
        "from .pinned_lookup_outcomes import (\n"
        "    PeerValueAbsent,\n"
        "    PeerValueIncomplete,\n"
        "    PeerValueUnavailable,\n"
        ")\n",
        "value-store outcome imports",
    )
    text = replace_once(
        text,
        "    ) -> bytes | Record | None:\n",
        "    ) -> bytes | Record | PeerValueAbsent | PeerValueIncomplete | PeerValueUnavailable | None:\n",
        "value-store result annotation",
    )
    replacements = (
        (
            "            if peer_id == self.local_peer_id:\n"
            "                return None\n",
            "            if peer_id == self.local_peer_id:\n"
            "                return PeerValueUnavailable()\n",
            "local peer is not a remote absence",
        ),
        (
            "                    logger.warning(\"Connection closed while reading length\")\n"
            "                    return None\n",
            "                    logger.warning(\"DHT GET_VALUE stream closed before response\")\n"
            "                    return PeerValueUnavailable()\n",
            "closed response length",
        ),
        (
            "                    logger.debug(\n"
            "                        f\"Connection closed by peer {peer_id} while reading data\"\n"
            "                    )\n"
            "                    return None\n",
            "                    logger.warning(\"DHT GET_VALUE stream closed during response\")\n"
            "                    return PeerValueUnavailable()\n",
            "closed response body",
        ),
        (
            "                        logger.error(\n"
            "                            \"Received an invalid-signed-record, ignoring the response\"\n"
            "                        )\n"
            "                        return None\n",
            "                        logger.warning(\"DHT GET_VALUE signed peer record was invalid\")\n"
            "                        return PeerValueUnavailable()\n",
            "invalid sender record",
        ),
        (
            "                # Handle case where value is not found but peer infos are returned\n"
            "                else:\n"
            "                    logger.debug(\n"
            "                        f\"Value not found for key {key.hex()} from peer {peer_id},\"\n"
            "                        f\" received {len(response.closerPeers)} closer peers\"\n"
            "                    )\n"
            "                    return None\n",
            "                # Absence requires a valid empty response with no unqueried referrals.\n"
            "                else:\n"
            "                    if response.type != Message.MessageType.GET_VALUE:\n"
            "                        return PeerValueUnavailable()\n"
            "                    if response.HasField(\"record\"):\n"
            "                        return PeerValueUnavailable()\n"
            "                    if response.closerPeers:\n"
            "                        return PeerValueIncomplete()\n"
            "                    return PeerValueAbsent()\n",
            "empty response classification",
        ),
        (
            "            except Exception as proto_err:\n"
            "                logger.warning(f\"Failed to parse as protobuf: {proto_err}\")\n\n"
            "            return None\n",
            "            except Exception:\n"
            "                logger.warning(\"DHT GET_VALUE response was malformed\")\n"
            "                return PeerValueUnavailable()\n",
            "malformed response classification",
        ),
        (
            "        except Exception as e:\n"
            "            logger.warning(f\"Failed to get value from peer {peer_id}: {e}\")\n"
            "            return None\n",
            "        except Exception:\n"
            "            logger.warning(\"DHT GET_VALUE peer query failed\")\n"
            "            return PeerValueUnavailable()\n",
            "peer query failure classification",
        ),
        (
            "            logger.debug(f\"Getting value for key {key.hex()} from peer {peer_id}\")\n",
            "            logger.debug(\"Querying peer for DHT GET_VALUE\")\n",
            "peer query debug redaction",
        ),
        (
            "            logger.debug(f\"Opened stream to peer {peer_id} for GET_VALUE\")\n",
            "            logger.debug(\"Opened DHT GET_VALUE stream\")\n",
            "peer stream debug redaction",
        ),
        (
            "                    logger.debug(\n"
            "                        f\"Received value for key {key.hex()} from peer {peer_id}\"\n"
            "                    )\n",
            "                    logger.debug(\"Received DHT GET_VALUE record\")\n",
            "record debug redaction",
        ),
    )
    for old, new, label in replacements:
        text = replace_once(text, old, new, label)
    text = replace_once(
        text,
        """                logger.debug(
                    f"Received protobuf response from peer"
                    f" {peer_id}, type: {response.type}"
                )
""",
        """                logger.debug("Received DHT GET_VALUE response")
""",
        "response debug redaction",
    )
    text = replace_once(
        text,
        """                    if response.type != Message.MessageType.GET_VALUE:
                        return PeerValueUnavailable()
                    if response.HasField("record"):
""",
        """                    if response.type != Message.MessageType.GET_VALUE:
                        return PeerValueUnavailable()
                    if response.key != key:
                        logger.warning("DHT GET_VALUE response key did not match request")
                        return PeerValueUnavailable()
                    if not maybe_consume_signed_record(response, self.host, peer_id):
                        logger.warning("DHT GET_VALUE signed peer record was invalid")
                        return PeerValueUnavailable()
                    if response.HasField("record"):
""",
        "empty response key and sender validation",
    )
    ast.parse(text, filename=str(path))
    path.write_text(text, encoding="utf-8")


def patch_kad_dht(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    marker = "# --- repository-owned pinned resolver outcome overlay ---\n"
    if marker in text:
        raise RuntimeError("pinned KadDHT overlay was already applied")
    text += (
        "\n"
        + marker
        + "from .pinned_lookup_outcomes import install as _install_lookup_outcomes\n"
        + "_install_lookup_outcomes(KadDHT, ValueStore)\n"
    )
    ast.parse(text, filename=str(path))
    path.write_text(text, encoding="utf-8")


def patch_registry(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from libp2p.kad_dht.kad_dht import DHTMode, KadDHT\n",
        "from libp2p.kad_dht.kad_dht import DHTMode, KadDHT\n"
        "from libp2p.kad_dht.pinned_lookup_outcomes import (\n"
        "    DHTLookupUnavailable,\n"
        "    LookupCounts,\n"
        "    PeerValueAbsent,\n"
        "    PeerValueIncomplete,\n"
        "    PeerValueUnavailable,\n"
        "    report_lookup_summary,\n"
        ")\n",
        "Registry outcome imports",
    )
    text = replace_once(
        text,
        "    async def _read_dht_value(self, kad_key: str, *, quorum: int = 0) -> bytes | None:\n"
        "        try:\n"
        "            return await self.dht.get_value(kad_key, quorum=quorum)\n"
        "        except Exception:\n"
        "            return None\n",
        "    async def _read_dht_value(self, kad_key: str, *, quorum: int = 0) -> bytes | None:\n"
        "        return await self.dht.get_value(kad_key, quorum=quorum)\n",
        "Registry DHT exception propagation",
    )
    start = text.index("    async def read_remote_identity_envelope(self, object_key_hex: str) -> bytes | None:\n")
    end = text.index("    async def read_remote_identity_envelope_by_hash(\n", start)
    new_method = '''    async def read_remote_identity_envelope(self, object_key_hex: str) -> bytes | None:
        """Read raw Identity bytes from peers without converting uncertainty to absence."""
        try:
            record_key = bytes.fromhex(object_key_hex)
        except ValueError:
            raise ValueError("identity object key must be valid hex") from None
        if len(record_key) != 32:
            raise ValueError("identity object key must be 32 bytes")
        canonical_object_key_hex = record_key.hex()

        remote_reader = self._remote_identity_reader
        if remote_reader is not None:
            counts = LookupCounts(attempts=1)
            try:
                envelope = await remote_reader.read_remote_identity_envelope(
                    canonical_object_key_hex
                )
            except Exception:
                counts.failed = 1
                report_lookup_summary("remote_identity", counts)
                raise DHTLookupUnavailable("remote_identity", counts) from None
            if not isinstance(envelope, (bytes, bytearray)):
                counts.failed = 1
                report_lookup_summary("remote_identity", counts)
                raise DHTLookupUnavailable("remote_identity", counts)
            return bytes(envelope)

        bootstrap_peers = tuple(self._bootstrap_peers)
        counts = LookupCounts()
        if not bootstrap_peers:
            report_lookup_summary("remote_identity", counts)
            raise DHTLookupUnavailable("remote_identity", counts)

        envelope = None
        try:
            async with Libp2pKadDHT(
                listen="/ip4/127.0.0.1/tcp/0",
                durable_store=None,
                dht_mode=DHTMode.CLIENT,
            ) as remote_dht:
                kad_key = remote_dht._kad_key(
                    canonical_object_key_hex, kind="identity"
                )
                local_host = getattr(self, "_host", None)
                local_peer_id = None if local_host is None else local_host.get_id()
                for peer in bootstrap_peers:
                    try:
                        peer_info = info_from_p2p_addr(Multiaddr(peer))
                    except Exception:
                        counts.attempts += 1
                        counts.failed += 1
                        continue
                    if local_peer_id is not None and peer_info.peer_id == local_peer_id:
                        continue
                    counts.attempts += 1
                    try:
                        await remote_dht.bootstrap(peer)
                        record = await remote_dht.dht.value_store._get_from_peer(
                            peer_info.peer_id,
                            kad_key.encode("utf-8"),
                            return_record=True,
                        )
                    except Exception:
                        counts.failed += 1
                        continue
                    if isinstance(record, PeerValueAbsent):
                        counts.empty += 1
                        continue
                    if isinstance(record, PeerValueIncomplete):
                        counts.incomplete += 1
                        continue
                    if isinstance(record, PeerValueUnavailable) or record is None:
                        counts.failed += 1
                        continue
                    candidate = getattr(record, "value", None)
                    if not isinstance(candidate, (bytes, bytearray)):
                        counts.failed += 1
                        continue
                    envelope = bytes(candidate)
                    break
        except DHTLookupUnavailable:
            raise
        except Exception:
            counts.failed += 1
            report_lookup_summary("remote_identity", counts)
            raise DHTLookupUnavailable("remote_identity", counts) from None

        if envelope is not None:
            return envelope
        report_lookup_summary("remote_identity", counts)
        if counts.is_clean_absence():
            return None
        raise DHTLookupUnavailable("remote_identity", counts)

'''
    text = text[:start] + new_method + text[end:]
    ast.parse(text, filename=str(path))
    path.write_text(text, encoding="utf-8")


def apply_overlay(site_packages: Path, registry_file: Path) -> None:
    package = site_packages / "libp2p" / "kad_dht"
    metadata = site_packages / "libp2p-0.7.0.dist-info" / "METADATA"
    if not metadata.is_file():
        raise RuntimeError("pinned libp2p 0.7.0 distribution metadata is missing")
    metadata_fields = {
        line for line in metadata.read_text(encoding="utf-8").splitlines()
        if line.startswith(("Name:", "Version:"))
    }
    if not {"Name: libp2p", "Version: 0.7.0"}.issubset(metadata_fields):
        raise RuntimeError("runtime overlay requires the locked libp2p 0.7.0 package")
    if not package.is_dir():
        raise RuntimeError("pinned libp2p package directory is missing")
    value_store = package / "value_store.py"
    kad_dht = package / "kad_dht.py"
    for path in (value_store, kad_dht, registry_file):
        if not path.is_file():
            raise RuntimeError(f"pinned runtime source is missing: {path.name}")
    if (package / "pinned_lookup_outcomes.py").exists():
        raise RuntimeError("pinned resolver overlay helper already exists")
    patch_value_store(value_store)
    patch_kad_dht(kad_dht)
    patch_registry(registry_file)
    shutil.copyfile(OVERLAY, package / "pinned_lookup_outcomes.py")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-packages", type=Path, required=True)
    parser.add_argument("--registry-file", type=Path, required=True)
    arguments = parser.parse_args()
    apply_overlay(arguments.site_packages.resolve(), arguments.registry_file.resolve())


if __name__ == "__main__":
    main()
