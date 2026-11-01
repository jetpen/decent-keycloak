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
        "    MAX_DHT_MESSAGE_SIZE,\n"
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
        "                    and response.record.value\n"
        "                ):\n"
        "                    # Consume the sender's signed-peer-record\n",
        "                    and response.record.value\n"
        "                ):\n"
        "                    if key.startswith(b\\\"/decent-registry/identity/\\\"):\\n"
        "                        if response.key != key or response.record.key != key:\\n"
        "                            logger.warning(\\\"DHT GET_VALUE record key did not match request\\\")\\n"
        "                            return PeerValueUnavailable()\\n"
        "                        if response.closerPeers:\\n"
        "                            logger.warning(\\\"DHT GET_VALUE record had unqueried referrals\\\")\\n"
        "                            return PeerValueIncomplete()\\n"
        "                    # Consume the sender's signed-peer-record\n",
        "positive record exact-key and referral checks",
    )
    start_marker = "                    if key.startswith(b"
    end_marker = "                    # Consume the sender's signed-peer-record"
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    identity_guard = '''                    if key.startswith(b"/decent-registry/identity/"):
                        if response.key != key or response.record.key != key:
                            logger.warning("DHT GET_VALUE record key did not match request")
                            return PeerValueUnavailable()
                        if response.closerPeers:
                            logger.warning("DHT GET_VALUE record had unqueried referrals")
                            return PeerValueIncomplete()
'''
    text = text[:start] + identity_guard + text[end:]
    text = replace_once(
        text,
        "            # Read response length\n"
        "            length_bytes = b\"\"\n"
        "            while True:\n"
        "                b = await stream.read(1)\n"
        "                if not b:\n"
        "                    logger.warning(\"Connection closed while reading length\")\n"
        "                    return None\n"
        "                length_bytes += b\n"
        "                if b[0] & 0x80 == 0:\n"
        "                    break\n"
        "            response_length = varint.decode_bytes(length_bytes)\n"
        "            # Read response data\n",
        "            # Read response length\n"
        "            length_bytes = b\"\"\n"
        "            while True:\n"
        "                b = await stream.read(1)\n"
        "                if not b:\n"
        "                    logger.warning(\"DHT GET_VALUE stream closed before response\")\n"
        "                    return PeerValueUnavailable()\n"
        "                length_bytes += b\n"
        "                if b[0] & 0x80 == 0:\n"
        "                    break\n"
        "                if len(length_bytes) >= 5:\n"
        "                    logger.warning(\"DHT GET_VALUE frame length prefix exceeded bound\")\n"
        "                    return PeerValueUnavailable()\n"
        "            try:\n"
        "                response_length = varint.decode_bytes(length_bytes)\n"
        "            except Exception:\n"
        "                logger.warning(\"DHT GET_VALUE frame length prefix was invalid\")\n"
        "                return PeerValueUnavailable()\n"
        "            if (varint.encode(response_length) != length_bytes\n"
        "                    or response_length > MAX_DHT_MESSAGE_SIZE):\n"
        "                logger.warning(\"DHT GET_VALUE response frame was invalid or oversized\")\n"
        "                return PeerValueUnavailable()\n"
        "            # Read response data\n",
        "bounded canonical GET_VALUE frame before body read",
    )
    text = replace_once(
        text,
        """            # Read varint-prefixed response length

            length_bytes = b""
            while True:
                logger.debug("Reading varint length prefix for response...")
                b = await stream.read(1)
                if not b:
                    logger.warning("Connection closed while reading varint length")
                    return False
                length_bytes += b
                if b[0] & 0x80 == 0:
                    break
            logger.debug(f"Received varint length bytes: {length_bytes.hex()}")
            response_length = varint.decode_bytes(length_bytes)
            logger.debug("Response length: %d bytes", response_length)
            # Read response data
""",
        """            # Read varint-prefixed response length

            length_bytes = b""
            while True:
                b = await stream.read(1)
                if not b:
                    logger.warning("DHT PUT_VALUE stream closed before response")
                    return False
                length_bytes += b
                if b[0] & 0x80 == 0:
                    break
                if len(length_bytes) >= 5:
                    logger.warning("DHT PUT_VALUE frame length prefix exceeded bound")
                    return False
            response_length = varint.decode_bytes(length_bytes)
            if (varint.encode(response_length) != length_bytes
                    or response_length > MAX_DHT_MESSAGE_SIZE):
                logger.warning("DHT PUT_VALUE response frame was invalid or oversized")
                return False
            # Read response data
""",
        "bounded PUT_VALUE acknowledgement frame",
    )
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
    text = replace_once(
        text,
        "from .common import (\n    ALPHA,\n    BUCKET_SIZE,\n    PROTOCOL_ID,\n    PROTOCOL_PREFIX,\n    QUERY_TIMEOUT,\n)\n",
        "from .common import (\n    ALPHA,\n    BUCKET_SIZE,\n    PROTOCOL_ID,\n    PROTOCOL_PREFIX,\n    QUERY_TIMEOUT,\n)\n"
        "from .pinned_lookup_outcomes import MAX_DHT_MESSAGE_SIZE\n",
        "KadDHT frame size import",
    )
    text = replace_once(
        text,
        "        # 4. Select the best record if any valid records were found\n"
        "        if valid_records:\n",
        "        from .pinned_lookup_outcomes import check_identity_candidate_selection\n"
        "        check_identity_candidate_selection(key, quorum)\n\n"
        "        # 4. Select the best record if any valid records were found\n"
        "        if valid_records:\n",
        "pre-selection Identity candidate guard",
    )
    text = replace_once(
        text,
        "                            if quorum and len(valid_records) >= quorum:\n",
        "                            # Identity lookups must inspect all known peers.\n"
        "                            if (quorum and len(valid_records) >= quorum\n"
        "                                    and not key.startswith(\"/decent-registry/identity/\")):\n",
        "Identity quorum early-stop guard",
    )
    text = replace_once(
        text,
        "        # 1. Check local store first\n"
        "        value_record = self.value_store.get(key_bytes)\n"
        "        if value_record:\n"
        "            logger.debug(\"Found value locally\")\n"
        "            return value_record.value\n",
        "        # 1. Check local store first. Identity reads must refresh\n"
        "        # from peers; a cached legacy head cannot establish the current head.\n"
        "        value_record = self.value_store.get(key_bytes)\n"
        "        if value_record:\n"
        "            if not key.startswith(\"/decent-registry/identity/\"):\n"
        "                logger.debug(\"Found value locally\")\n"
        "                return value_record.value\n",
        "all-mode Identity cache bypass",
    )
    # Inbound DHT request sizes are also peer-controlled. Bound and canonicalize
    # the prefix before the single body read, not only outbound ValueStore replies.
    text = replace_once(
        text,
        "            # Read varint-prefixed length for the message\n"
        "            length_prefix = b\"\"\n"
        "            while True:\n"
        "                byte = await stream.read(1)\n"
        "                if not byte:\n"
        "                    logger.warning(\"Stream closed while reading varint length\")\n"
        "                    await stream.close()\n"
        "                    return\n"
        "                length_prefix += byte\n"
        "                if byte[0] & 0x80 == 0:\n"
        "                    break\n"
        "            msg_length = varint.decode_bytes(length_prefix)\n"
        "\n"
        "            # Read the message bytes\n",
        "            # Read varint-prefixed length for the message\n"
        "            length_prefix = b\"\"\n"
        "            while True:\n"
        "                byte = await stream.read(1)\n"
        "                if not byte:\n"
        "                    logger.warning(\"Stream closed while reading varint length\")\n"
        "                    await stream.close()\n"
        "                    return\n"
        "                length_prefix += byte\n"
        "                if byte[0] & 0x80 == 0:\n"
        "                    break\n"
        "                if len(length_prefix) >= 5:\n"
        "                    logger.warning(\"DHT inbound frame length prefix exceeded bound\")\n"
        "                    await stream.close()\n"
        "                    return\n"
        "            try:\n"
        "                msg_length = varint.decode_bytes(length_prefix)\n"
        "            except Exception:\n"
        "                logger.warning(\"DHT inbound frame length prefix was invalid\")\n"
        "                await stream.close()\n"
        "                return\n"
        "            if (varint.encode(msg_length) != length_prefix\n"
        "                    or msg_length > MAX_DHT_MESSAGE_SIZE):\n"
        "                logger.warning(\"DHT inbound frame was noncanonical or oversized\")\n"
        "                await stream.close()\n"
        "                return\n"
        "\n"
        "            # Read the message bytes\n",
        "bounded inbound DHT frame",
    )
    text += (
        "\n"
        + marker
        + "from .pinned_lookup_outcomes import install as _install_lookup_outcomes\n"
        + "_install_lookup_outcomes(KadDHT, ValueStore)\n"
    )
    ast.parse(text, filename=str(path))
    path.write_text(text, encoding="utf-8")


def patch_provider_store(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from .pb.kademlia_pb2 import (\n    Message,\n)\n",
        "from .pb.kademlia_pb2 import (\n    Message,\n)\n"
        "from .pinned_lookup_outcomes import MAX_DHT_MESSAGE_SIZE\n",
        "provider-store message-size import",
    )
    patterns = (
        (
            "                    break\n\n"
            "            response_length = varint.decode_bytes(length_bytes)\n"
            "            # Read response data\n",
            "                    break\n"
            "                    if len(length_bytes) >= 5:\n"
            "                        logger.warning(\"DHT ADD_PROVIDER frame length prefix exceeded bound\")\n"
            "                        return False\n\n"
            "            response_length = varint.decode_bytes(length_bytes)\n"
            "            if (varint.encode(response_length) != length_bytes\n"
            "                    or response_length > MAX_DHT_MESSAGE_SIZE):\n"
            "                logger.warning(\"DHT ADD_PROVIDER response frame invalid or oversized\")\n"
            "                return False\n"
            "            # Read response data\n",
            "bounded ADD_PROVIDER acknowledgement frame",
        ),
        (
            "                    break\n\n"
            "                response_length = varint.decode_bytes(length_bytes)\n"
            "                # Read response data\n",
            "                    break\n"
            "                    if len(length_bytes) >= 5:\n"
            "                        logger.warning(\"DHT GET_PROVIDERS frame length prefix exceeded bound\")\n"
            "                        return []\n\n"
            "                response_length = varint.decode_bytes(length_bytes)\n"
            "                if (varint.encode(response_length) != length_bytes\n"
            "                        or response_length > MAX_DHT_MESSAGE_SIZE):\n"
            "                    logger.warning(\"DHT GET_PROVIDERS response frame invalid or oversized\")\n"
            "                    return []\n"
            "                # Read response data\n",
            "bounded GET_PROVIDERS response frame",
        ),
    )
    for old,new,label in patterns:
        text = replace_once(text, old, new, label)
    ast.parse(text, filename=str(path))
    path.write_text(text,encoding="utf-8")


def patch_peer_routing(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from .common import (\n    ALPHA,\n    PROTOCOL_ID,\n)\n",
        "from .common import (\n    ALPHA,\n    PROTOCOL_ID,\n)\n"
        "from .pinned_lookup_outcomes import MAX_DHT_MESSAGE_SIZE\n",
        "peer routing message-size import",
    )
    text = replace_once(
        text,
        "                if b[0] & 0x80 == 0:\n"
        "                    break\n"
        "            response_length = varint.decode_bytes(length_bytes)\n\n"
        "            # Read response data\n",
        "                if b[0] & 0x80 == 0:\n"
        "                    break\n"
        "                if len(length_bytes) >= 5:\n"
        "                    logger.warning(\"FIND_NODE frame length prefix exceeded bound\")\n"
        "                    return []\n"
        "            response_length = varint.decode_bytes(length_bytes)\n"
        "            if (varint.encode(response_length) != length_bytes\n"
        "                    or response_length > MAX_DHT_MESSAGE_SIZE):\n"
        "                logger.warning(\"FIND_NODE response frame invalid or oversized\")\n"
        "                return []\n\n"
        "            # Read response data\n",
        "bounded FIND_NODE response frame",
    )
    ast.parse(text, filename=str(path))
    path.write_text(text,encoding="utf-8")


def patch_registry(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from libp2p.kad_dht.kad_dht import DHTMode, KadDHT\n",
        "from libp2p.kad_dht.kad_dht import DHTMode, KadDHT\n"
        "from libp2p.kad_dht.pinned_lookup_outcomes import (\n"
        "    DHTLookupUnavailable,\n"
        "    DHTUnvalidatedRecords,\n"
        "    LookupCounts,\n"
        "    MAX_IDENTITY_CANDIDATE_BYTES,\n"
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
        '''        try:
            return await self.dht.get_value(kad_key, quorum=quorum)
        except DHTUnvalidatedRecords as exc:
            # Candidates from completed primary peer replies remain positive
            # evidence if Registry authentication/history cannot accept them.
            candidates = tuple(exc.records)
            try:
                kind, record_key = _RegistryDHTValueValidator._parse_key(kad_key)
                if kind != "identity" or not self._bootstrap_peers:
                    raise ValueError("Identity history recovery is unavailable")
                for candidate in candidates:
                    _RegistryDHTValueValidator._metadata(kad_key, candidate)
                    try:
                        self._validator.validate_identity_get(
                            record_key=record_key, envelope_cbor=candidate,
                        )
                    except Exception:
                        chain = await self._read_remote_identity_predecessor_chain(
                            record_key.hex(), candidate,
                        )
                        if chain is None:
                            raise ValueError("authenticated Identity history unavailable")
                        self._validator.validate_identity_get(
                            record_key=record_key, envelope_cbor=candidate,
                            predecessor_chain=chain,
                        )
                selected = _RegistryDHTValueValidator(self).select(kad_key, candidates)
                return candidates[selected]
            except DHTLookupUnavailable:
                raise
            except Exception:
                # Preserve primary candidates and reconcile them with bootstrap
                # evidence in the caller; never convert them to clean absence.
                raise DHTUnvalidatedRecords("get_value", exc.counts, candidates) from None
''',
        "Registry DHT exception propagation",
    )
    text = replace_once(
        text,
        "        raw_dht = await self._read_dht_value(kad_key, quorum=quorum)\n"
        "        if raw_dht is None and self._bootstrap_peers:\n"
        "            raw_dht = await self.read_remote_identity_envelope(object_key_hex)\n"
        "        raw_local = self._durable_get(kind=\"identity\", key=record_key)\n"
        "        try:\n"
        "            raw_current = _select_newest_envelope(raw_dht, raw_local)\n"
        "        except Exception:\n"
        "            return None\n",
        "        raw_dht = await self._read_dht_value(kad_key, quorum=quorum)\n"
        "        if self._bootstrap_peers:\n"
        "            raw_remote = await self.read_remote_identity_envelope(object_key_hex)\n"
        "            if raw_dht is None:\n"
        "                raw_dht = raw_remote\n"
        "            elif raw_remote is None:\n"
        "                counts = LookupCounts(failed=1)\n"
        "                report_lookup_summary(\"get_value\", counts)\n"
        "                raise DHTLookupUnavailable(\"get_value\", counts)\n"
        "            else:\n"
        "                try:\n"
        "                    raw_dht = _select_newest_envelope(raw_dht, raw_remote)\n"
        "                except Exception:\n"
        "                    counts = LookupCounts(failed=1)\n"
        "                    report_lookup_summary(\"get_value\", counts)\n"
        "                    raise DHTLookupUnavailable(\"get_value\", counts) from None\n"
        "        raw_local = self._durable_get(kind=\"identity\", key=record_key)\n"
        "        if raw_dht is None and raw_local is not None:\n"
        "            counts = LookupCounts(failed=1)\n"
        "            report_lookup_summary(\"get_value\", counts)\n"
        "            raise DHTLookupUnavailable(\"get_value\", counts)\n"
        "        try:\n"
        "            raw_current = _select_newest_envelope(raw_dht, raw_local)\n"
        "        except Exception:\n"
        "            counts = LookupCounts(failed=1)\n"
        "            report_lookup_summary(\"get_value\", counts)\n"
        "            raise DHTLookupUnavailable(\"get_value\", counts) from None\n",
        "compare primary, bootstrap and durable Identity heads",
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

        bootstrap_peers = tuple(self._bootstrap_peers)
        counts = LookupCounts()
        records_size = 0
        remote_reader = self._remote_identity_reader
        if remote_reader is not None:
            counts.attempts += 1
            try:
                envelope = await remote_reader.read_remote_identity_envelope(
                    canonical_object_key_hex
                )
            except Exception:
                counts.failed += 1
                report_lookup_summary("remote_identity", counts)
                raise DHTLookupUnavailable("remote_identity", counts) from None
            if not isinstance(envelope, (bytes, bytearray)):
                counts.failed += 1
                report_lookup_summary("remote_identity", counts)
                raise DHTLookupUnavailable("remote_identity", counts) from None
            envelope_size = max(len(envelope), memoryview(envelope).nbytes)
            if envelope_size > MAX_IDENTITY_CANDIDATE_BYTES:
                counts.failed += 1
                report_lookup_summary("remote_identity", counts)
                raise DHTLookupUnavailable("remote_identity", counts) from None
            remote_candidate = memoryview(envelope).tobytes()
            counts.records.append(remote_candidate)
            counts.positive_records += 1
            records_size = len(remote_candidate)

        if not bootstrap_peers:
            report_lookup_summary("remote_identity", counts)
            raise DHTLookupUnavailable("remote_identity", counts)

        try:
            kad_key = self._kad_key(
                canonical_object_key_hex, kind="identity"
            ).encode("utf-8")
            local_host = getattr(self, "_host", None)
            local_peer_id = None if local_host is None else local_host.get_id()
        except Exception:
            counts.failed += 1
            report_lookup_summary("remote_identity", counts)
            raise DHTLookupUnavailable("remote_identity", counts) from None

        records_size = sum(map(len, counts.records))
        bootstrap_peer_records = 0
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
                # Reuse the active client host for a direct GET_VALUE. This
                # bypasses KadDHT.get_value's cache/repair path without creating
                # a second peer identity that the Registry can refer back to.
                await self.bootstrap(peer)
                record = await self.dht.value_store._get_from_peer(
                    peer_info.peer_id,
                    kad_key,
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
            candidate_size = max(len(candidate), memoryview(candidate).nbytes)
            if candidate_size > MAX_IDENTITY_CANDIDATE_BYTES:
                counts.failed += 1
                continue
            counts.positive_records += 1
            bootstrap_peer_records += 1
            if candidate in counts.records:
                continue
            if (len(counts.records) >= 64
                    or records_size + candidate_size > MAX_IDENTITY_CANDIDATE_BYTES):
                counts.failed += 1
                continue
            candidate_bytes = memoryview(candidate).tobytes()
            counts.records.append(candidate_bytes)
            records_size += len(candidate_bytes)

        if remote_reader is not None and bootstrap_peer_records == 0:
            counts.failed += 1
        if (counts.failed or counts.timeouts or counts.incomplete
                or counts.attempts != counts.positive_records + counts.empty):
            report_lookup_summary("remote_identity", counts)
            raise DHTLookupUnavailable("remote_identity", counts)
        if not counts.records:
            report_lookup_summary("remote_identity", counts)
            if counts.is_clean_absence():
                return None
            raise DHTLookupUnavailable("remote_identity", counts)

        candidates = list(counts.records)
        if len(set(candidates)) > 1:
            try:
                registry_key = kad_key.decode("utf-8")
                kind, record_key = _RegistryDHTValueValidator._parse_key(registry_key)
                if kind != "identity":
                    raise ValueError("unexpected Registry record kind")
                for candidate in candidates:
                    _RegistryDHTValueValidator._metadata(registry_key, candidate)
                    try:
                        self._validator.validate_identity_get(
                            record_key=record_key,
                            envelope_cbor=candidate,
                        )
                    except Exception:
                        chain = await self._read_remote_identity_predecessor_chain(
                            record_key.hex(), candidate,
                        )
                        if chain is None:
                            raise ValueError("authenticated Identity history unavailable")
                        self._validator.validate_identity_get(
                            record_key=record_key,
                            envelope_cbor=candidate,
                            predecessor_chain=chain,
                        )
                selected = _RegistryDHTValueValidator(self).select(
                    registry_key, candidates
                )
                return candidates[selected]
            except Exception:
                report_lookup_summary("remote_identity", counts)
                raise DHTLookupUnavailable("remote_identity", counts) from None
        return candidates[0]

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
    provider_store = package / "provider_store.py"
    peer_routing = package / "peer_routing.py"
    for path in (value_store, kad_dht, provider_store, peer_routing, registry_file):
        if not path.is_file():
            raise RuntimeError(f"pinned runtime source is missing: {path.name}")
    if (package / "pinned_lookup_outcomes.py").exists():
        raise RuntimeError("pinned resolver overlay helper already exists")
    patch_value_store(value_store)
    patch_kad_dht(kad_dht)
    patch_provider_store(provider_store)
    patch_peer_routing(peer_routing)
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
