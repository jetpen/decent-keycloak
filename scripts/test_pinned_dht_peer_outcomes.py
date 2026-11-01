"""Behavioral regressions for the locked libp2p peer-query implementation."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE_ROOT = os.environ.get("RESOLVER_TEST_LIBP2P_SOURCE")
if SOURCE_ROOT:
    sys.path.insert(0, SOURCE_ROOT)

import trio
import varint
from libp2p.kad_dht.kad_dht import DHTMode, KadDHT
from libp2p.kad_dht.pb.kademlia_pb2 import Message, Record
from libp2p.kad_dht.value_store import ValueStore
from libp2p.kad_dht.pinned_lookup_outcomes import (
    DHTLookupUnavailable,
    LookupCounts,
    MAX_DHT_MESSAGE_SIZE,
    _CURRENT_LOOKUP_COUNTS,
    check_identity_candidate_selection,
    install,
)


class PeerOutcomeTest(unittest.TestCase):
    def _response(
        self,
        *,
        message_type=None,
        closer_peers=0,
        malformed=False,
        response_key=b"/decent-registry/identity/" + b"aa" * 32,
        record_key=None,
        sender_record=None,
        record_value=None,
    ):
        if malformed:
            payload = b"\xff"
        else:
            message = Message()
            message.type = message_type or Message.MessageType.GET_VALUE
            message.key = response_key
            if record_value is not None:
                message.record.key = record_key or response_key
                message.record.value = record_value
            if sender_record is not None:
                message.senderRecord = sender_record
            for _ in range(closer_peers):
                message.closerPeers.add().id = b"unparsed-peer-id"
            payload = message.SerializeToString()
        return bytearray(varint.encode(len(payload)) + payload)

    def _make_dht(self, outcomes):
        queried_peers = []
        read_sizes = []

        class Stream:
            def __init__(self, response):
                self.response = response

            async def write(self, _data):
                pass

            async def read(self, size):
                read_sizes.append(size)
                chunk = bytes(self.response[:size])
                del self.response[:size]
                return chunk

            async def close(self):
                pass

        class CloseFailureStream(Stream):
            async def close(self):
                raise OSError("stream close failed")

        class Host:
            async def new_stream(_self, peer_id, _protocols):
                queried_peers.append(peer_id)
                outcome = outcomes[peer_id]
                if outcome == "closed":
                    return Stream(bytearray())
                if outcome == "close-fail":
                    return CloseFailureStream(self._response())
                if outcome == "delayed":
                    class DelayedStream(Stream):
                        async def read(self, _size):
                            await trio.sleep(0.1)
                            return b""
                    return DelayedStream(bytearray())
                return Stream(outcome)

        class RoutingTable:
            def find_local_closest_peers(_self, _key):
                return list(outcomes)

        store = ValueStore(Host(), local_peer_id="local")
        dht = KadDHT.__new__(KadDHT)
        dht.value_store = store
        dht.routing_table = RoutingTable()
        dht.local_peer_id = "local"
        dht.validator = None
        dht.queried_peers = queried_peers
        dht.response_read_sizes = read_sizes
        return dht

    def _run_dht(self, dht, key="/decent-registry/identity/" + "aa" * 32, quorum=0):
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            return trio.run(dht.get_value, key, quorum)

    def test_candidate_overflow_is_not_returned_to_generic_selection(self):
        key = b"/decent-registry/identity/" + b"ef" * 32
        too_large = b"x" * (4 * 1024 * 1024 + 1)

        class OversizedStore:
            async def _get_from_peer(self, _peer_id, requested_key, return_record=False):
                return Record(key=requested_key, value=too_large)

        class DummyDht:
            async def get_value(self, _key, quorum=0):
                return None

        install(DummyDht, OversizedStore)
        store = OversizedStore()
        counts = LookupCounts()
        token = _CURRENT_LOOKUP_COUNTS.set(counts)
        try:
            result = trio.run(store._get_from_peer, "peer", key, True)
        finally:
            _CURRENT_LOOKUP_COUNTS.reset(token)

        self.assertEqual("PeerValueUnavailable", type(result).__name__)
        self.assertEqual(1, counts.failed)
        self.assertEqual([], counts.records)

    def test_record_over_one_megabyte_remains_readable_within_registry_history_budget(self):
        key = b"/decent-registry/identity/" + b"aa" * 32
        value = b"x" * (1024 * 1024 + 1)
        message = Message()
        message.type = Message.MessageType.GET_VALUE
        message.key = key
        message.record.key = key
        message.record.value = value
        payload = message.SerializeToString()
        dht = self._make_dht({
            "peer": bytearray(varint.encode(len(payload)) + payload),
        })
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(
                dht.value_store._get_from_peer,
                "peer",
                key,
                True,
            )
        self.assertIsInstance(result, Record)
        self.assertGreater(len(result.value), 1024 * 1024)

    def test_four_mebibyte_identity_value_is_rejected_when_frame_exceeds_total_cap(self):
        key = b"/decent-registry/identity/" + b"ab" * 32
        value = b"x" * (MAX_DHT_MESSAGE_SIZE - 32)
        message = Message()
        message.type = Message.MessageType.GET_VALUE
        message.key = key
        message.record.key = key
        message.record.value = value
        payload = message.SerializeToString()
        self.assertGreater(len(payload), MAX_DHT_MESSAGE_SIZE)
        dht = self._make_dht({"peer": bytearray(varint.encode(len(payload)) + payload)})
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertEqual("PeerValueUnavailable", type(result).__name__)
        self.assertLessEqual(max(dht.response_read_sizes), 5)

    def test_non_identity_near_cap_record_fits_complete_frame_budget(self):
        key = b"/decent-registry/provider/" + b"ab" * 32
        value = b"x" * (MAX_DHT_MESSAGE_SIZE - 256)
        message = Message()
        message.type = Message.MessageType.GET_VALUE
        message.key = key
        message.record.key = key
        message.record.value = value
        payload = message.SerializeToString()
        self.assertLessEqual(len(payload), MAX_DHT_MESSAGE_SIZE)
        dht = self._make_dht({"peer": bytearray(varint.encode(len(payload)) + payload)})
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertIsInstance(result, Record)
        self.assertEqual(value, result.value)

    def test_non_identity_oversized_frame_is_rejected_before_body_read(self):
        key = b"/decent-registry/provider/" + b"ab" * 32
        prefix = varint.encode(MAX_DHT_MESSAGE_SIZE + 1)
        dht = self._make_dht({"peer": bytearray(prefix)})
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertIsNone(result)
        self.assertEqual(len(prefix), len(dht.response_read_sizes))

    def test_oversized_declared_response_is_rejected_before_body_read(self):
        maximum = MAX_DHT_MESSAGE_SIZE
        key = b"/decent-registry/identity/" + b"aa" * 32
        dht = self._make_dht({
            "peer": bytearray(varint.encode(maximum + 1)),
        })

        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(
                dht.value_store._get_from_peer,
                "peer",
                key,
                True,
            )

        self.assertEqual("PeerValueUnavailable", type(result).__name__)
        self.assertTrue(dht.response_read_sizes)
        self.assertLessEqual(max(dht.response_read_sizes), maximum)

    def test_overlong_response_length_prefix_is_bounded(self):
        key = b"/decent-registry/identity/" + b"aa" * 32
        dht = self._make_dht({
            "peer": bytearray(b"\x80" * 6),
        })
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(
                dht.value_store._get_from_peer,
                "peer",
                key,
                True,
            )
        self.assertEqual("PeerValueUnavailable", type(result).__name__)
        self.assertEqual(5, len(dht.response_read_sizes))

    def test_get_value_rejects_noncanonical_complete_length_prefix(self):
        key = b"/decent-registry/identity/" + b"aa" * 32
        response = Message()
        response.type = Message.MessageType.GET_VALUE
        response.key = key
        payload = response.SerializeToString()
        self.assertLess(len(payload), 128)
        prefix = bytes((len(payload) | 0x80, 0))
        dht = self._make_dht({"peer": bytearray(prefix + payload)})
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertEqual("PeerValueUnavailable", type(result).__name__)
        self.assertEqual([1, 1], dht.response_read_sizes)

    def test_put_value_ack_frame_is_bounded(self):
        maximum = MAX_DHT_MESSAGE_SIZE
        key = b"/test/key"
        dht = self._make_dht({"peer": bytearray(varint.encode(maximum + 1))})
        dht.value_store.store[key] = (
            Record(key=key, value=b"published-value"), float("inf"))
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(
                dht.value_store._store_at_peer, "peer", key, b"published-value")
        self.assertFalse(result)
        self.assertLessEqual(max(dht.response_read_sizes), maximum)

    def test_put_value_ack_rejects_noncanonical_complete_length_prefix(self):
        key = b"/test/key"
        response = Message()
        response.type = Message.MessageType.PUT_VALUE
        response.key = key
        payload = response.SerializeToString()
        self.assertLess(len(payload), 128)
        prefix = bytes((len(payload) | 0x80, 0))
        dht = self._make_dht({"peer": bytearray(prefix + payload)})
        dht.value_store.store[key] = (
            Record(key=key, value=b"published-value"), float("inf"))
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(
                dht.value_store._store_at_peer, "peer", key, b"published-value")
        self.assertFalse(result)
        self.assertEqual([1, 1], dht.response_read_sizes)

    def test_put_value_ack_overlong_prefix_is_bounded(self):
        key = b"/test/key"
        dht = self._make_dht({"peer": bytearray(b"\x80" * 6)})
        dht.value_store.store[key] = (
            Record(key=key, value=b"published-value"), float("inf"))
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(
                dht.value_store._store_at_peer, "peer", key, b"published-value")
        self.assertFalse(result)
        self.assertEqual(5, len(dht.response_read_sizes))

    def test_non_identity_candidates_are_not_subject_to_identity_retention_cap(self):
        key = b"/decent-registry/provider/" + b"ab" * 32

        class Store:
            async def _get_from_peer(self, _peer_id, requested_key, return_record=False):
                return Record(key=requested_key, value=b"best-value")

        class DummyDht:
            async def get_value(self, _key, quorum=0):
                return None

        install(DummyDht, Store)
        store = Store()
        counts = LookupCounts(attempts=64, records=[b"prior"] * 64)
        token = _CURRENT_LOOKUP_COUNTS.set(counts)
        try:
            result = trio.run(store._get_from_peer, "peer", key, True)
        finally:
            _CURRENT_LOOKUP_COUNTS.reset(token)
        self.assertEqual("Record", type(result).__name__)
        self.assertEqual(0, counts.failed)
        self.assertEqual(64, len(counts.records))

    def test_duplicate_large_identity_candidates_are_retained_once(self):
        key = b"/decent-registry/identity/" + b"ab" * 32
        value = b"large-value" * (200 * 1024)

        class Store:
            async def _get_from_peer(self, _peer_id, requested_key, return_record=False):
                return Record(key=requested_key, value=bytes(bytearray(value)))

        class DummyDht:
            async def get_value(self, _key, quorum=0):
                return None

        install(DummyDht, Store)
        store = Store()
        counts = LookupCounts()
        token = _CURRENT_LOOKUP_COUNTS.set(counts)
        try:
            results = [
                trio.run(store._get_from_peer, f"peer-{index}", key, True)
                for index in range(3)
            ]
        finally:
            _CURRENT_LOOKUP_COUNTS.reset(token)
        self.assertTrue(all(isinstance(result, Record) for result in results))
        self.assertEqual(3, counts.positive_records)
        self.assertEqual([value], counts.records)
        self.assertEqual(0, counts.failed)

    def test_non_identity_get_value_errors_keep_generic_classification(self):
        class Store:
            async def _get_from_peer(self, *_args, **_kwargs):
                return None

        class DummyDht:
            async def get_value(self, _key, quorum=0):
                raise ValueError("generic lookup failure")

        install(DummyDht, Store)
        with self.assertRaisesRegex(ValueError, "generic lookup failure"):
            trio.run(DummyDht().get_value, "/decent-registry/provider/ab", 0)

    def test_record_with_unqueried_referrals_is_not_a_complete_candidate(self):
        dht = self._make_dht({
            "peer": self._response(record_value=b"legacy-head", closer_peers=1),
        })
        key = b"/decent-registry/identity/" + b"aa" * 32
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertEqual("PeerValueIncomplete", type(result).__name__)

    def test_positive_record_requires_exact_message_key(self):
        dht = self._make_dht({
            "peer": self._response(
                response_key=b"/different/key",
                record_key=b"/decent-registry/identity/" + b"aa" * 32,
                record_value=b"value",
            ),
        })

        key = b"/decent-registry/identity/" + b"aa" * 32
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertEqual("PeerValueUnavailable", type(result).__name__)

    def test_positive_record_requires_exact_record_key(self):
        dht = self._make_dht({
            "peer": self._response(
                record_key=b"/different/key", record_value=b"value",
            ),
        })

        key = b"/decent-registry/identity/" + b"aa" * 32
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertEqual("PeerValueUnavailable", type(result).__name__)

    def test_non_identity_empty_peer_reply_keeps_generic_none_result(self):
        key = b"/decent-registry/provider/" + b"ab" * 32
        dht = self._make_dht({
            "peer": self._response(response_key=key),
        })
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertIsNone(result)

    def test_non_identity_failed_peer_reply_keeps_generic_none_result(self):
        key = b"/decent-registry/provider/" + b"ab" * 32
        for outcome in ("closed", self._response(malformed=True)):
            with self.subTest(outcome=outcome if isinstance(outcome, str) else "malformed"):
                dht = self._make_dht({"peer": outcome})
                with patch(
                    "libp2p.kad_dht.value_store.env_to_send_in_RPC",
                    return_value=(b"", None),
                ):
                    result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
                self.assertIsNone(result)

    def test_non_identity_record_with_referral_keeps_generic_record_result(self):
        key = b"/decent-registry/provider/" + b"ab" * 32
        dht = self._make_dht({
            "peer": self._response(
                response_key=key, record_value=b"provider-value", closer_peers=1,
            ),
        })
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertIsInstance(result, Record)
        self.assertEqual(b"provider-value", result.value)

    def test_non_identity_positive_record_with_mismatched_message_key_keeps_generic_result(self):
        """Characterize generic provider reads; exact-key rejection is Identity-scoped."""
        key = b"/decent-registry/provider/" + b"ab" * 32
        dht = self._make_dht({
            "peer": self._response(
                response_key=b"/different/message-key",
                record_key=key,
                record_value=b"provider-value",
            ),
        })
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            result = trio.run(dht.value_store._get_from_peer, "peer", key, True)
        self.assertIsInstance(result, Record)
        self.assertEqual(b"provider-value", result.value)

    def test_mixed_identity_heads_are_deferred_to_authenticated_registry_selection(self):
        key = "/decent-registry/identity/" + "ab" * 32
        dht = self._make_dht({
            "legacy-peer": self._response(record_value=b"legacy-head", response_key=key.encode()),
            "rotated-peer": self._response(record_value=b"history-dependent-head", response_key=key.encode()),
        })

        class Validator:
            def validate(self, _key, value):
                if value != b"legacy-head":
                    raise ValueError("requires authenticated predecessor context")

            def select(self, _key, values):
                return 0

        dht.validator = Validator()
        with self.assertRaises(Exception) as context:
            self._run_dht(dht, key)
        self.assertEqual("DHTUnvalidatedRecords", type(context.exception).__name__)
        self.assertCountEqual(
            (b"legacy-head", b"history-dependent-head"), context.exception.records)

    def test_client_identity_quorum_does_not_hide_unqueried_mixed_head(self):
        key = "/decent-registry/identity/" + "ab" * 32
        dht = self._make_dht({
            "legacy-peer": self._response(record_value=b"legacy-head", response_key=key.encode()),
            "rotated-peer": self._response(record_value=b"history-dependent-head", response_key=key.encode()),
        })
        dht.mode = DHTMode.CLIENT

        class Validator:
            def validate(self, _key, value):
                if value != b"legacy-head":
                    raise ValueError("requires authenticated predecessor context")

            def select(self, _key, _values):
                return 0

        dht.validator = Validator()
        records = {
            "legacy-peer": b"legacy-head",
            "rotated-peer": b"history-dependent-head",
        }

        async def direct_peer_read(peer_id, requested_key, return_record=False):
            dht.queried_peers.append(peer_id)
            counts = _CURRENT_LOOKUP_COUNTS.get()
            counts.attempts += 1
            value = records[peer_id]
            counts.records.append(value)
            return Record(key=requested_key, value=value)

        dht.value_store._get_from_peer = direct_peer_read
        with patch("libp2p.kad_dht.kad_dht.ALPHA", 1):
            with self.assertRaises(Exception) as context:
                self._run_dht(dht, key, quorum=1)
        self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)
        self.assertIn("rotated-peer", dht.queried_peers)

    def test_client_identity_cache_does_not_hide_newer_mixed_peer_head(self):
        key = "/decent-registry/identity/" + "da" * 32
        dht = self._make_dht({
            "legacy-peer": self._response(record_value=b"legacy-head", response_key=key.encode()),
            "rotated-peer": self._response(record_value=b"history-dependent-head", response_key=key.encode()),
        })
        dht.mode = DHTMode.CLIENT
        dht.value_store.store[key.encode()] = (
            Record(key=key.encode(), value=b"cached-legacy-head"), float("inf"))

        class Validator:
            def validate(self, _key, value):
                if value != b"legacy-head":
                    raise ValueError("requires authenticated predecessor context")

            def select(self, _key, _values):
                return 0

        dht.validator = Validator()
        with self.assertRaises(Exception) as context:
            self._run_dht(dht, key)
        self.assertEqual("DHTUnvalidatedRecords", type(context.exception).__name__)
        self.assertCountEqual(
            (b"legacy-head", b"history-dependent-head"), context.exception.records)

    def test_server_identity_cache_does_not_hide_newer_mixed_peer_head(self):
        key = "/decent-registry/identity/" + "bc" * 32
        dht = self._make_dht({
            "legacy-peer": self._response(record_value=b"legacy-head", response_key=key.encode()),
            "rotated-peer": self._response(record_value=b"history-dependent-head", response_key=key.encode()),
        })
        dht.mode = DHTMode.SERVER
        dht.value_store.store[key.encode()] = (
            Record(key=key.encode(), value=b"cached-legacy-head"), float("inf"))

        class Validator:
            def validate(self, _key, value):
                if value != b"legacy-head":
                    raise ValueError("requires authenticated predecessor context")

            def select(self, _key, _values):
                return 0

        dht.validator = Validator()
        with self.assertRaises(Exception) as context:
            self._run_dht(dht, key)
        self.assertEqual("DHTUnvalidatedRecords", type(context.exception).__name__)
        self.assertCountEqual(
            (b"legacy-head", b"history-dependent-head"), context.exception.records)
        self.assertIn("rotated-peer", dht.queried_peers)

    def test_mixed_identity_head_and_peer_failure_stays_unavailable(self):
        key = "/decent-registry/identity/" + "cd" * 32
        dht = self._make_dht({
            "legacy-peer": self._response(record_value=b"legacy-head", response_key=key.encode()),
            "failed-peer": "closed",
        })

        class Validator:
            def validate(self, _key, value):
                if value != b"legacy-head":
                    raise ValueError("invalid")

            def select(self, _key, _values):
                return 0

        dht.validator = Validator()
        with self.assertRaises(Exception) as context:
            self._run_dht(dht, key)
        self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)

    def test_identity_lookup_failure_without_retained_candidates_is_unavailable(self):
        key = "/decent-registry/identity/" + "ab" * 32
        counts = LookupCounts(attempts=1, failed=1)
        token = _CURRENT_LOOKUP_COUNTS.set(counts)
        try:
            with self.assertRaises(Exception) as context:
                check_identity_candidate_selection(key, 0)
            self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)
        finally:
            _CURRENT_LOOKUP_COUNTS.reset(token)

    def test_identity_mixed_candidates_with_nonzero_quorum_are_unavailable(self):
        counts = LookupCounts(attempts=2, records=[b"legacy", b"rotated"])
        token = _CURRENT_LOOKUP_COUNTS.set(counts)
        try:
            with self.assertRaises(Exception) as context:
                check_identity_candidate_selection(
                    "/decent-registry/identity/" + "ab" * 32, 1)
            self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)
        finally:
            _CURRENT_LOOKUP_COUNTS.reset(token)

    def test_mixed_nonidentity_values_keep_existing_selection_path(self):
        counts = LookupCounts(attempts=2, records=[b"first", b"second"])
        token = _CURRENT_LOOKUP_COUNTS.set(counts)
        try:
            check_identity_candidate_selection(
                "/decent-registry/provider/" + "ef" * 32, 0)
        finally:
            _CURRENT_LOOKUP_COUNTS.reset(token)

    def test_failed_stream_close_is_not_a_valid_negative(self):
        dht = self._make_dht({"peer": "closed"})
        try:
            self._run_dht(dht)
        except Exception as exc:
            self.assertEqual("DHTLookupUnavailable", type(exc).__name__)
        else:
            self.fail("a closed peer stream must not become terminal not_found")

    def test_valid_empty_reply_is_a_distinct_negative(self):
        dht = self._make_dht({"peer": self._response()})
        self.assertIsNone(self._run_dht(dht))

    def test_close_failure_after_valid_empty_reply_is_not_a_terminal_negative(self):
        dht = self._make_dht({"peer": "close-fail"})
        with self.assertRaises(Exception) as context:
            self._run_dht(dht)
        self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)

    def test_zero_peer_attempts_are_unavailable_not_absence(self):
        dht = self._make_dht({})
        try:
            self._run_dht(dht)
        except Exception as exc:
            self.assertEqual("DHTLookupUnavailable", type(exc).__name__)
        else:
            self.fail("zero peer attempts cannot establish absence")

    def test_mixed_valid_empty_and_failed_peer_is_unavailable(self):
        dht = self._make_dht({"empty": self._response(), "closed": "closed"})
        try:
            self._run_dht(dht)
        except Exception as exc:
            self.assertEqual("DHTLookupUnavailable", type(exc).__name__)
        else:
            self.fail("a failed peer must prevent a terminal absence result")

    def test_incomplete_referral_is_not_a_terminal_negative(self):
        dht = self._make_dht({"peer": self._response(closer_peers=1)})
        try:
            self._run_dht(dht)
        except Exception as exc:
            self.assertEqual("DHTLookupUnavailable", type(exc).__name__)
        else:
            self.fail("unqueried closer peers must prevent a terminal absence result")

    def test_wrong_message_type_is_not_a_terminal_negative(self):
        dht = self._make_dht(
            {"peer": self._response(message_type=Message.MessageType.PING)}
        )
        with self.assertRaises(Exception) as context:
            self._run_dht(dht)
        self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)

    def test_mismatched_response_key_is_not_a_terminal_negative(self):
        dht = self._make_dht({"peer": self._response(response_key=b"/other/key")})
        with self.assertRaises(Exception) as context:
            self._run_dht(dht)
        self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)

    def test_invalid_sender_record_is_not_a_terminal_negative(self):
        dht = self._make_dht({"peer": self._response(sender_record=b"\\xff")})
        with self.assertRaises(Exception) as context:
            self._run_dht(dht)
        self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)

    def test_peer_timeout_is_not_a_terminal_negative(self):
        dht = self._make_dht({"peer": "delayed"})
        with patch("libp2p.kad_dht.kad_dht.QUERY_TIMEOUT", 0.01):
            with self.assertLogs("libp2p.kad_dht.kad_dht", level="WARNING") as logs:
                with self.assertRaises(Exception) as context:
                    self._run_dht(dht)
        self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)
        self.assertTrue(any(
            "DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=0 failed=0 timeouts=1 incomplete=0"
            in line for line in logs.output
        ))

    def test_malformed_response_is_not_a_terminal_negative(self):
        dht = self._make_dht({"peer": self._response(malformed=True)})
        try:
            self._run_dht(dht)
        except Exception as exc:
            self.assertEqual("DHTLookupUnavailable", type(exc).__name__)
        else:
            self.fail("a malformed response must not establish absence")

    def test_unvalidated_records_are_distinct_from_failed_or_empty_reads(self):
        dht = self._make_dht({"peer": self._response(record_value=b"needs-history")})

        class Validator:
            def validate(self, _key, _value):
                raise ValueError("requires authenticated predecessor context")

        dht.validator = Validator()
        with self.assertRaises(Exception) as context:
            self._run_dht(dht)
        self.assertEqual("DHTUnvalidatedRecords", type(context.exception).__name__)
        self.assertEqual((b"needs-history",), context.exception.records)

    def test_unvalidated_record_mixed_with_failed_peer_stays_unavailable(self):
        dht = self._make_dht({
            "record": self._response(record_value=b"needs-history"), "failed": "closed",
        })

        class Validator:
            def validate(self, _key, _value):
                raise ValueError("requires authenticated predecessor context")

        dht.validator = Validator()
        with self.assertRaises(Exception) as context:
            self._run_dht(dht)
        self.assertEqual("DHTLookupUnavailable", type(context.exception).__name__)


if __name__ == "__main__":
    unittest.main()
