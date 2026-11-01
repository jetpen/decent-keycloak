"""Behavioral regressions for Registry propagation of pinned DHT outcomes."""
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

LIBP2P_SOURCE = os.environ.get("RESOLVER_TEST_LIBP2P_SOURCE")
if LIBP2P_SOURCE:
    sys.path.insert(0, LIBP2P_SOURCE)
REGISTRY_SOURCE = os.environ.get("RESOLVER_TEST_REGISTRY_SOURCE")
if REGISTRY_SOURCE:
    sys.path.insert(0, REGISTRY_SOURCE)

import trio
import decent_registry.dht.libp2p_dht as registry_module
from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from libp2p.kad_dht.pinned_lookup_outcomes import (
    DHTLookupUnavailable,
    DHTUnvalidatedRecords,
    LookupCounts,
    PeerValueAbsent,
    PeerValueIncomplete,
    PeerValueUnavailable,
)


class RegistryLookupOutcomeTest(unittest.TestCase):
    def test_dht_read_exception_is_not_swallowed(self):
        class DHT:
            async def get_value(self, _key, quorum=0):
                raise DHTLookupUnavailable("get_value", SimpleNamespace(
                    attempts=0, empty=0, failed=1, timeouts=0, incomplete=0
                ))

        holder = SimpleNamespace(dht=DHT())
        with self.assertRaises(DHTLookupUnavailable):
            trio.run(Libp2pKadDHT._read_dht_value, holder, "/key")

    def _holder(self, result, peers=("peer-address",)):
        class RemoteDht:
            def __init__(self, **_kwargs):
                self.dht = SimpleNamespace(value_store=SimpleNamespace(
                    _get_from_peer=self._read
                ))

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def _kad_key(self, _object_key, *, kind):
                return f"/decent-registry/{kind}/key"

            async def bootstrap(self, _peer):
                pass

            async def _read(self, _peer_id, _key, return_record=False):
                return result

        async def direct_read(_peer_id, _key, return_record=False):
            return result

        async def bootstrap(_peer):
            pass

        holder = SimpleNamespace(
            _remote_identity_reader=None,
            _bootstrap_peers=peers,
            _host=None,
            _kad_key=lambda _object_key, *, kind: f"/decent-registry/{kind}/key",
            dht=SimpleNamespace(value_store=SimpleNamespace(
                _get_from_peer=direct_read
            )),
            bootstrap=bootstrap,
        )
        return holder, RemoteDht

    def _read_remote(self, holder, remote_dht):
        with (
            patch.object(registry_module, "Libp2pKadDHT", remote_dht),
            patch.object(registry_module, "Multiaddr", lambda address: address),
            patch.object(
                registry_module,
                "info_from_p2p_addr",
                lambda _address: SimpleNamespace(peer_id="peer-id"),
            ),
        ):
            return trio.run(
                Libp2pKadDHT.read_remote_identity_envelope,
                holder,
                "ab" * 32,
            )

    def test_remote_direct_read_reuses_primary_host_for_direct_query(self):
        calls = []
        bootstrap_calls = []
        holder, remote_dht = self._holder(PeerValueAbsent())

        async def direct_read(peer_id, key, return_record=False):
            calls.append((peer_id, key, return_record))
            return PeerValueAbsent()

        async def bootstrap(peer):
            bootstrap_calls.append(peer)

        object_key = "ab" * 32
        expected_key = f"/decent-registry/identity/{object_key}".encode()
        holder._kad_key = lambda value, *, kind: f"/decent-registry/{kind}/{value}"
        holder.dht = SimpleNamespace(
            value_store=SimpleNamespace(_get_from_peer=direct_read),
        )
        holder.bootstrap = bootstrap

        result = self._read_remote(holder, remote_dht)

        self.assertIsNone(result)
        self.assertEqual(bootstrap_calls, ["peer-address"])
        self.assertEqual(calls, [("peer-id", expected_key, True)])

    def test_remote_direct_read_returns_none_only_for_valid_empty_reply(self):
        holder, remote_dht = self._holder(PeerValueAbsent())
        self.assertIsNone(self._read_remote(holder, remote_dht))

    def test_remote_direct_read_incomplete_referral_is_unavailable(self):
        holder, remote_dht = self._holder(PeerValueIncomplete())
        with self.assertRaises(DHTLookupUnavailable):
            self._read_remote(holder, remote_dht)

    def test_remote_direct_read_mixed_with_unavailable_peer_fails_closed(self):
        # Two peers use distinct typed results, so the adapter cannot treat a
        # partial query failure as global absence.
        outcomes = iter((PeerValueAbsent(), PeerValueUnavailable()))
        holder, remote_dht = self._holder(None, peers=("peer-one", "peer-two"))
        async def read_peer(_peer_id, _key, return_record=False):
            return next(outcomes)

        holder.dht.value_store._get_from_peer = read_peer
        with self.assertRaises(DHTLookupUnavailable):
            self._read_remote(holder, remote_dht)

    def test_remote_direct_read_positive_with_unavailable_peer_fails_closed(self):
        # A positive candidate cannot be accepted when another configured peer
        # did not provide complete evidence.
        outcomes = iter((SimpleNamespace(value=b"legacy-head"), PeerValueUnavailable()))
        holder, remote_dht = self._holder(None, peers=("peer-one", "peer-two"))
        async def read_peer(_peer_id, _key, return_record=False):
            return next(outcomes)

        holder.dht.value_store._get_from_peer = read_peer
        with self.assertRaises(DHTLookupUnavailable):
            self._read_remote(holder, remote_dht)

    def test_remote_direct_read_authenticates_all_mixed_heads_before_selection(self):
        outcomes = iter((SimpleNamespace(value=b"legacy-head"),
                         SimpleNamespace(value=b"rotated-head")))
        holder, remote_dht = self._holder(None, peers=("peer-one", "peer-two"))
        object_key = "ab" * 32
        holder._kad_key = lambda value, *, kind: f"/decent-registry/{kind}/{value}"

        async def read_peer(_peer_id, _key, return_record=False):
            return next(outcomes)

        async def read_history(_object_key, candidate):
            return (candidate,) if candidate == b"rotated-head" else None

        class Validator:
            def validate_identity_get(self, *, record_key, envelope_cbor,
                                      predecessor_chain=None):
                if envelope_cbor == b"rotated-head" and predecessor_chain is None:
                    raise ValueError("rotation requires predecessor history")
                return envelope_cbor

        class Selector:
            @staticmethod
            def _parse_key(_key):
                return ("identity", b"owner-key")

            @staticmethod
            def _metadata(_key, _candidate):
                return None

            def __init__(self, _owner):
                pass

            def select(self, _key, candidates):
                return candidates.index(b"rotated-head")

        holder.dht.value_store._get_from_peer = read_peer
        holder._read_remote_identity_predecessor_chain = read_history
        holder._validator = Validator()
        with patch.object(registry_module, "_RegistryDHTValueValidator", Selector):
            result = self._read_remote(holder, remote_dht)
        self.assertEqual(b"rotated-head", result)

    def test_remote_reader_head_is_compared_with_all_bootstrap_candidates(self):
        object_key = "ab" * 32
        holder, remote_dht = self._holder(None, peers=("peer-one",))
        holder._kad_key = lambda value, *, kind: f"/decent-registry/{kind}/{value}"
        peer_calls = []

        class Reader:
            async def read_remote_identity_envelope(self, _key):
                return b"legacy-head"

        async def read_peer(peer_id, _key, return_record=False):
            peer_calls.append(peer_id)
            return SimpleNamespace(value=b"rotated-head")

        async def read_history(_object_key, candidate):
            return (candidate,) if candidate == b"rotated-head" else None

        class Validator:
            def validate_identity_get(self, *, record_key, envelope_cbor,
                                      predecessor_chain=None):
                if envelope_cbor == b"rotated-head" and predecessor_chain is None:
                    raise ValueError("rotation requires predecessor history")
                return envelope_cbor

        class Selector:
            @staticmethod
            def _parse_key(_key):
                return ("identity", b"owner-key")

            @staticmethod
            def _metadata(_key, _candidate):
                return None

            def __init__(self, _owner):
                pass

            def select(self, _key, candidates):
                return candidates.index(b"rotated-head")

        holder._remote_identity_reader = Reader()
        holder.dht.value_store._get_from_peer = read_peer
        holder._read_remote_identity_predecessor_chain = read_history
        holder._validator = Validator()
        with patch.object(registry_module, "_RegistryDHTValueValidator", Selector):
            result = self._read_remote(holder, remote_dht)
        self.assertEqual(b"rotated-head", result)
        self.assertEqual(["peer-id"], peer_calls)

    def _identity_read_holder(self, raw_dht, raw_remote, raw_local):
        calls = {"dht": 0, "remote": 0}

        class Validator:
            def validate_identity_get(self, *, record_key, envelope_cbor,
                                      predecessor_chain=None):
                if envelope_cbor == b"rotated-head" and predecessor_chain is None:
                    raise ValueError("rotation requires predecessor history")
                return envelope_cbor

        async def read_dht(_key, *, quorum=0):
            calls["dht"] += 1
            return raw_dht

        async def read_remote(_key):
            calls["remote"] += 1
            return raw_remote

        async def read_history(_object_key, candidate):
            return (candidate,) if candidate == b"rotated-head" else None

        holder = SimpleNamespace(
            _bootstrap_peers=("peer-address",),
            _kad_key=lambda value, *, kind: f"/decent-registry/{kind}/{value}",
            _read_dht_value=read_dht,
            read_remote_identity_envelope=read_remote,
            _durable_get=lambda *, kind, key: raw_local,
            _durable_history=lambda *, kind, key: (),
            _history_to_current=lambda history, local, current: None,
            _read_remote_identity_predecessor_chain=read_history,
            _validator=Validator(),
            _durable_store=None,
        )
        return holder, calls

    def test_unvalidated_primary_candidates_do_not_fall_through_to_bootstrap_absence(self):
        object_key = "ab" * 32
        holder, calls = self._identity_read_holder(None, None, None)
        candidate = b"unauthenticated-primary-head"
        counts = LookupCounts(
            attempts=1,
            positive_records=1,
            records=[candidate],
        )

        class DHT:
            async def get_value(self, _key, quorum=0):
                raise DHTUnvalidatedRecords("get_value", counts, (candidate,))

        class RejectingValidator:
            def validate_identity_get(self, *, record_key, envelope_cbor,
                                      predecessor_chain=None):
                raise ValueError("candidate is not authenticated")

        holder.dht = DHT()
        holder._validator = RejectingValidator()

        async def read_primary(kad_key, *, quorum=0):
            return await Libp2pKadDHT._read_dht_value(holder, kad_key, quorum=quorum)

        holder._read_dht_value = read_primary
        with self.assertRaises(DHTUnvalidatedRecords) as caught:
            trio.run(
                Libp2pKadDHT._get_validated_identity_envelope_unlocked,
                holder,
                object_key,
            )
        self.assertEqual((candidate,), caught.exception.records)
        self.assertEqual({"dht": 0, "remote": 0}, calls)

    def test_clean_remote_absence_does_not_fall_back_to_durable_identity(self):
        object_key = "ab" * 32
        holder, calls = self._identity_read_holder(None, None, b"legacy-head")
        with patch.object(registry_module, "_select_newest_envelope", side_effect=lambda a, b: b if a is None else a):
            with self.assertRaises(DHTLookupUnavailable):
                trio.run(
                    Libp2pKadDHT._get_validated_identity_envelope_unlocked,
                    holder,
                    object_key,
                )
        self.assertEqual({"dht": 1, "remote": 1}, calls)

    def test_no_bootstrap_peers_is_unavailable_not_absence(self):
        holder, remote_dht = self._holder(PeerValueAbsent(), peers=())
        with self.assertRaises(DHTLookupUnavailable):
            self._read_remote(holder, remote_dht)

    def test_large_duplicate_reader_and_peer_heads_share_unique_budget(self):
        candidate = b"x" * (3 * 1024 * 1024)
        holder, remote_dht = self._holder(None, peers=("peer-one", "peer-two"))

        class Reader:
            async def read_remote_identity_envelope(self, _key):
                return candidate

        async def read_peer(_peer_id, _key, return_record=False):
            return SimpleNamespace(value=candidate)

        holder._remote_identity_reader = Reader()
        holder.dht.value_store._get_from_peer = read_peer
        result = self._read_remote(holder, remote_dht)
        self.assertEqual(candidate, result)

    def test_remote_reader_checks_size_before_copying_bytearray(self):
        maximum = 4 * 1024 * 1024

        class OversizedBytearray(bytearray):
            def __len__(self):
                return maximum + 1

            def __bytes__(self):
                raise AssertionError("oversized reader buffer was copied")

        class Reader:
            async def read_remote_identity_envelope(self, _key):
                return OversizedBytearray()

        holder = SimpleNamespace(
            _remote_identity_reader=Reader(), _bootstrap_peers=(), _host=None
        )
        with self.assertRaises(DHTLookupUnavailable):
            trio.run(
                Libp2pKadDHT.read_remote_identity_envelope,
                holder,
                "ab" * 32,
            )

    def test_remote_reader_positive_without_peer_comparison_is_unavailable(self):
        class Reader:
            async def read_remote_identity_envelope(self, _key):
                return b"potentially-stale-head"

        holder = SimpleNamespace(
            _remote_identity_reader=Reader(), _bootstrap_peers=(), _host=None
        )
        with self.assertRaises(DHTLookupUnavailable):
            trio.run(
                Libp2pKadDHT.read_remote_identity_envelope,
                holder,
                "ab" * 32,
            )

    def test_remote_reader_positive_with_empty_bootstrap_peers_is_unavailable(self):
        class Reader:
            async def read_remote_identity_envelope(self, _key):
                return b"potentially-stale-head"

        outcomes = iter((PeerValueAbsent(),))
        holder, remote_dht = self._holder(None, peers=("peer-one",))
        holder._remote_identity_reader = Reader()

        async def read_peer(_peer_id, _key, return_record=False):
            return next(outcomes)

        holder.dht.value_store._get_from_peer = read_peer
        with self.assertRaises(DHTLookupUnavailable):
            self._read_remote(holder, remote_dht)

    def test_remote_reader_none_is_unavailable_not_absence(self):
        class Reader:
            async def read_remote_identity_envelope(self, _key):
                return None

        holder = SimpleNamespace(
            _remote_identity_reader=Reader(), _bootstrap_peers=(), _host=None
        )
        with self.assertRaises(DHTLookupUnavailable):
            trio.run(
                Libp2pKadDHT.read_remote_identity_envelope,
                holder,
                "ab" * 32,
            )


if __name__ == "__main__":
    unittest.main()
