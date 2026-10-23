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
    PeerValueAbsent,
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

        holder = SimpleNamespace(
            _remote_identity_reader=None,
            _bootstrap_peers=peers,
            _host=None,
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

    def test_remote_direct_read_returns_none_only_for_valid_empty_reply(self):
        holder, remote_dht = self._holder(PeerValueAbsent())
        self.assertIsNone(self._read_remote(holder, remote_dht))

    def test_remote_direct_read_mixed_with_unavailable_peer_fails_closed(self):
        # Two peers use distinct typed results, so the adapter cannot treat a
        # partial query failure as global absence.
        outcomes = iter((PeerValueAbsent(), PeerValueUnavailable()))
        holder, remote_dht = self._holder(None, peers=("peer-one", "peer-two"))
        class MixedRemoteDht(remote_dht):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.dht.value_store._get_from_peer = self._read_mixed

            async def _read_mixed(self, _peer_id, _key, return_record=False):
                return next(outcomes)

        with self.assertRaises(DHTLookupUnavailable):
            self._read_remote(holder, MixedRemoteDht)

    def test_no_bootstrap_peers_is_unavailable_not_absence(self):
        holder, remote_dht = self._holder(PeerValueAbsent(), peers=())
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
