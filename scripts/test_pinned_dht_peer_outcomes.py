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
from libp2p.kad_dht.kad_dht import KadDHT
from libp2p.kad_dht.pb.kademlia_pb2 import Message
from libp2p.kad_dht.value_store import ValueStore


class PeerOutcomeTest(unittest.TestCase):
    def _response(
        self,
        *,
        message_type=None,
        closer_peers=0,
        malformed=False,
        response_key=b"/test/key",
        sender_record=None,
    ):
        if malformed:
            payload = b"\xff"
        else:
            message = Message()
            message.type = message_type or Message.MessageType.GET_VALUE
            message.key = response_key
            if sender_record is not None:
                message.senderRecord = sender_record
            for _ in range(closer_peers):
                message.closerPeers.add().id = b"unparsed-peer-id"
            payload = message.SerializeToString()
        return bytearray(varint.encode(len(payload)) + payload)

    def _make_dht(self, outcomes):
        class Stream:
            def __init__(self, response):
                self.response = response

            async def write(self, _data):
                pass

            async def read(self, size):
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
        return dht

    def _run_dht(self, dht):
        with patch(
            "libp2p.kad_dht.value_store.env_to_send_in_RPC",
            return_value=(b"", None),
        ):
            return trio.run(dht.get_value, "/test/key")

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


if __name__ == "__main__":
    unittest.main()
