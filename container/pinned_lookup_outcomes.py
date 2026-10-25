"""Fail-closed outcome tracking for the pinned libp2p 0.7.0 resolver."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
import logging
from typing import Any

import trio


@dataclass(frozen=True)
class PeerValueAbsent:
    """A completed GET_VALUE response with neither a record nor referrals."""


@dataclass(frozen=True)
class PeerValueUnavailable:
    """A peer query did not produce a trustworthy response."""


@dataclass(frozen=True)
class PeerValueIncomplete:
    """A peer returned referrals which this lookup did not traverse."""


@dataclass
class LookupCounts:
    attempts: int = 0
    empty: int = 0
    failed: int = 0
    timeouts: int = 0
    incomplete: int = 0

    def is_clean_absence(self) -> bool:
        return (
            self.attempts > 0
            and self.empty == self.attempts
            and self.failed == 0
            and self.timeouts == 0
            and self.incomplete == 0
        )


_CURRENT_LOOKUP_COUNTS: ContextVar[LookupCounts | None] = ContextVar(
    "decent_registry_dht_lookup_counts", default=None
)
_LOGGER = logging.getLogger("libp2p.kad_dht.kad_dht")


class DHTLookupUnavailable(RuntimeError):
    """An inconclusive DHT read; the message and fields contain no peer data."""

    def __init__(self, stage: str, counts: LookupCounts):
        if stage not in {"get_value", "remote_identity"}:
            stage = "unknown"
        self.stage = stage
        self.attempts = min(max(counts.attempts, 0), 999)
        self.empty = min(max(counts.empty, 0), 999)
        self.failed = min(max(counts.failed, 0), 999)
        self.timeouts = min(max(counts.timeouts, 0), 999)
        self.incomplete = min(max(counts.incomplete, 0), 999)
        super().__init__("DHT lookup unavailable")


def report_lookup_summary(stage: str, counts: LookupCounts) -> None:
    """Emit only bounded counts; never include keys, peers, endpoints, or errors."""
    if stage not in {"get_value", "remote_identity"}:
        stage = "unknown"
    fields = tuple(
        min(max(getattr(counts, name), 0), 999)
        for name in ("attempts", "empty", "failed", "timeouts", "incomplete")
    )
    _LOGGER.warning(
        "DHT_LOOKUP_SUMMARY stage=%s attempts=%d empty=%d failed=%d "
        "timeouts=%d incomplete=%d",
        stage,
        *fields,
    )


class _SuppressUnqualifiedMiss(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            return not record.getMessage().startswith("Value not found for key ")
        except Exception:
            return False


def install(kad_dht_class: type[Any], value_store_class: type[Any]) -> None:
    """Install outcome-aware wrappers around the locked private query seam."""
    original_peer_read = value_store_class._get_from_peer
    original_get_value = kad_dht_class.get_value

    async def tracked_peer_read(self: Any, peer_id: Any, key: bytes, return_record: bool = False):
        counts = _CURRENT_LOOKUP_COUNTS.get()
        if counts is not None:
            counts.attempts += 1
        try:
            outcome = await original_peer_read(self, peer_id, key, return_record)
        except trio.Cancelled:
            if counts is not None:
                counts.timeouts += 1
            raise
        except Exception:
            if counts is not None:
                counts.failed += 1
            return PeerValueUnavailable()

        if counts is not None:
            if isinstance(outcome, PeerValueAbsent):
                counts.empty += 1
            elif isinstance(outcome, PeerValueIncomplete):
                counts.incomplete += 1
            elif isinstance(outcome, PeerValueUnavailable) or outcome is None:
                counts.failed += 1
        return outcome

    async def outcome_aware_get_value(self: Any, key: str, quorum: int = 0) -> bytes | None:
        counts = LookupCounts()
        token = _CURRENT_LOOKUP_COUNTS.set(counts)
        miss_filter = _SuppressUnqualifiedMiss()
        _LOGGER.addFilter(miss_filter)
        try:
            try:
                value = await original_get_value(self, key, quorum=quorum)
            except Exception:
                counts.failed += 1
                report_lookup_summary("get_value", counts)
                raise DHTLookupUnavailable("get_value", counts) from None
        finally:
            _LOGGER.removeFilter(miss_filter)
            _CURRENT_LOOKUP_COUNTS.reset(token)

        if value is not None:
            return value

        report_lookup_summary("get_value", counts)
        if counts.is_clean_absence():
            _LOGGER.warning("Value not found for key %s", key)
            return None
        raise DHTLookupUnavailable("get_value", counts)

    value_store_class._get_from_peer = tracked_peer_read
    kad_dht_class.get_value = outcome_aware_get_value
