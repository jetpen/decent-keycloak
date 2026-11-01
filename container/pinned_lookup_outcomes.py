"""Fail-closed outcome tracking for the pinned libp2p 0.7.0 resolver."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
import logging
from typing import Any

import trio

MAX_DHT_MESSAGE_SIZE = 4 * 1024 * 1024
MAX_IDENTITY_CANDIDATE_BYTES = 4 * 1024 * 1024


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
    positive_records: int = 0
    records: list[bytes] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if self.records and self.positive_records == 0:
            self.positive_records = len(self.records)

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


class DHTUnvalidatedRecords(DHTLookupUnavailable):
    """Private candidates for higher-layer verification, never absence/evidence."""

    def __init__(self, stage: str, counts: LookupCounts, records: tuple[bytes, ...]):
        if not isinstance(counts, LookupCounts):
            raise TypeError("counts must be LookupCounts")
        records = tuple(records)
        if not records or not all(isinstance(record, bytes) for record in records):
            raise ValueError("positive Identity records must be retained as bytes")
        super().__init__(stage, counts)
        self.counts = counts
        self.records = records


def check_identity_candidate_selection(key: str, quorum: int) -> None:
    """Stop generic DHT selection/cache repair from masking Identity candidates."""
    counts = _CURRENT_LOOKUP_COUNTS.get()
    if not key.startswith("/decent-registry/identity/") or counts is None:
        return
    if counts.failed or counts.timeouts or counts.incomplete:
        raise DHTLookupUnavailable("get_value", counts)
    if counts.attempts != counts.positive_records + counts.empty:
        raise DHTLookupUnavailable("get_value", counts)
    if not counts.records:
        return
    if len(set(counts.records)) > 1:
        # The caller's quorum does not resolve a divergent Identity state.
        if quorum:
            raise DHTLookupUnavailable("get_value", counts)
        raise DHTUnvalidatedRecords("get_value", counts, tuple(counts.records))


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
        if not key.startswith(b"/decent-registry/identity/"):
            outcome = await original_peer_read(self, peer_id, key, return_record)
            if isinstance(outcome, (PeerValueAbsent, PeerValueIncomplete, PeerValueUnavailable)):
                return None
            return outcome
        if counts is None:
            return await original_peer_read(self, peer_id, key, return_record)
        counts.attempts += 1
        try:
            outcome = await original_peer_read(self, peer_id, key, return_record)
        except trio.Cancelled:
            counts.timeouts += 1
            raise
        except Exception:
            counts.failed += 1
            return PeerValueUnavailable()

        if isinstance(outcome, PeerValueAbsent):
            counts.empty += 1
        elif isinstance(outcome, PeerValueIncomplete):
            counts.incomplete += 1
        elif isinstance(outcome, PeerValueUnavailable) or outcome is None:
            counts.failed += 1
        else:
            candidate = getattr(outcome, "value", None)
            if not isinstance(candidate, bytes):
                counts.failed += 1
                return PeerValueUnavailable()
            counts.positive_records += 1
            if candidate not in counts.records:
                if (len(counts.records) >= 64
                        or sum(map(len, counts.records)) + len(candidate) > MAX_IDENTITY_CANDIDATE_BYTES):
                    counts.failed += 1
                    return PeerValueUnavailable()
                counts.records.append(candidate)
        return outcome

    async def outcome_aware_get_value(self: Any, key: str, quorum: int = 0) -> bytes | None:
        if not isinstance(key, str) or not key.startswith("/decent-registry/identity/"):
            return await original_get_value(self, key, quorum=quorum)
        counts = LookupCounts()
        token = _CURRENT_LOOKUP_COUNTS.set(counts)
        miss_filter = _SuppressUnqualifiedMiss()
        _LOGGER.addFilter(miss_filter)
        try:
            try:
                value = await original_get_value(self, key, quorum=quorum)
            except DHTUnvalidatedRecords as exc:
                report_lookup_summary("get_value", counts)
                raise
            except DHTLookupUnavailable:
                report_lookup_summary("get_value", counts)
                raise
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
        if (counts.records and counts.attempts == counts.positive_records
                and not (counts.empty or counts.failed or counts.timeouts or counts.incomplete)
                and (not quorum or counts.positive_records >= quorum)):
            raise DHTUnvalidatedRecords("get_value", counts, tuple(counts.records))
        raise DHTLookupUnavailable("get_value", counts)

    value_store_class._get_from_peer = tracked_peer_read
    kad_dht_class.get_value = outcome_aware_get_value
