"""Safety-gated response cache for MCP tool calls.

Caching tool responses saves repeated server round-trips and repeated
validation cost, but a cache in a security pipeline is itself an attack
surface: a poisoned response that gets cached is served again and again,
amplifying a single detector miss into many. This cache therefore treats
eligibility as a security decision, not a performance one:

- only responses that passed response validation are stored
  (``require_clean_verdict``);
- entries are isolated per principal (``per_principal``), so one caller's
  responses are never replayed to another;
- entries expire after ``ttl_seconds``, bounding how long any mistake lives.

Every gate can be disabled to measure exactly what it prevents.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ResponseCacheConfig:
    """Configuration for the governed response cache."""

    enabled: bool = True
    ttl_seconds: float = 300.0
    max_entries: int = 4096
    per_principal: bool = True
    require_clean_verdict: bool = True


@dataclass
class CacheStats:
    """Counters describing cache behavior over a run."""

    lookups: int = 0
    hits: int = 0
    misses: int = 0
    stores: int = 0
    rejected_unclean: int = 0
    expired: int = 0
    evicted: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "lookups": self.lookups,
            "hits": self.hits,
            "misses": self.misses,
            "stores": self.stores,
            "rejected_unclean": self.rejected_unclean,
            "expired": self.expired,
            "evicted": self.evicted,
        }


@dataclass
class _Entry:
    content: Any
    verdict_passed: bool
    stored_at: float
    principal: str


class GovernedResponseCache:
    """LRU response cache whose admission policy is security-aware."""

    def __init__(self, config: ResponseCacheConfig | None = None) -> None:
        self.config = config or ResponseCacheConfig()
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self.stats = CacheStats()

    # -- key construction ---------------------------------------------------

    def make_key(
        self,
        server_id: str,
        tool_name: str,
        params: dict[str, Any] | None,
        principal: str = "",
    ) -> str:
        """Deterministic key over the full call identity.

        Params are canonicalized (sorted keys) so semantically identical calls
        collide. The principal is part of the key when per-principal isolation
        is on, which makes cross-principal reuse impossible by construction
        rather than by a check at read time.
        """
        canonical = json.dumps(params or {}, sort_keys=True, default=str)
        parts = [server_id, tool_name, canonical]
        if self.config.per_principal:
            parts.append(principal)
        return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()

    # -- operations ---------------------------------------------------------

    def get(self, key: str, now: float | None = None) -> _Entry | None:
        """Return a live entry for *key*, or None."""
        if not self.config.enabled:
            return None
        now = time.monotonic() if now is None else now
        self.stats.lookups += 1

        entry = self._entries.get(key)
        if entry is None:
            self.stats.misses += 1
            return None
        if now - entry.stored_at > self.config.ttl_seconds:
            del self._entries[key]
            self.stats.expired += 1
            self.stats.misses += 1
            return None

        self._entries.move_to_end(key)
        self.stats.hits += 1
        return entry

    def put(
        self,
        key: str,
        content: Any,
        verdict_passed: bool,
        principal: str = "",
        now: float | None = None,
    ) -> bool:
        """Store a response if admission gates allow it. Returns True if stored."""
        if not self.config.enabled:
            return False
        now = time.monotonic() if now is None else now

        if self.config.require_clean_verdict and not verdict_passed:
            self.stats.rejected_unclean += 1
            return False

        self._entries[key] = _Entry(
            content=content,
            verdict_passed=verdict_passed,
            stored_at=now,
            principal=principal,
        )
        self._entries.move_to_end(key)
        self.stats.stores += 1

        while len(self._entries) > self.config.max_entries:
            self._entries.popitem(last=False)
            self.stats.evicted += 1
        return True

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
