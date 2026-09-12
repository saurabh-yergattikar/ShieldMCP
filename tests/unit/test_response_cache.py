"""Tests for the safety-gated response cache."""

from shieldmcp.governance import GovernedResponseCache, ResponseCacheConfig


def _cache(**overrides) -> GovernedResponseCache:
    return GovernedResponseCache(ResponseCacheConfig(**overrides))


class TestKeying:
    def test_identical_calls_collide(self):
        c = _cache()
        k1 = c.make_key("s", "t", {"a": 1, "b": 2}, "alice")
        k2 = c.make_key("s", "t", {"b": 2, "a": 1}, "alice")
        assert k1 == k2

    def test_different_params_do_not_collide(self):
        c = _cache()
        assert c.make_key("s", "t", {"a": 1}, "alice") != c.make_key(
            "s", "t", {"a": 2}, "alice"
        )

    def test_per_principal_isolation_is_structural(self):
        c = _cache(per_principal=True)
        assert c.make_key("s", "t", {"a": 1}, "alice") != c.make_key(
            "s", "t", {"a": 1}, "bob"
        )

    def test_shared_keys_when_isolation_off(self):
        c = _cache(per_principal=False)
        assert c.make_key("s", "t", {"a": 1}, "alice") == c.make_key(
            "s", "t", {"a": 1}, "bob"
        )


class TestAdmissionGates:
    def test_clean_response_is_cached(self):
        c = _cache()
        k = c.make_key("s", "t", {}, "alice")
        assert c.put(k, "result", verdict_passed=True, principal="alice")
        assert c.get(k) is not None

    def test_flagged_response_is_rejected(self):
        c = _cache(require_clean_verdict=True)
        k = c.make_key("s", "t", {}, "alice")
        assert not c.put(k, "poisoned", verdict_passed=False, principal="alice")
        assert c.get(k) is None
        assert c.stats.rejected_unclean == 1

    def test_ungated_cache_admits_flagged_response(self):
        c = _cache(require_clean_verdict=False)
        k = c.make_key("s", "t", {}, "alice")
        assert c.put(k, "poisoned", verdict_passed=False, principal="alice")
        entry = c.get(k)
        assert entry is not None
        assert entry.verdict_passed is False


class TestExpiryAndEviction:
    def test_ttl_expiry(self):
        c = _cache(ttl_seconds=10.0)
        k = c.make_key("s", "t", {}, "alice")
        c.put(k, "result", verdict_passed=True, principal="alice", now=100.0)
        assert c.get(k, now=105.0) is not None
        assert c.get(k, now=111.0) is None
        assert c.stats.expired == 1

    def test_lru_eviction_bounds_size(self):
        c = _cache(max_entries=2)
        for i in range(4):
            k = c.make_key("s", "t", {"i": i}, "alice")
            c.put(k, i, verdict_passed=True, principal="alice")
        assert len(c) == 2
        assert c.stats.evicted == 2

    def test_disabled_cache_never_hits(self):
        c = _cache(enabled=False)
        k = c.make_key("s", "t", {}, "alice")
        assert not c.put(k, "x", verdict_passed=True, principal="alice")
        assert c.get(k) is None


class TestStats:
    def test_hit_miss_accounting(self):
        c = _cache()
        k = c.make_key("s", "t", {}, "alice")
        assert c.get(k) is None
        c.put(k, "x", verdict_passed=True, principal="alice")
        assert c.get(k) is not None
        s = c.stats.as_dict()
        assert s["lookups"] == 2
        assert s["hits"] == 1
        assert s["misses"] == 1
        assert s["stores"] == 1
