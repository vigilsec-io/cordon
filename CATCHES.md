# Vigil — Real-World Catches Log

> Every entry here is a real finding from this workspace that Vigil caught during an active Claude Code session.
> This is both a product win log and a regression baseline — if a rule regresses, these are the first things to retest.
> Format: date · rule · project · what was caught · what the fix was

---

## 2026-06-30

### VGL-PKG003 — redis==5.0.8 outdated (scout)

**Rule:** VGL-PKG003 (outdated Python package version)  
**Project:** scout / Zora backend  
**When:** Immediately after Claude wrote `redis[asyncio]==5.0.8` to `requirements.txt` during #121 (Redis caching layer implementation)  
**What Vigil said:**
```
[HIGH] VGL-PKG003 — redis==5.0.8 is outdated — AI suggested an old version; latest is 8.0.1
  at requirements.txt:15
  → redis==5.0.8
  fix: Update to redis==8.0.1
```
**Fix:** Updated to `redis==8.0.1` in the same turn. Also discovered the `[asyncio]` extra no longer exists in v6+ (merged into base), so dropped the extra.  
**Impact:** Prevented deploying a 3-major-version-old Redis client. The jump 5→8 includes breaking async API changes that would have caused a production runtime crash on first cache call.  
**Lesson:** AI training data cutoff means model confidently suggests versions from 12-18 months ago. VGL-PKG003 catches this automatically on every `Edit`/`Write` to requirements files.

---

### VGL-SW001 false positive fix — snake_case storage keys (vigil, scout)

**Rule:** VGL-SW001 (Swift hardcoded secret in storage key)  
**Project:** vigil rule corpus + scout iOS  
**When:** Rule fired on `ZoraSecrets.swift` storage key names like `cf_access_client_id`  
**What was wrong:** The regex matched any lowercase string adjacent to a storage API call, including the *key name* (an identifier) rather than the *value* (a secret). `cf_access_client_id` is a key name — the value is injected at build time from `.xcconfig`.  
**Fix:** Added a third FP guard to `vigil/src/vigil/rules/swift.py`:
```python
# Guard: if value matches ^[a-z][a-z0-9_]*$ it's a storage key identifier, not a secret
if re.match(r'^[a-z][a-z0-9_]*$', value):
    continue
```
Added 3 regression tests in `vigil/tests/test_rules_swift.py` to lock this in.  
**Impact:** Prevented noisy false-positive alerts on every session touching the iOS secrets migration. Rule is now tighter without losing real-secret detection.  
**Lesson:** Snake_case key *names* in Keychain/UserDefaults calls look like secrets to a naive regex. A single structural check (value is all lowercase + underscores = it's a variable name, not a secret) eliminates the whole class.

---

## Earlier (pre-CATCHES.md — reconstructed from ACTIVE_TASK.md and session logs)

### Dockerfile root-user findings (hyrox-tickets, mcp-trust-ledger)

**Rule:** VGL-DF001 (Dockerfile running as root) — fired via security_runner.py semgrep scan  
**Projects:** hyrox-tickets, mcp-trust-ledger  
**What was caught:** Both Dockerfiles had no `USER` directive — containers ran as root  
**Fix:** Added `RUN useradd -r -u 1001 appuser && USER appuser` before `CMD` in both  
**Impact:** Containers now run as non-root; limits blast radius if a dependency CVE is exploited

---

## Running Score

| Rule | Times fired (real) | Times fired (FP) | Projects |
|------|--------------------|------------------|---------|
| VGL-PKG003 | 1 | 0 | scout |
| VGL-SW001 | 0 | 1 (fixed + regression test) | scout iOS |
| VGL-DF001 | 2 | 0 | hyrox-tickets, mcp-trust-ledger |

**Total real bugs caught by Vigil hook (PostToolUse, not batch scan):** 1  
**Total FPs fixed with regression tests:** 1  
**Outdated deps prevented from reaching server:** 1 (redis 5→8, ~3 major versions)

---

*Updated: 2026-06-30. Add a row every time Vigil fires in a Claude session.*
