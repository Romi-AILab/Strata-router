#!/usr/bin/env python3
"""
strata-router -- affinity + least-queued passthrough router for N identical
Strata (or any OpenAI/Anthropic-compatible) inference boxes behind one base URL.

The four hard rules this file implements (they ARE the design):

1. NO TRANSLATION.
   /v1/messages, /v1/responses, /v1/chat/completions and /v1/completions are
   forwarded byte-for-byte. Only headers are touched, plus `model` if you
   explicitly ask for a rewrite. thinking / redacted_thinking blocks, tool_use,
   stop_reason, cache_control and the SSE event names survive untouched, because
   nothing here parses them. Translation layers are exactly where Claude-Code /
   Codex compatibility dies, so there is none.

2. NO RATE LIMITING HERE -- THIS ROUTER NEVER RETURNS 429.
   Requests are handed to the backend's own FIFO queue, so the queue lives in
   exactly one place: next to the real slots. Do not add a second admission queue
   in the proxy; it only invents 429s and hides backpressure.

3. AFFINITY FIRST, LEAST-QUEUED SECOND.
   A conversation family (an agent and all its turns) stays on one box so that
   box's prompt / KV / conversation cache stays warm. Only *new* conversation
   keys are load-placed, using the router's own in-flight count -- which counts
   requests parked in a backend queue, the most honest load signal available --
   plus the backend's reported serving/queued counters. Round-robin over cold
   caches is a regression for agent workloads, so it is not offered.

   TIERS (optional, per-backend): `priority` (lower = preferred), `max_inflight`
   (hard cap on conversations this router places there) and `require_idle`
   (borrow only while the box reports no load that is not ours -- external load
   is reported serving+queued minus our own in-flight, confirmed on two
   consecutive polls so our own finishing traffic never bounces us off).
   Set local=0 / borrowed=1 for "local first, overflow to the peer only when it
   is verifiably idle". A tier that will not accept falls through to the next;
   when no tier accepts, the healthy primary tier queues the request -- the gate
   redirects, it never rejects. The idle verdict is only ever made from live
   proof: a borrowed box whose status went silent, OR whose status has never
   once answered (wrong key, wrong path, unrecognised schema), is NOT idle --
   you may not stack on a machine you cannot see. Gate check and reservation
   happen in one lock acquisition, so the cap is atomic under bursts.
   `x-strata-pin` overrides affinity, tier and the max_inflight cap, but NOT
   the require_idle gate: the peer's courtesy is not ours to waive.
   Each backend may carry its own `backend_api_key` (mirror deployments: your
   box holds its own key, the peer's spec holds the borrower key they issued
   you); the global field and STRATA_BACKEND_API_KEY remain the fallback.
   The standard input port is `--set-key <id>`: a hidden prompt writes the key
   into `router.keys.json` (0600 / NTFS-inheritance stripped; since 1.2.14
   DPAPI ciphertext on Windows -- a stray scan sees base64 noise, and the
   blob never opens for another user or machine) so the config
   file itself stays keyless; `backend_api_key_env` reads one backend's key
   from a named environment variable instead. Order: inline field > keys file
   > env var > keys file `global` > global field > STRATA_BACKEND_API_KEY.
   Inference and status polling authenticate per box; revoking a peer means
   rotating your own box's key alone. Keys never appear in argv, in
   router.json when typed through --set-key, or in any log line.

4. HEALTH = CONNECTION FAILURE ONLY.
   Connection refused / reset / no-route / connect-timeout makes a box suspect,
   then down. A box that is merely *busy* -- 429, queue_wait_timeout, slow first
   byte, 5xx, mid-stream reset -- stays in the pool and keeps taking queue.
   If every box looks down we still forward to the least-bad one: queueing a task
   is always better than failing it.

Client-side timeouts are the one real limit on "queue forever": a STREAMING
request parked in a Strata queue emits a keep-alive comment every ~10 s and
this router relays it live -- the relay uses read1, never a fill-read, or the
bytes would sit in the buffer until the turn ends -- so a stream-idle timeout
survives the wait and what kills long waits is a total wall-clock ceiling. A
NON-streaming request truly sends nothing while queued, so its read timeout
is the ceiling (see README.md).

Usage
-----
    python router.py --backend a=http://127.0.0.1:8080 --backend b=http://192.168.1.24:8080
    python router.py --probe            # inspect each box, verify paths, exit
    python router.py --config router.json

    GET  /healthz
    GET  /__router/stats
    POST /__router/sticky/clear
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import http.client
import json
import logging
import math
import os
import random
import re
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

VERSION = "1.2.17"
ROUTER_STARTED = int(time.time())   # process start epoch (stats started_at/uptime_s)
LOG = logging.getLogger("strata-router")

# How often the per-request watchdog peeks at the caller's socket (mirrors
# Strata's own client watch, which runs at the same interval).
CLIENT_WATCH_S = 0.5
# A box notices a dead PARKED stream only at its next keep-alive beat
# (Strata: QUEUE_BEAT_S = 10 s). The router releases an aborted request the
# moment its own watchdog fires, so until that beat lands, the box's own
# report still counts our corpse as load. This grace window is how long the
# courtesy verdict keeps subtracting that ghost -- long enough for one beat
# plus status lag, short enough that real foreign load is never hidden for
# long (it re-confirms itself on the next sample after the grace).
GHOST_GRACE_S = 12.0
RECENT_TTFB_WINDOW = 30    # per-box rolling window of finished-request ttfb (v1.2.14)

# Paths accepted for generation (POST). Router path == backend path unless a
# per-backend path_prefix is set (some builds serve only /anthropic/v1/messages).
POST_PATHS = ("/v1/messages", "/v1/responses", "/v1/chat/completions", "/v1/completions")
GET_PATHS = ("/v1/models", "/models", "/health")
COUNT_TOKENS_SUFFIX = "/count_tokens"

# RFC 9110 connection-scoped headers never cross a proxy.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}
# We ask upstream for identity encoding so SSE is never gzip-buffered.
STRIP_REQUEST_HEADERS = HOP_BY_HOP | {
    # x-strata-control (L2-3/M1): the control token gates the ROUTER, never a
    # box -- forwarding it would hand the secret to the borrowed box's owner
    # on every pinned turn.
    "host", "content-length", "accept-encoding", "x-strata-backend", "x-strata-affinity", "x-strata-pin",
    "x-strata-control",
}

HEALTHY = "healthy"
SUSPECT = "suspect"   # connect failures seen, still taking traffic
DOWN = "down"         # skipped unless nothing else exists, then half-open trial


def short(key):
    """Display form: every ``kind:hash`` part (the two-level key joins scope and
    lane with '/') keeps its kind and an 8-hex hash head. Truncating the whole
    value instead would cut the lane off and print two lanes identically."""
    if not key:
        return "-"

    def _one(k):
        kind, sep, val = k.partition(":")
        return kind + ":" + val[:8] if val else k

    return "/".join(_one(p) for p in key.split("/"))


def sha1_16(s):
    return hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:16]


# RFC 7230 token: the only shape a header name may have on the wire. Relay
# uses it to vet what a box sends back (see the response-copy site).
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")

# C0/DEL controls a lying box can hide inside a header VALUE. They cannot forge
# a line (bare CR/LF drop the header outright at the relay gate below), but
# they truncate the value in some downstream stacks -- an operator's log would
# then show something other than what the router saw. Response values relay
# sanitized, never dropped (review R4-B/F2).
_HDR_VAL_CTL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _as_int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _dump(x):
    try:
        return json.dumps(x, sort_keys=True, ensure_ascii=False)
    except Exception:
        return repr(x)


def _json_or_none(body):
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


class Backend:
    """One inference box: base URL plus a thread-safe health / load record."""

    def __init__(self, backend_id, base_url, path_prefix="", cfg=None):
        u = urlparse(base_url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise SystemExit("backend %s: bad URL %r" % (backend_id, base_url))
        self.id = str(backend_id)
        self.https = u.scheme == "https"
        self.host = u.hostname
        self.port = u.port or (443 if self.https else 80)
        self.prefix = (path_prefix or "").rstrip("/")
        self.cfg = cfg or {}

        # tiered placement knobs (see rule 3): all per-backend, so the same file
        # mirrors onto the peer machine with just the priorities swapped.
        self.priority = _as_int(self.cfg.get("priority"), 0)
        cap = _as_int(self.cfg.get("max_inflight"), None)
        self.max_inflight = None if cap is None or cap < 0 else cap
        self.require_idle = bool(self.cfg.get("require_idle"))
        # per-box key: the spec's own backend_api_key wins (peer boxes carry a
        # borrower key), then the global field, then the environment. cfg is
        # already the global dict merged with this backend's spec.
        self.api_key = str(self.cfg.get("backend_api_key")
                           or os.environ.get("STRATA_BACKEND_API_KEY") or "")

        self.lock = threading.Lock()
        self.inflight = 0
        self.connect_failures = 0
        self.state = HEALTHY
        self.down_until = 0.0
        self.trial_open = False

        # last values read from the box's own status endpoint
        self.reported = {"serving": None, "queued": None}
        self.status_ok = None
        self.status_source = None
        self.status_error = None
        self.ever_reported = False   # did the status endpoint EVER answer?
        self.status_ts = 0.0         # monotonic time of the last good report
        self.ext_streak = 0          # consecutive reports showing load that is
                                     # not ours (reported total minus own inflight)
        self._ghost_debt = []        # abort-release deadlines: the box may still
                                     # count OUR dead request for one beat -- subtract it
                                     # from the external-load verdict (see GHOST_GRACE_S)

        self.stats = {
            "requests": 0, "streams": 0, "connect_errors": 0, "http_4xx": 0, "http_5xx": 0,
            "stream_errors": 0, "aborted_by_client": 0, "ttfb_sum": 0.0, "ttfb_n": 0,
            "dur_sum": 0.0, "last_error": None, "last_status": None, "last_ttfb": None,
            "migrations_from": 0, "bytes_out": 0,
        }
        # rolling ttfb of the last finished requests (v1.2.14): per-FINISHED-request
        # sampling, so none of the self-polling bias a monitor's own sampling has.
        # Bounded; appended/trimmed under self.lock at the completion tick.
        self.recent_ttfb = []

    # ---- health state machine (rule 4) -----------------------------------
    def note_connect_failure(self, err, max_fails, backoff):
        down_msg = None
        debug_msg = None
        with self.lock:
            self.connect_failures += 1
            self.stats["connect_errors"] += 1
            self.stats["last_error"] = time.strftime("%H:%M:%S") + " " + err
            if self.connect_failures >= max_fails:
                repeat = self.state == DOWN
                self.state = DOWN
                self.down_until = time.monotonic() + backoff
                self.trial_open = False
                if repeat:
                    # already DOWN: refreshing the backoff each poll is correct,
                    # re-ANNOUNCING "probe again in 5s" every ~3s is a log storm
                    # that lies about when the probe will happen (R4-A/F6)
                    debug_msg = ("backend %s still DOWN (%s; backoff refreshed %.0fs)",
                                 self.id, err, backoff)
                else:
                    down_msg = "backend %s -> DOWN (%s; probe again in %.0fs)" % (self.id, err, backoff)
            elif self.state == HEALTHY:
                self.state = SUSPECT
        if debug_msg:  # never under the lock either -- same blocked-sink doctrine
            LOG.debug(*debug_msg)
        if down_msg:  # NEVER log under the lock (L2-3/M3): a blocked log sink
            LOG.warning(down_msg)  # (GUI-piped stderr, quick-edit freeze, stuck
                                   # file) would hold the lock and freeze every
                                   # begin/end/pick touching this box

    def note_success(self):
        heal_msg = None
        with self.lock:
            if self.state != HEALTHY:
                heal_msg = "backend %s -> HEALTHY" % self.id
            self.connect_failures = 0
            self.state = HEALTHY
            self.down_until = 0.0
            self.trial_open = False
        if heal_msg:
            LOG.info(heal_msg)

    def note_stream_error(self, err):
        # Ambiguous: our client may have hung up, or the engine died mid-stream.
        # Recorded, never enough on its own to eject a box.
        with self.lock:
            self.stats["stream_errors"] += 1
            self.stats["last_error"] = time.strftime("%H:%M:%S") + " stream: " + err

    def note_client_abort(self):
        """The caller hung up (watchdog EOF/RST, or a refused write): counted
        as an abort, never as a box failure (rule 4). Also records a GHOST
        DEBT: our inflight released the instant the relay broke, but a parked
        request stays in the box's activity.in_flight until its next
        keep-alive beat. For that window the courtesy gate must not read the
        leftover as the owner's load -- OUR aborted request must never close
        a healthy home's gate and exile a lane onto the borrowed box."""
        now = time.monotonic()
        with self.lock:
            self.stats["aborted_by_client"] += 1
            self._ghost_debt = [t for t in self._ghost_debt if t > now]
            self._ghost_debt.append(now + GHOST_GRACE_S)

    def note_timeout_release(self):
        """The router gave up on a SENT request (read timeout, no first byte).
        Exactly like an abort for ghost-debt purposes (L2-3/M2): we release our
        inflight now, but the box keeps counting the parked request until its
        next beat -- our corpse must not close a healthy home's gate and exile
        the lane. Counted as debt, never as an abort: the caller did not hang
        up, and the request may still finish on the box."""
        now = time.monotonic()
        with self.lock:
            self._ghost_debt = [t for t in self._ghost_debt if t > now]
            self._ghost_debt.append(now + GHOST_GRACE_S)

    def begin(self):
        """Reserve a slot. False means the box is in its down-cooldown, or is
        already carrying the one half-open trial -- everyone else gets the
        migration path instead of joining a queue behind a dead box."""
        with self.lock:
            if self.state == DOWN:
                if self.trial_open or time.monotonic() < self.down_until:
                    return False
                self.trial_open = True          # half-open: exactly one trial
            self.inflight += 1
            self.stats["requests"] += 1
            return True

    def take_sticky(self):
        """Sticky turn's reservation: healthy, room (cap), and -- if borrowed
        -- verifiably open still. False does NOT mean "leave the conversation":
        it means the caller should try the overflow path (a peer box that can
        take this branch NOW), and only fall back to a plain begin() queue at
        home when nowhere else accepts. This is what lets parallel branches of
        one session (lanes) spread over boxes instead of all queueing behind
        the lane that holds the slot."""
        with self.lock:
            if self.state == DOWN:
                return False
            if not self._accepts_locked(time.monotonic()):
                return False
            self.inflight += 1
            self.stats["requests"] += 1
            return True

    def end(self):
        with self.lock:
            self.inflight = max(0, self.inflight - 1)

    def load_state_ok(self):
        with self.lock:
            if self.state != DOWN:
                return True
            return bool(self.down_until) and time.monotonic() >= self.down_until

    # ---- tier gate for NEW placements (rule 3, tiered mode) --------------
    def _stale_after(self):
        # a borrowed box that has stopped reporting is unknown, and unknown is
        # not idle; the floor keeps a fast poll interval from over-trusting
        return max(3.0 * float(self.cfg.get("status_interval") or 1.0), 5.0)

    def _accepts_locked(self, now, ignore_cap=False):
        if not ignore_cap and self.max_inflight is not None and self.inflight >= self.max_inflight:
            return False
        if self.require_idle:
            if not self.ever_reported:
                return False      # the idle verdict needs live proof: a status
                                  # endpoint that has never answered (wrong key,
                                  # wrong path, unreadable schema) is unknown,
                                  # and unknown is NOT idle -- fail closed
            if now - self.status_ts > self._stale_after():
                return False      # went blind mid-run: never stack on an unseen box
            if self.ext_streak >= 2:
                return False      # foreign load (the owner's, or another borrower's)
                                  # confirmed by two consecutive reports -- one
                                  # stale sample right after our own request ends
                                  # must not bounce our conversation off the box
        return True

    def try_place(self, ignore_cap=False):
        """Atomic test-and-reserve for a NEW placement: tier gate, half-open
        trial and inflight++ inside ONE lock acquisition, so a burst of
        concurrent first turns cannot all read the same accepting verdict and
        then all reserve. This is what makes max_inflight a hard cap."""
        with self.lock:
            if not self._accepts_locked(time.monotonic(), ignore_cap=ignore_cap):
                return False
            if self.state == DOWN:
                if self.trial_open or time.monotonic() < self.down_until:
                    return False
                self.trial_open = True
            self.inflight += 1
            self.stats["requests"] += 1
            return True

    def accepts_placement(self):
        """May a NEW conversation be placed here right now? Since v1.2.5 sticky
        turns consult the SAME gate: a refused sticky turn OVERFLOWS to a peer
        that accepts now (and stays where it warmed its cache), or queues at
        home when nothing accepts -- it is never failed and never silently
        yanked. A box marked require_idle must have its status endpoint
        answering before it can look idle at all (fail closed); boxes without
        the flag degrade to the inflight cap alone."""
        with self.lock:
            return self._accepts_locked(time.monotonic())

    # ---- load score (rule 3) ---------------------------------------------
    def load_score(self):
        """Lower is better. Own in-flight dominates: it includes requests parked
        in that box's FIFO, which is precisely the queue we want to avoid.
        Reported load counts ONLY while the status feed is fresh -- a box that
        went blind used to keep contributing its last sample forever (R4-A/F5)
        -- and only as a NON-NEGATIVE number: a peer that lies queued=-1e6 must
        not win every new conversation ("more idle than idle" does not exist,
        R4-B/F1). Blind boxes fall back to inflight-only scoring, the degradation
        the poller has always documented as the right answer. The formula
        itself lives in _score_locked -- placement and the monitor-facing
        snapshot read the SAME number (R6-C/P3-2, R6-D/P3)."""
        with self.lock:
            return self._score_locked() + random.random()   # jitter spreads ties

    def snapshot(self):
        with self.lock:
            return {
                "id": self.id,
                "url": ("https" if self.https else "http") + "://" + self.host + ":" + str(self.port) + self.prefix,
                "state": self.state,
                "inflight": self.inflight,
                "connect_failures": self.connect_failures,
                "down_remaining_s": max(0.0, round(self.down_until - time.monotonic(), 1)),
                "half_open_trial": self.trial_open,
                "reported": dict(self.reported),
                "status_ok": self.status_ok,
                "status_source": self.status_source,
                "status_error": self.status_error,
                "priority": self.priority,
                "max_inflight": self.max_inflight,
                "require_idle": self.require_idle,
                "has_api_key": bool(self.api_key),
                # DOWN is part of the accepting verdict (R4-A/F1): placement is
                # separately gated on state, so the old snapshot told monitors
                # a dead box was open -- monitor-grade readouts means the gate
                # word is the whole truth, half-open trials included
                "accepting": self.state != DOWN and self._accepts_locked(time.monotonic()),
                "ext_streak": self.ext_streak,
                "reported_age_s": round(time.monotonic() - self.status_ts, 1) if self.ever_reported else None,
                "score": round(self._score_locked(), 1),
                "avg_ttfb_s": round(self.stats["ttfb_sum"] / self.stats["ttfb_n"], 2) if self.stats["ttfb_n"] else None,
                "recent_ttfb_avg_s": (round(sum(self.recent_ttfb) / len(self.recent_ttfb), 2)
                                      if self.recent_ttfb else None),
                "recent_ttfb_p95_s": (sorted(self.recent_ttfb)[max(0, int(0.95 * (len(self.recent_ttfb) - 1) + 0.5))]
                                      if self.recent_ttfb else None),
                "recent_ttfb_n": len(self.recent_ttfb),
                "stats": dict(self.stats),
            }

    def _score_locked(self):
        """Single source of truth for "how loaded is this box" (caller holds
        the lock). Placement adds only the tie-break jitter; the snapshot
        exports this number verbatim. It carries BOTH v1.2.16 defenses --
        non-negative clamp and freshness gate -- because the display copy used
        to have neither: /stats showed a lying box -60,000,000 and froze a
        blind box at its last sample while placement had long since fallen
        back to inflight-only (R6-C/P3-2, R6-D/P3: monitors must never be
        handed a number the router itself has disowned)."""
        s = float(self.inflight) * 1000.0
        if self.ever_reported and (time.monotonic() - self.status_ts) <= self._stale_after():
            q = self.reported.get("queued")
            sv = self.reported.get("serving")
            if q is not None:
                s += max(0.0, float(q)) * 60.0
            if sv is not None:
                s += max(0.0, float(sv) - 1.0) * 45.0
        if self.state == DOWN:
            s += 1e9
        elif self.state == SUSPECT:
            s += 5e3
        return s


class Pool:
    """Backend selection: sticky by conversation key, least-queued for new keys."""

    def __init__(self, backends, cfg):
        self.backends = list(backends)
        self.by_id = {b.id: b for b in self.backends}
        self.cfg = cfg
        self.lock = threading.Lock()
        self.affinity = OrderedDict()
        # requests whose overflow re-home is not yet proven by a first byte:
        # token -> (lane_key, home_id, alt_id). THE TOKEN IS PER REQUEST, not
        # per lane: two turns of the SAME lane (an SDK retry after a stalled
        # park -- expected traffic, README says so) can legitimately be in
        # flight to different peers at once. A lane-keyed entry silently
        # overwrote the first pending -- whichever request answered first
        # re-homed the lane onto the OTHER one's box, and the second one's
        # rollback popped a mismatched entry and 502'd over a live home
        # (review L1-2/M1). Each request settles its own token exactly once:
        # commit, rollback, or fizzle.
        self._overflow_pending = OrderedDict()
        self._overflow_token = 0
        self.metrics = {
            "requests": 0, "sticky_hits": 0, "new_placements": 0, "migrations": 0,
            "pinned": 0, "pin_misses": 0, "last_resort": 0, "count_tokens_synthesized": 0,
            # keyless GET/HEAD proxies (e.g. /v1/models probes): a real
            # terminal of the ledger so requests == SUM(terminals) stays
            # exact without letting monitoring probes masquerade as new
            # conversations (review R4-A/F4)
            "passthrough_gets": 0,
            "gate_bypass_borrow": 0, "overflow_placements": 0, "overflow_rollbacks": 0,
            "overflow_fizzles": 0, "overflow_evictions": 0,
            # operator-cancelled overflow re-homes (pin takeover, sticky
            # clear): the LAST term of the closed identity -- requests ==
            # placements + fizzles + evictions + operator_cancelled. Until it
            # was countable, the README's identity clause could not be
            # re-derived from /stats alone after an operator touched anything
            # (stress Q2/F3).
            "operator_cancelled": 0,
        }

    def _stash_pending(self, token, entry):
        """Book a pending overflow (CALLER HOLDS self.lock). The 4096 cap is a
        last-ditch bound -- past it the honest failure is thread exhaustion,
        not eviction -- but an evicted token would silently open a ledger gap
        and turn its request's later rollback into a 502 (L2-3/L5), so the
        event gets its own counter and the README's identity clause stays
        self-verifiable instead of aspirational."""
        self._overflow_pending[token] = entry
        evicted = 0
        while len(self._overflow_pending) > 4096:
            self._overflow_pending.popitem(last=False)
            evicted += 1
        if evicted:
            self.metrics["overflow_evictions"] += evicted
            LOG.warning("overflow ledger hit its 4096 cap and evicted %d pending re-home(s) -- "
                        "this many concurrent parked re-homes means the box fleet is far past "
                        "any real load; their requests will 502 instead of home-queue", evicted)

    def overflow_commit(self, affinity_key, token=None):
        """The overflow target ANSWERED (first HTTP status -- any status: busy
        is not dead): the lane really warmed its cache there. Re-home now.

        The token says WHICH request's provisional re-home this is. A retry
        of the same lane may be parked on a third box right now under its own
        token: it neither gets re-homed by proxy here, nor loses anything
        when its own turn comes to commit, roll back or fizzle."""
        with self.lock:
            pend = self._overflow_pending.pop(token, None) if token else None
            if pend is None or pend[0] != affinity_key:
                return
            self.metrics["overflow_placements"] += 1
        self._affinity_put(affinity_key, pend[2])

    def overflow_rollback(self, affinity_key, token, failed_id):
        """The overflow target died BEFORE a single request byte was sent --
        nothing reached it, so nothing is lost by moving on. Release its
        reservation EXACTLY once (the caller must not end() it again; the
        returned tuple carries the reservation state of whatever box takes
        over) and hand the caller a box to queue at instead -- rule 2: the
        gate redirects, it never rejects.

        Returns (backend, reason, reserved): the live home ("sticky"), or --
        when the home itself raced into DOWN inside this same request -- a
        fresh placement ("migrated"), the pick-time doctrine again: a queued
        turn anywhere beats a 502 the SDK would only retry. The two honest-502
        endings differ in WHO holds the reservation: plain None means the
        rollback never touched it (no pending entry -- an operator cleared it):
        the caller's finally still releases ITS OWN alt reservation. A
        (None, "released", False) verdict means this function already ended
        the alt and the caller must NOT end it twice (R6-C note-1: today the
        branch behind it is unreachable -- _place re-includes when exclude
        covers everything -- but the contract must not depend on that)."""
        with self.lock:
            pend = self._overflow_pending.pop(token, None) if token else None
        if pend is None or pend[0] != affinity_key or pend[2] != failed_id:
            return None
        alt = self.by_id.get(failed_id)
        if alt is not None:
            alt.end()
            with alt.lock:
                # try_place counted a request that was never sent -- un-count it
                alt.stats["requests"] = max(0, alt.stats["requests"] - 1)
        with self.lock:
            self.metrics["overflow_rollbacks"] += 1
        home = self.by_id.get(pend[1])
        if home is not None and home.state != DOWN and home.begin():
            return home, "sticky", True
        # the home died mid-request too (or raced into its cooldown): migrate
        # this turn onward instead of failing it. Counted as the settled
        # overflow it is (overflow_rollbacks already ticked) plus the home's
        # migrations_from evidence; the lane's later turns re-place fresh on
        # their own once the poller drops the dead home's keys.
        alt2, reserved = self._place(exclude={failed_id} | ({home.id} if home else set()))
        if alt2 is not None and not reserved:
            reserved = alt2.begin()     # queue-anyway box (nothing accepted)
            if reserved:
                self._note_gate_bypass(alt2)
        if alt2 is not None:
            if home is not None:
                with home.lock:
                    home.stats["migrations_from"] += 1
            LOG.warning("overflow of %s died AND home %s is DOWN; migrated onward to %s (nothing lost)",
                        short(affinity_key), pend[1], alt2.id)
            return alt2, "migrated", reserved
        # no other box exists; the honest 502 stands -- but alt.end() ran
        # above, so hand the caller the released verdict (R6-C note-1)
        return (None, "released", False)

    def overflow_fizzle(self, affinity_key, token):
        """The overflow request ended WITHOUT ever answering (read timeout,
        the caller hanging up, a stream break before the first status) and
        without rolling back: drop its provisional entry so it cannot become
        a stale landmine for this lane's next turn, and book it. A stashed
        overflow settles EXACTLY once -- commit, rollback, or fizzle -- which
        is what makes the placement counters a closed identity."""
        with self.lock:
            if token is not None and self._overflow_pending.pop(token, None) is not None:
                self.metrics["overflow_fizzles"] += 1

    def _overflow_drop_key(self, affinity_key):
        """Forget a lane's provisional re-homes (operator pin, sticky clear):
        the requests themselves keep streaming where they are -- they just no
        longer earn a re-home. Each reservation still belongs to its request."""
        with self.lock:
            dead = [t for t, v in list(self._overflow_pending.items()) if v[0] == affinity_key]
            for t in dead:
                del self._overflow_pending[t]
            self.metrics["operator_cancelled"] += len(dead)
            return len(dead)

    def _note_gate_bypass(self, be):
        """The redirect fallback admitted onto a box whose require_idle gate
        REFUSES new work -- by design (the gate redirects, it never rejects),
        but it is the one path where work may land on a peer we cannot vouch
        for idle. It must never be invisible: count it, log it.

        A refusal that was ONLY max_inflight while the gate itself stood open
        is not a bypass -- that is our own traffic waiting behind our own
        traffic -- and must not tick (review L1-2/M2: a metric crying
        capacity-wolf on every third lane desensitizes operators to the real
        borrow alarms it exists to reveal)."""
        closed = False
        if be.require_idle:
            with be.lock:  # _accepts_locked reads several fields (L2-3/L6)
                closed = not be._accepts_locked(time.monotonic(), ignore_cap=True)
        if closed:
            with self.lock:
                self.metrics["gate_bypass_borrow"] += 1
            LOG.warning(
                "gate-bypass borrow of %s: no tier accepted, its require_idle gate was closed "
                "(redirect, never reject) -- borrowed work may meet the owner there", be.id,
            )

    # ---- affinity store ---------------------------------------------------
    def _affinity_get(self, key):
        ttl = float(self.cfg.get("sticky_ttl") or 0)
        with self.lock:
            hit = self.affinity.get(key)
            if not hit:
                return None
            backend_id, ts = hit
            if ttl > 0 and time.monotonic() - ts > ttl:
                del self.affinity[key]
                return None
            # idle-TTL: a live conversation keeps its pin -- ttl counts idle
            # time since the LAST turn, not since placement, so a long working
            # night never drifts an active session onto a cold box
            self.affinity[key] = (backend_id, time.monotonic())
            self.affinity.move_to_end(key)
            return backend_id

    def _affinity_put(self, key, backend_id):
        # explicit None check: `or 20000` silently turned a configured 0 into
        # 20000 and a negative cap into "empty the table on every write"
        # (R4-A/F7); validate_cfg rejects non-positive caps at boot now
        v = self.cfg.get("sticky_max")
        cap = 20000 if v is None else int(v)
        with self.lock:
            self.affinity[key] = (backend_id, time.monotonic())
            self.affinity.move_to_end(key)
            while len(self.affinity) > cap:
                self.affinity.popitem(last=False)

    def _affinity_drop_backend(self, backend_id):
        with self.lock:
            dead = [k for k, v in list(self.affinity.items()) if v[0] == backend_id]
            for k in dead:
                del self.affinity[k]
            stale = [k for k, v in list(self._overflow_pending.items())
                     if backend_id in v]
            for k in stale:
                del self._overflow_pending[k]
            if stale:
                # A migration (or eject) voided pending re-homes whose home OR
                # alt just died. That is NOT the operator-cancelled exception
                # the README's closed identity documents: the underlying
                # request may still complete elsewhere and its later settle
                # pops nothing -- book each drop as a fizzle NOW or the
                # identity gains an uncounted hole per home migration
                # (review L1-3/L1).
                self.metrics["overflow_fizzles"] += len(stale)
            return len(dead)

    # ---- selection --------------------------------------------------------
    def pick(self, affinity_key, pin=None, passthrough=False):
        """Return (backend, reason, reserved, overflow_token). Never returns
        None: queueing beats failing. `reserved` is False only on the
        last-resort forward, where the cooldown refused the slot but we send
        anyway (rule 4); the caller must then NOT call end() for this request.
        `overflow_token` is non-None only for reason=="overflow": the
        provisional re-home it waits for, settled by the SAME request via
        commit / rollback / fizzle.
        `passthrough`: a keyless GET/HEAD proxy (no conversation behind it) --
        it still occupies a slot but books passthrough_gets, never
        new_placements, so "new conversations" keeps its meaning (R4-A/F4).

        pin: an explicit x-strata-pin box id. It overrides affinity, tier and
        the max_inflight cap -- the operator escape hatch for "this subagent
        runs there" -- but it does NOT override require_idle: a borrowed peer's
        courtesy is not the operator's to waive. An unknown or unavailable pin
        falls back to normal placement instead of failing the task.
        """
        with self.lock:
            self.metrics["requests"] += 1

        if pin:
            want = self.by_id.get(pin)
            if want is not None and want.try_place(ignore_cap=True):
                if affinity_key:
                    self._affinity_put(affinity_key, want.id)
                    # an operator who just pinned this lane takes manual
                    # control: a provisional overflow re-home in flight must
                    # not silently overwrite the pin when its stream answers
                    # (review L1-2/S1). The request itself keeps streaming.
                    self._overflow_drop_key(affinity_key)
                with self.lock:
                    self.metrics["pinned"] += 1
                return want, "pinned", True, None
            with self.lock:
                self.metrics["pin_misses"] += 1
            LOG.warning("pin %r unavailable; falling back to normal placement", pin)

        home = None
        if affinity_key:
            want = self._affinity_get(affinity_key)
            home = self.by_id.get(want) if want else None
            if home is not None and home.take_sticky():
                with self.lock:
                    self.metrics["sticky_hits"] += 1
                return home, "sticky", True, None

        if home is not None:
            if home.state != DOWN:
                # Home is ALIVE but cannot take this turn right now (at cap,
                # or its idle gate closed by load that is not ours): overflow
                # the branch to a peer that is open NOW, tier order, atomic
                # reservation. "A conversation that overflowed stays where it
                # warmed its cache" now reaches branch (lane) level -- a
                # subagent branch queues behind the lane holding the slot no
                # more than a new conversation would. Two safety rails: the
                # overflow target is never a DOWN box's half-open trial (the
                # trial belongs to fresh placement, the recovery path -- here
                # the home queue is strictly better than a cold box), and the
                # re-home is NOT committed until the target answers (see
                # overflow_commit/rollback -- a dead-but-fresh peer must not
                # steal the lane with a 502).
                alt, reserved = self._place(exclude={home.id}, no_trial=True)
                if alt is home:
                    # single-box pool whose gate re-opened in the microsecond
                    # since take_sticky refused: that IS the sticky take.
                    if reserved:
                        with self.lock:
                            self.metrics["sticky_hits"] += 1
                        return home, "sticky", True, None
                if alt is not None and reserved:
                    with self.lock:
                        self._overflow_token += 1
                        token = self._overflow_token
                        self._stash_pending(token, (affinity_key, home.id, alt.id))
                    LOG.info("lane %s overflow %s -> %s (home at capacity/gate closed; re-home on first byte)",
                             short(affinity_key), home.id, alt.id)
                    return alt, "overflow", True, token
                # nowhere else takes it either: home's FIFO still beats a cold
                # peer or a failure (rule 2 -- the gate redirects, never rejects)
                if home.begin():
                    self._note_gate_bypass(home)   # queueing at a home whose
                    # own require_idle gate is closed is exactly the borrowed
                    # work the metric exists to reveal -- never invisible
                    with self.lock:
                        self.metrics["sticky_hits"] += 1
                    return home, "sticky", True, None
                # raced into DOWN between the two attempts: fall through to
                # the migration path below
            # The conversation has a home box but it is unreachable or cooling
            # down: move the conversation rather than fail it, and remember the
            # move so later turns do not ping-pong back to the dead box.
            alt, reserved = self._place(exclude={home.id})
            if alt is not None and not reserved:
                reserved = alt.begin()     # queue-anyway box (nothing accepted)
                if reserved:
                    self._note_gate_bypass(alt)
            if alt is not None and reserved:
                with self.lock:
                    self.metrics["migrations"] += 1
                with home.lock:
                    home.stats["migrations_from"] += 1
                dropped = self._affinity_drop_backend(home.id)
                LOG.warning(
                    "affinity %s migrating %s -> %s (dropped %d keys); one cold prompt re-read expected",
                    short(affinity_key), home.id, alt.id, dropped,
                )
                self._affinity_put(affinity_key, alt.id)
                return alt, "migrated", True, None
        else:
            # New conversation: put it on the shallowest ACCEPTING queue and
            # pin it there. The reservation happens inside _place, atomically
            # with the gate check -- concurrent first turns cannot both take
            # the last slot of a capped box.
            alt, reserved = self._place()
            if alt is not None and not reserved:
                reserved = alt.begin()     # queue-anyway box (nothing accepted)
                if reserved:
                    self._note_gate_bypass(alt)
            if alt is not None and reserved:
                if affinity_key:
                    self._affinity_put(affinity_key, alt.id)
                with self.lock:
                    self.metrics["passthrough_gets" if passthrough else "new_placements"] += 1
                return alt, "placed", True, None

        # Every reservation path lost the race or was refused. Give each
        # candidate its real begin() in load order BEFORE booking a
        # last-resort forward: the box whose half-open trial is actually free
        # takes it (that is exactly the last-resort trial forward we forward
        # into anyway) instead of leaving the choice to load_score's random
        # tie-break -- an honest diagnostic beats a coin flip (stress Q2/F2).
        be = None
        for cand in sorted(self.backends, key=lambda b: b.load_score()):
            if cand.begin():
                be = cand
                break
        reserved = be is not None
        if be is None:
            be = min(self.backends, key=lambda b: b.load_score())
        if reserved:
            with be.lock:
                alive = be.state != DOWN
            if alive:
                # Healthy box, reservations raced (the half-open trial opened
                # between try_place and begin): queuing at a LIVE box is
                # borrowed work, not the all-down last-resort the counter
                # warns about -- book it where an operator reads it right
                # (stress P2/C4). Exactly one placement tick per request
                # either way; the ledger sum is untouched.
                self._note_gate_bypass(be)
                with self.lock:
                    self.metrics["passthrough_gets" if passthrough else "new_placements"] += 1
                if affinity_key:
                    self._affinity_put(affinity_key, be.id)   # "placed" means homed
                LOG.info("new placement found every gate closed mid-race; queued at live %s", be.id)
                return be, "placed", True, None
        with self.lock:
            self.metrics["last_resort"] += 1
        LOG.warning("every backend is cooling down; last-resort forward to %s", be.id)
        return be, "last_resort", reserved, None

    def _place(self, exclude=None, no_trial=False):
        """Tiered placement with atomic reserve: returns (backend, reserved).
        Tiers are tried in ascending `priority`; inside a tier boxes are tried
        by ascending score and the first that passes its gate AND takes the
        reservation wins (Backend.try_place). If no box in any tier accepts,
        the FIRST (highest-priority) tier that is merely healthy becomes the
        queue -- returned UNRESERVED so the caller decides (waiting in the
        primary box's FIFO beats borrowing a busy peer or failing; the gate
        redirects, it never rejects, rule 2 stays intact).

        no_trial: skip DOWN boxes entirely -- they may not even take the
        half-open trial. For overflow, where the caller has a live home to
        queue at; the trial stays reserved for fresh placement (recovery).

        With every box at the default priority 0 and no caps this is exactly
        the old single-tier least-queued behaviour."""
        cands = [b for b in self.backends if not (exclude and b.id in exclude)]
        if not cands:
            cands = list(self.backends)
        if not cands:
            return None, False
        fallback = None
        for prio in sorted({b.priority for b in cands}):
            tier = [b for b in cands if b.priority == prio]
            usable = [b for b in tier if b.load_state_ok() and (b.state != DOWN or not no_trial)]
            if not usable:
                continue
            for b in sorted(usable, key=lambda b: b.load_score()):
                if b.try_place():
                    return b, True
            if fallback is None:
                fallback = usable
        return min(fallback or cands, key=lambda b: b.load_score()), False

    def status(self):
        with self.lock:
            dist = {}
            for backend_id, _ts in self.affinity.values():
                dist[backend_id] = dist.get(backend_id, 0) + 1
            out = dict(self.metrics)
            out["affinity_keys"] = len(self.affinity)
            out["affinity_by_backend"] = dist
            # the provisional window made observable: overflows that have left
            # home but not yet earned a re-home (each settles within its own
            # request's lifetime -- a number that GROWS is the landmine signal)
            out["overflow_pending"] = len(self._overflow_pending)
            return out


# ---------------------------------------------------------------------------
# affinity key: stable across turns of one conversation, different per conversation
# ---------------------------------------------------------------------------

def affinity_key_of(path, body, headers):
    """Two-level key -- SCOPE + "/" + LANE -- either alone when only one is known:

      scope:  x-strata-affinity header  (explicit pin / debugging)  -- alone
              metadata.user_id          (Claude Code session id)
              prompt_cache_key / user / session_id (Responses-style)
      lane:   hash of the *stable* prompt prefix: system + tools + first turn.

    The scope alone is NOT the key: Claude Code's metadata.user_id is a
    SESSION id, and its subagents all share it -- keying on it merges every
    parallel branch into one conversation, pinning them all to one box while
    the second box idles (observed in production). The lane part separates
    them: branches differ in their first turn, so each becomes its own lane
    and is placed on its own box; a branch's later turns keep the same first
    turn, so the lane holds its warm cache for the branch's life -- for as
    long as system+tools hold too (a session whose tool set changes mid-run,
    an MCP server connecting, deliberately reads as a NEW prompt prefix: the
    warm cache was keyed on the old prefix anyway).
    The growing tail must never be in the key or every turn would look like a
    new conversation and get re-placed onto a cold cache.
    """
    hdr = headers.get("x-strata-affinity")
    if hdr:
        return "hdr:" + sha1_16(hdr)

    obj = _json_or_none(body)
    if not isinstance(obj, dict):
        # FULL body hashed: repr(body[:65536]) merged every two malformed
        # bodies sharing their first 64 KB into one lane (stress P2).
        return ("anon:" + sha1_16(path + ":" + hashlib.sha1(body).hexdigest())) if body else None

    scope = None
    md = obj.get("metadata")
    if isinstance(md, dict):
        uid = md.get("user_id")
        if isinstance(uid, str) and not uid.strip():
            uid = None    # whitespace counts as absent (pre-1.2.12 semantics)
        if uid is not None and uid != "" and uid != {} and uid != []:
            # Any present user_id is a scope signal: dropping non-strings
            # silently merged every session whose first turn happened to
            # match (five distinct sessions, one lane -- stress P2). _dump
            # keeps the JSON type (json quotes strings, so int 1 and string
            # "1" are structurally distinct scopes); a restart wipes the
            # in-memory affinity table anyway, so the changed string hash
            # costs nothing. Empty string/dict/list = absent, as before.
            scope = "meta:" + sha1_16(_dump(uid))
    if scope is None:
        for field in ("prompt_cache_key", "user", "session_id"):
            v = obj.get(field)
            if isinstance(v, (str, int, float, bool)) and str(v).strip():
                # same doctrine: 12345 and "12345" are not the same session
                # -- str() flattening aliased them (stress P2).
                scope = field + ":" + sha1_16(_dump(v))
                break

    parts = []
    system = obj.get("system")
    if isinstance(system, str):
        parts.append(system)
    elif system is not None:
        parts.append(_dump(system))
    if obj.get("tools") is not None:
        parts.append(_dump(obj["tools"]))
    if obj.get("input") is not None:
        parts.append(_dump(_first(obj.get("input"))))
    if obj.get("messages") is not None:
        parts.append(_dump(_first(obj.get("messages"))))
    if obj.get("prompt") is not None:
        # legacy /v1/completions (R4-A/F3): stateless clients resend the whole
        # prompt every turn, so the HEAD of it is the stable conversation
        # prefix. Hashing only the head keeps the lane warm while the head
        # holds and re-places when the conversation really changes -- without
        # it, completions traffic got no affinity pillar at all.
        parts.append(_dump(obj["prompt"])[:4096])
    lane = "prefix:" + sha1_16(chr(31).join(parts)) if any(parts) else None

    if scope and lane:
        return scope + "/" + lane
    return scope or lane


def _first(x):
    if isinstance(x, list) and x:
        return x[0]
    return x


# ---------------------------------------------------------------------------
# backend status polling -- the "least-queued" signal
# ---------------------------------------------------------------------------

_WALK_DEPTH = 6
_QUEUE_KEYS = re.compile(r"(queue|queued|waiting|pending|backlog|deferred)", re.I)
_SERVING_KEYS = re.compile(r"(serv|running|active|inflight|in_flight|decod|slot|processing)", re.I)
# Words that name capacity or configuration, never live load. Strata's own
# schema carries the traps: concurrency.serving is the configured slot count
# (>= 1 even when idle), the vram section reports reserve_mib / expert_slots,
# and "reserve" contains "serve" -- so the shallowest-path rule below could
# promote a VRAM MiB figure (16 chars) over the true activity.in_flight (18).
# A leaf whose path holds any of these words is never load.
_CAP_WORD = re.compile(r"(vram|concurrency|expert|cache|max|requested|reserve|capacity|limit|timeout|window|_mib)", re.I)


def walk_ints(node, path, out, depth=0):
    """Collect numeric leaves with dotted paths, tolerant of schema drift.
    A list is also reduced to a busy-slot count so /metrics-style arrays work."""
    if depth > _WALK_DEPTH or len(out) > 400:
        return out
    if isinstance(node, dict):
        for k, v in node.items():
            walk_ints(v, path + (str(k),), out, depth + 1)
    elif isinstance(node, bool):
        return out
    elif isinstance(node, (int, float)):
        if math.isfinite(float(node)):      # NaN/Infinity is not load data (R4-B/F1)
            out.append((".".join(path), float(node)))
    elif isinstance(node, list):
        busy = 0
        for item in node:
            if isinstance(item, dict):
                st = str(item.get("state") or item.get("status") or "").lower()
                if st and st not in ("idle", "free", "empty", "none", "off"):
                    busy += 1
                for k, v in item.items():
                    if isinstance(v, (int, float)) and not isinstance(v, bool) and \
                            math.isfinite(float(v)) and _QUEUE_KEYS.search(str(k)):
                        out.append((".".join(path + (str(k),)), float(v)))
            elif isinstance(item, (int, float)) and not isinstance(item, bool):
                busy += 1 if item else 0
        out.append((".".join(path) + ".__busy_serving__", float(busy)))
    return out


def _pick_box_extras(obj, out):
    """v1.2.14 presence-gated extras: the box's OWN published numbers ride along
    when it publishes them (Strata /v1/status carries last_timings/uptime/gpu;
    /metrics carries the live instant rate). None means the box does not publish
    it -- never a fabricated zero. Extras must never sink the serving/queued
    verdict, so every access is guarded and the whole pick is best-effort."""
    try:
        if not isinstance(obj, dict):
            return out
        lt = obj.get("last_timings")
        if isinstance(lt, dict):
            v = lt.get("predicted_per_second")
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
                out["decode_tok_s"] = round(float(v), 1)
        live = obj.get("live")
        if isinstance(live, dict):            # /metrics shape: instant rate instead
            v = live.get("tok_s")
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
                out.setdefault("decode_tok_s", round(float(v), 1))
        up = obj.get("uptime_s")
        if isinstance(up, int) and not isinstance(up, bool) and up >= 0:
            out["box_uptime_s"] = up
        mach = obj.get("machine")
        gpu = mach.get("gpu") if isinstance(mach, dict) else None
        if isinstance(gpu, dict):
            u = gpu.get("util_pct")
            if isinstance(u, (int, float)) and not isinstance(u, bool) and 0 <= u <= 100:
                out["gpu_util_pct"] = int(round(float(u)))
    except Exception:
        pass
    return out


def parse_status(payload):
    try:
        # a lying box's NaN/Infinity literals arrive as None through this door
        # -- they must never walk as load, ride /stats as invalid JSON literals,
        # or poison score comparisons (R4-B/F1)
        obj = json.loads(payload, parse_constant=lambda _name: None)
    except Exception:
        return _parse_prometheus(payload)
    leaves = []
    walk_ints(obj, (), leaves)
    if not leaves:
        return None
    known = {}
    for path, val in leaves:
        known.setdefault(path, val)
    out = {"serving": None, "queued": None}
    if "activity.in_flight" in known:
        # Strata /v1/status: requests running PLUS the ones waiting for the
        # turn -- the honest total. Its concurrency.serving is capacity, and
        # the total already includes waiting, so no queue counter is added.
        out["serving"] = known["activity.in_flight"]
        return _pick_box_extras(obj, out)
    if "live.queued" in known or "live.running" in known:
        # Strata /metrics: live.queued always; live.running only when the
        # engine batches -- solo service keeps its runner in live.state.
        out["queued"] = known.get("live.queued")
        if "live.running" in known:
            out["serving"] = known["live.running"]
        else:
            live = obj.get("live")
            st = live.get("state") if isinstance(live, dict) else None
            out["serving"] = {"reading": 1.0, "generating": 1.0, "idle": 0.0, "unloaded": 0.0}.get(st)
            if out["serving"] is None and not out["queued"]:
                # an unmapped live.state with queued=0 is UNKNOWN, not idle:
                # unknown is never idle (the gate fails closed, rule 3)
                return None
        return _pick_box_extras(obj, out)
    for key, rx in (("serving", _SERVING_KEYS), ("queued", _QUEUE_KEYS)):
        cands = sorted([(len(p), v) for p, v in leaves
                        if rx.search(p) and not any(_CAP_WORD.search(seg) for seg in p.split("."))])
        if cands:
            # shallowest match wins: deep ones are per-slot detail
            out[key] = cands[0][1]
    if out["serving"] is None and out["queued"] is None:
        return None
    return _pick_box_extras(obj, out)


def _parse_prometheus(payload):
    out = {"serving": None, "queued": None}
    for line in payload.splitlines():
        if not line or line.startswith("#"):
            continue
        name = line.split("{", 1)[0].split(" ", 1)[0]
        if _CAP_WORD.search(name):
            continue
        m = re.search(r"([0-9eE.+-]+)\s*$", line)
        if not m:
            continue
        try:
            val = float(m.group(1))
        except ValueError:
            continue
        if _QUEUE_KEYS.search(name) and out["queued"] is None:
            out["queued"] = val
        elif _SERVING_KEYS.search(name) and out["serving"] is None:
            out["serving"] = val
    return out if out["serving"] is not None or out["queued"] is not None else None


class StatusPoller(threading.Thread):
    """Reads each box's own load endpoint so placement sees real queue depth
    instead of guessing. Strata publishes /v1/status (activity.in_flight =
    requests running + waiting) and /metrics (live.running / live.queued /
    live.state); fields that name a capacity -- concurrency.serving, the vram
    figures -- are never read as load. If neither endpoint answers, the score
    falls back to the router's own in-flight count, which is still correct."""

    daemon = True
    name = "status-poller"

    def __init__(self, pool, cfg):
        super().__init__()
        self.pool = pool
        self.cfg = cfg
        self.stop_evt = threading.Event()

    def run(self):
        while not self.stop_evt.is_set():
            for be in self.pool.backends:
                try:
                    self._poll(be)
                except Exception as exc:
                    with be.lock:
                        be.status_error = "poller: " + repr(exc)
            self.stop_evt.wait(max(0.2, float(self.cfg.get("status_interval") or 1.0)))

    def _poll(self, be):
        for sub in (self.cfg.get("status_paths") or ["/v1/status", "/metrics"]):
            code, body = self._get(be, sub)
            if code is None:
                # connection-level failure seen out of band: a real health signal
                be.note_connect_failure(
                    "status poll " + sub + " unreachable",
                    int(self.cfg.get("max_connect_failures") or 3),
                    float(self.cfg.get("down_backoff") or 20.0),
                )
                with be.lock:
                    be.status_ok = False
                    be.status_error = "unreachable"
                return
            if code == -1:
                # connected, then silence or a protocol break: busy is not
                # dead (rule 4). Charging this toward DOWN would eject a live
                # box mid-decode and migrate its warm conversations -- instead
                # mark the report stale and try the other status path.
                with be.lock:
                    be.status_ok = False
                    # upstream body is UNTRUSTED text on its way into /stats --
                    # clip it (review R1-B/F10): a hostile box must not turn the
                    # unauthenticated stats feed into its own message board
                    be.status_error = sub + ": no answer (" + (body[:120] + ("…" if len(body) > 120 else "")) + ")"
                continue
            # ANY HTTP answer -- even 401 or 500 -- proves the box is alive
            # (rule 4), and clears connect-failure debt from earlier stalls.
            be.note_success()
            if code == 200 and body:
                parsed = parse_status(body)
                if parsed and any(isinstance(v, float) and not math.isfinite(v)
                                  for v in parsed.values()):
                    # last gate between an untrusted box and /stats + load_score
                    # (R4-B/F1, prometheus path included): one non-finite number
                    # makes the whole sample a lie -- reject the sample
                    parsed = None
                if parsed:
                    with be.lock:
                        be.reported = parsed
                        be.status_ok = True
                        be.status_source = sub
                        be.status_error = None
                        be.ever_reported = True
                        be.status_ts = time.monotonic()
                        total = (parsed.get("serving") or 0) + (parsed.get("queued") or 0)
                        # ghost debt: requests we aborted that the box may still
                        # be counting for one keep-alive beat -- our corpses are
                        # not the owner's load (see GHOST_GRACE_S)
                        debt = sum(1 for t in be._ghost_debt if t > be.status_ts)
                        be.ext_streak = be.ext_streak + 1 if total > be.inflight + debt else 0
                    return
                with be.lock:
                    be.status_error = sub + ": 200 but no load field recognised"
            else:
                with be.lock:
                    be.status_error = sub + ": HTTP " + str(code)
        with be.lock:
            be.status_ok = False

    def _get(self, be, path):
        try:
            conn = open_connection(be, float(self.cfg.get("connect_timeout") or 5.0), float(self.cfg.get("status_timeout") or 3.0))
        except Exception as exc:
            return None, str(exc)          # refused / reset / connect-timeout: health signal
        try:
            conn.request("GET", be.prefix + path, headers=backend_headers(self.cfg, None, be))
            resp = conn.getresponse()
            body = resp.read(262144).decode("utf-8", "replace")
            code = resp.status
            conn.close()
            return code, body
        except Exception as exc:
            # reached the box but got no answer (read timeout / protocol
            # break): -1 = stalled, which never counts toward DOWN
            try:
                conn.close()
            except Exception:
                pass
            return -1, str(exc)


def open_connection(be, connect_timeout, read_timeout):
    conn = None
    try:
        if be.https:
            ctx = ssl._create_unverified_context() if be.cfg.get("tls_insecure") else ssl.create_default_context()
            conn = http.client.HTTPSConnection(be.host, be.port, timeout=connect_timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(be.host, be.port, timeout=connect_timeout)
        conn.connect()
        try:
            conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.sock.settimeout(read_timeout)
        except Exception:
            pass
        return conn
    except Exception:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        raise


_ILLEGAL_HV = re.compile(rb"[^\t\x20-\x7e\x80-\xff]")   # what http.client.putheader refuses


def backend_headers(cfg, incoming, backend=None):
    """Forward the caller's headers except hop-by-hop ones -- minus anything
    http.client could not encode (ASCII names, latin-1 values, no control
    bytes: those raise mid-request and kill the handler thread), and minus
    auth when we hold a key. A key configured for THIS backend always wins
    over whatever the caller sent: shims and CLI clients carry their own
    credential toward the ROUTER, which is not the box's key -- forwarding it
    verbatim would 401 every request (or exactly the borrowed turns, since
    mirror boxes hold different keys) while the dashboard looked healthy.
    With no configured key the caller's auth is forwarded untouched."""
    out = {}
    if incoming is not None:
        for k, v in incoming.items():
            lk = k.lower()
            if lk in STRIP_REQUEST_HEADERS:
                continue
            try:
                vb = v.encode("latin-1")
                k.encode("ascii")
            except UnicodeEncodeError:
                continue
            if not _HEADER_NAME_RE.fullmatch(k):
                # names get the same shape gate responses get (v1.2.12/F1):
                # a caller-supplied "x(y:" or "a b" is not an RFC 7230 token
                # -- relaying it bets the BOX's parser tolerates what ours
                # would not (stress Q2/F4). A junk name carries no meaning
                # the box needs; drop it.
                continue
            if _ILLEGAL_HV.search(vb):
                continue
            out[lk] = v
    out.setdefault("user-agent", "strata-router/" + VERSION)
    key = getattr(backend, "api_key", "") if backend is not None else ""
    if not key:
        key = cfg.get("backend_api_key") or os.environ.get("STRATA_BACKEND_API_KEY") or ""
    if key:
        for h in ("authorization", "x-api-key", "api-key"):
            out.pop(h, None)
        out["authorization"] = "Bearer " + key
        out["x-api-key"] = key
    return out


# ---------------------------------------------------------------------------
# HTTP handler -- the passthrough itself
# ---------------------------------------------------------------------------

BODY_METHODS = ("POST", "PUT", "PATCH", "DELETE")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True
    server_version = "strata-router/" + VERSION

    pool = None
    cfg = {}

    # ---- plumbing ---------------------------------------------------------
    def log_message(self, fmt, *args):
        LOG.debug("%s %s", self.address_string(), fmt % args)

    def _tune(self):
        try:
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

    def _json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            self.close_connection = True

    def _route_path(self):
        return self.path.split("?", 1)[0]

    # ---- inbound trust guards ----------------------------------------------
    # The router injects backend keys for callers that send none, so it must
    # know who is allowed to be a caller. It is bound to loopback by default,
    # which is the real boundary; these guards close the DNS-rebinding hole
    # where a remote web page rebinds its own domain to 127.0.0.1 and thereby
    # becomes "same origin" to the browser.
    _LOOPBACK = ("127.0.0.1", "localhost", "::1")

    def _entry_denied(self):
        """403 (connection closed) unless the request looks like it came from
        a local client on this router's own address. The body is drained
        (bounded) BEFORE the refusal: a close with the request body still in
        the kernel buffer makes Windows answer the close with an RST, and the
        refusal -- the only thing this caller learns -- never arrives."""
        if not self.path.startswith("/"):
            # absolute-form ("POST http://x/v1/messages") or any other
            # non-origin target: this router is not a forwarding proxy, and
            # the raw target would ride into the box's request line verbatim
            # (stress P1/F2). Origin-form only, refused by name.
            self._drain_body()
            self._json(400, {"error": {"message": "strata-router: request target must be origin-form (path starting with '/')"}})
            self.close_connection = True
            return True
        if not self.path.isascii() or re.search(r"[\x00-\x20\x7f]", self.path):
            # http.client encodes the request line as ASCII: a target with
            # high-bit or control bytes would raise UnicodeEncodeError mid-
            # relay and kill the handler with no response. Refuse at the door
            # (callers percent-encode; that stays pure ASCII).
            self._drain_body()
            self._json(400, {"error": {"message": "strata-router: request path must be ASCII without control characters"}})
            self.close_connection = True
            return True
        raw_host = (self.headers.get("host") or "").strip().lower()
        if raw_host.startswith("["):
            # IPv6 literal: [::1] or [::1]:8088. rsplit(":",1) on "[::1]"
            # chopped the address itself, so the ::1 entry was half-dead
            # (stress P1/F6).
            host = raw_host.rpartition("]")[0].lstrip("[")
        else:
            host = raw_host.rsplit(":", 1)[0]
        listen = str(self.cfg.get("listen") or "").strip().lower()
        if listen in self._LOOPBACK:
            allowed = self._LOOPBACK
        else:
            # Bound to a LAN/tailnet address: the loopback NAMES are no longer
            # evidence of a local caller -- a remote peer crafts Host: localhost
            # freely (curl does it without trying). Only the bound address is
            # admissible, and the boot warning about firewalling this port got
            # a lot more literal (review L2-2/M4).
            allowed = (listen,) if listen else self._LOOPBACK
        if host not in allowed:
            self._drain_body()
            self._json(403, {"error": {"message": "strata-router: foreign Host %r refused (rebinding guard)" % host}})
            self.close_connection = True
            return True
        org = self.headers.get("origin") or self.headers.get("referer")
        if org:
            m = re.match(r"https?://(\[[^\]]*\]|[^/:]+)", org)
            # the bracket alternative is what makes Origin: http://[::1]:8088
            # parse as the HOST [::1] -- the bare character class stopped at
            # the first colon inside the brackets and false-refused every
            # IPv6-literal dashboard caller (fail-closed, but closed on the
            # owner; stress Q1/Q2A-4 = Q2/F5). strip("[]") then yields the
            # address exactly as the Host check above compares it.
            if (m.group(1).strip("[]").lower() if m else "") not in allowed:
                self._drain_body()
                self._json(403, {"error": {"message": "strata-router: cross-origin caller refused (rebinding guard)"}})
                self.close_connection = True
                return True
        return False

    def _quiet_finish(self, secs=2.0):
        """Read what is left of an unwanted body politely, under a short
        deadline, so the refusal written after it reaches the sender over a
        still-live socket -- closing right here lets Windows RST-flush the
        bytes the sender still has queued and the caller learns nothing at
        all (stress P1/F3, Q1/Q2A-5)."""
        try:
            self.connection.settimeout(secs)
            deadline = time.monotonic() + secs
            while time.monotonic() < deadline and self.rfile.read(65536):
                pass
        except Exception:
            pass
        finally:
            try:
                self.connection.settimeout(None)
            except Exception:
                pass

    def _drain_body(self, limit=1 << 20):
        """Consume (bounded) whatever body a non-proxy route will not use, so
        the bytes cannot desync the next request on this keep-alive connection."""
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            self.close_connection = True
            return
        while n > 0:
            chunk = min(n, 65536)
            try:
                got = self.rfile.read(chunk)
            except Exception:
                self.close_connection = True
                return
            if not got:
                self.close_connection = True
                return
            n -= len(got)
            limit -= len(got)
            if limit <= 0:
                self._quiet_finish()
                self.close_connection = True
                return
        if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
            # A request refused at the door may carry its body chunked (TE
            # outranks any content-length) -- there is no number to count
            # down. The loops above would answer the 400/403 while the body
            # is still arriving: a keep-alive leftover parses as the next
            # request line, and a close RST-flushes the refusal away. Eat it
            # under the quiet deadline, then close regardless (stress
            # Q1/Q2A-5).
            self._quiet_finish()
            self.close_connection = True

    # ---- routes -----------------------------------------------------------
    def do_GET(self):
        self._tune()
        if self._entry_denied():
            return
        if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
            self.close_connection = True   # no content-length to drain by: close
                                           # rather than let leftover body bytes
                                           # parse as the next request line
        else:
            self._drain_body()  # GET with a body must not poison the connection
        path = self._route_path()
        if path == "/healthz":
            states = {b.id: b.state for b in self.pool.backends}
            up = any(b.state != DOWN for b in self.pool.backends)
            return self._json(200 if up else 503, {"ok": up, "version": VERSION, "backends": states})
        if path == "/__router/stats":
            return self._json(200, {
                "version": VERSION,
                "router": self.pool.status(),
                "backends": [b.snapshot() for b in self.pool.backends],
                "sticky_ttl_s": self.cfg.get("sticky_ttl"),
                "read_timeout_s": self.cfg.get("read_timeout"),
                # the interval actually in use (same `or 1.0` resolution as the
                # poller itself): a monitor must never guess the blind-window base
                "status_interval": float(self.cfg.get("status_interval") or 1.0),
                "started_at": ROUTER_STARTED,
                "uptime_s": int(time.time()) - ROUTER_STARTED,
                "time": time.time(),
            })
        if path in GET_PATHS or path.endswith("/models") or path.startswith("/v1/"):
            return self._proxy(b"")
        return self._json(404, {"error": {"message": "strata-router: no route for GET " + path}})

    def do_HEAD(self):
        self._tune()
        if self._entry_denied():
            return
        if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
            self.close_connection = True   # same as do_GET (stress P1/F4): a
                                           # chunked HEAD body has no length
                                           # to drain -- close, or the
                                           # leftovers parse as a request
        else:
            self._drain_body()  # a HEAD with a body must not poison the connection
        return self._proxy(b"", head=True)

    def _control_ok(self):
        """The control surface (x-strata-pin, sticky/clear) shares the router's
        localhost trust by default -- a documented model, but optionally
        gateable with a control token (keys-file "control" entry or
        control_token). Any OTHER local process can otherwise exile lanes
        (pin) or cold-re-home everything (clear), and any loopback-origin web
        page can fire the no-preflight clear (review L2-2/M2, L-1). When set,
        callers must send x-strata-control."""
        tok = str(self.cfg.get("_control_token") or self.cfg.get("control_token") or "").strip()
        # "_control_token" is what apply_keys() resolved; falling back to the
        # raw inline field means an embedded boot that skipped apply_keys
        # still honors the token it printed in its own config instead of
        # silently running an OPEN gate (the same `or` chain validate_cfg's
        # checks use -- boot-time verdict and runtime gate must read the
        # token from the same place; stress Q2/F6).
        if not tok:
            return True
        got = (self.headers.get("x-strata-control") or "").strip()
        if not got:
            return False
        try:
            return hmac.compare_digest(tok, got)
        except TypeError:
            # compare_digest rejects non-ASCII strings; a header decodes as
            # latin-1, so ANY local process with a stray high byte would kill
            # this handler thread (zero response bytes, L2-3/L1). A non-ASCII
            # header can never be the token -- answer 403, stay alive.
            return False

    def do_POST(self):
        self._tune()
        if self._entry_denied():
            return
        path = self._route_path()
        if path == "/__router/sticky/clear":
            if self.command != "POST":
                # OPTIONS must NOT alias into a destructive route (it is also
                # what a CORS preflight would fire) -- POST only (review L2-2/L2).
                self._drain_body()
                self._json(405, {"error": {"message": "strata-router: sticky/clear is POST-only"}})
                return
            if not self._control_ok():
                self._drain_body()
                self._json(403, {"error": {"message": "strata-router: control token required for sticky/clear (x-strata-control)"}})
                return
            self._drain_body()  # answer only AFTER consuming the body
            with self.pool.lock:
                n = len(self.pool.affinity)
                m = len(self.pool._overflow_pending)
                self.pool.affinity.clear()
                self.pool._overflow_pending.clear()
                self.pool.metrics["operator_cancelled"] += m
            return self._json(200, {"cleared_affinity_keys": n})
        body = self._read_body()
        if body is None:
            return
        return self._proxy(body)

    do_PUT = do_PATCH = do_DELETE = do_POST

    def do_OPTIONS(self):
        # OPTIONS is answered 405 on EVERY path (stress Q1/Q2A-3): the README
        # always claimed it, and a lying box was supposed to find no CORS
        # surface here -- but until now only sticky/clear refused it, so any
        # other path aliased into do_POST and an OPTIONS with a body was
        # PROXIED toward the box (a preflight-shaped probe answered with a
        # real inference, and without one, a chunked body sat unread). One
        # named answer, everywhere, body eaten first.
        self._tune()
        if self._entry_denied():
            return
        self._drain_body()
        self._json(405, {"error": {"message": "strata-router: no OPTIONS/CORS surface -- POST inference requests only"}})
        self.close_connection = True

    def _read_body(self):
        """Buffer the body: we must hash the prompt prefix before choosing a box.
        Returns None when an error response was already sent (always with the
        connection closed, so unparsed bytes can't masquerade as the next
        request line on a keep-alive connection)."""
        limit = int(self.cfg.get("max_body_mb") or 512) * 1024 * 1024
        te = (self.headers.get("transfer-encoding") or "").lower()
        if "chunked" in te:
            parts = []
            used = 0
            while True:
                raw = self.rfile.readline(65536)
                if not raw or raw.strip() == b"":
                    # EOF or a bare blank line where a chunk-size belongs.
                    # The old code broke out of the loop silently, turning a
                    # truncated body into a "complete" request at the box
                    # (stress P1/F4) -- neither shape is legal framing.
                    self._json(400, {"error": {"message": "strata-router: chunked body ended before the final chunk"}})
                    self.close_connection = True
                    return None
                line = raw.strip()
                size = line.split(b";")[0].strip()
                if not re.fullmatch(rb"[0-9a-fA-F]+", size):
                    # int(x, 16) is generous: it accepts "-1" (becomes
                    # read(-1) -- an UNBOUNDED read to EOF that walks past
                    # max_body_mb), "-2" (becomes ValueError inside read(),
                    # killing the handler with zero response bytes) and
                    # "0x21"/"1_0" forms. Hex digits only, or a named 400
                    # (review L2-2/M1).
                    self._json(400, {"error": {"message": "strata-router: bad chunk framing"}})
                    self.close_connection = True
                    return None
                n = int(size, 16)
                if n == 0:
                    trailers = 0
                    while True:
                        t = self.rfile.readline(4096)
                        if t in (b"", b"\r\n", b"\n"):
                            break       # trailer headers, then the blank line
                        trailers += 1
                        if trailers > 64:
                            # the final-chunk trailer loop was the one
                            # unbounded read left on this path (stress P1/F4).
                            # Counted in LINES, but readline(4096) caps each
                            # line at 4 KB, so the real bound is ~256 KB of
                            # trailer bytes -- lines are the unit, bytes are
                            # the ceiling (stress Q1/Q2A-6).
                            self._json(400, {"error": {"message": "strata-router: too many trailer headers"}})
                            self.close_connection = True
                            return None
                    break
                if used + n > limit:
                    self._json(413, {"error": {"message": "strata-router: body over max_body_mb"}})
                    self.close_connection = True
                    return None
                parts.append(self.rfile.read(n))
                used += n
                if self.rfile.readline(2) != b"\r\n":
                    # strict CRLF: chunk data not followed by CRLF is framing
                    # the router never agreed to parse; the old blind
                    # readline(2) accepted anything (stress P1/F4)
                    self._json(400, {"error": {"message": "strata-router: chunk data not terminated by CRLF"}})
                    self.close_connection = True
                    return None
            body = b"".join(parts)
            if len(body) > limit:
                self._json(413, {"error": {"message": "strata-router: body over max_body_mb"}})
                self.close_connection = True
                return None
            return body
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            self._json(400, {"error": {"message": "strata-router: bad content-length"}})
            self.close_connection = True
            return None
        if n < 0:
            self._json(400, {"error": {"message": "strata-router: bad content-length"}})
            self.close_connection = True
            return None
        if n == 0:
            return b""
        if n > limit:
            # check BEFORE reading: never buffer a body we will refuse
            self._json(413, {"error": {"message": "strata-router: body over max_body_mb"}})
            self.close_connection = True
            return None
        return self.rfile.read(n)

    # ---- the passthrough --------------------------------------------------
    def _watch_hangup(self, conn, gone):
        """Release the box the moment the CALLER hangs up -- not when a write
        happens to fail. Strata watches its clients with MSG_PEEK for exactly
        this (its _watch_client) so a hung-up request gives its FIFO seat up
        even while nothing is being written; but to Strata its client is US,
        and unless we watch our own caller the same way, a killed caller is
        invisible: localhost send buffers happily swallow keep-alive after
        keep-alive to a dead socket, the box burns minutes of prefill serving
        a dead request, and everything queued behind it starves (observed in
        production: one killed agent = a minutes-long zombie holding the only
        slot). Every CLIENT_WATCH_S: caller readable + a zero-byte peek == EOF;
        a socket error on the peek == RST; both mean hangup. Readable DATA is
        a pipelined next request: the caller is alive (Strata's rule, kept).
        On hangup, shut the backend socket down: that unblocks a relay parked
        in getresponse()/read(). The box's own watcher SETS the cancel flag
        within its 0.5 s poll: a request already in the slot stops within ~1 s
        (per-token cancel checks); one still parked in the FIFO notices at its
        next keep-alive beat (QUEUE_BEAT_S = 10 s) or at slot grant. Either
        way the seat frees on its own -- the router never has to chase it.
        """
        caller = self.connection
        sock = getattr(conn, "sock", None)

        def watch():
            while not gone.wait(CLIENT_WATCH_S):
                try:
                    r, _, _ = select.select([caller], [], [], 0)
                    if r and caller.recv(1, socket.MSG_PEEK) == b"":
                        gone.set()                      # EOF: caller closed
                except (ConnectionError, TimeoutError):
                    gone.set()                          # RST mid-peek: caller gone
                except (OSError, ValueError):
                    return                              # our socket closed: request ending
                if gone.is_set():
                    try:
                        if sock is not None:
                            sock.shutdown(socket.SHUT_RDWR)
                    except (OSError, ValueError):    # the relay's finally closed it first
                        pass
                    return

        threading.Thread(target=watch, daemon=True, name="router-client-watch").start()

    def _proxy(self, body, head=False):
        path = self.path
        bare = self._route_path()
        method = "HEAD" if head else self.command

        # parse config BEFORE reserving: a bad value must never leak a slot
        max_fails = int(self.cfg.get("max_connect_failures") or 3)
        backoff = float(self.cfg.get("down_backoff") or 20.0)
        connect_timeout = float(self.cfg.get("connect_timeout") or 5.0)
        read_timeout = self.cfg.get("read_timeout")
        read_timeout = None if read_timeout in (0, None, "0") else float(read_timeout)

        try:
            body = self._rewrite_model(body)
        except Exception as exc:
            # The ONE sanctioned body edit must never bill a healthy box for
            # the router's own trouble: rewrite happens BEFORE pick, and a
            # body the re-encoder chokes on is the CALLER's 400, not a
            # connect failure (review L2-2/M3).
            self._json(400, {"error": {"message": "strata-router: model rewrite failed on this body (%s)" % type(exc).__name__}})
            self.close_connection = True
            return

        key = affinity_key_of(bare, body, self.headers) if body else None
        pin = (self.headers.get("x-strata-pin") or "").strip() or None
        if pin and not self._control_ok():
            self._json(403, {"error": {"message": "strata-router: x-strata-pin refused -- control token required (x-strata-control)"}})
            self.close_connection = True
            return
        backend, reason, reserved, ovf_token = self.pool.pick(
            key, pin=pin, passthrough=(key is None and method in ("GET", "HEAD")))
        was_overflow = reason == "overflow"   # its pending entry must settle EXACTLY once
        # before this request ends: commit (it answered), rollback (target died
        # pre-send) or fizzle (ended any other way). ovf_settled tracks that.
        ovf_settled = False
        is_count_tokens = bare.endswith(COUNT_TOKENS_SUFFIX)

        started = time.monotonic()
        ttfb = None
        headers_out = False
        read_break = False    # the exception came from the BACKEND side of the relay
        sent = False          # did the request bytes complete toward the box?
        answered = False      # did the box's status line + headers parse?
        connect_charged = False  # an already-booked connect failure: never charge twice
        total = 0
        client_gone = threading.Event()  # watchdog: caller hung up (see _watch_hangup)
        conn = None
        try:
            try:
                conn = open_connection(backend, connect_timeout, read_timeout)
            except (ConnectionError, TimeoutError, OSError) as exc:
                if reason != "overflow":
                    raise
                # The overflow target is unreachable BEFORE a byte was sent:
                # nothing was lost (and it is a real health event, charged
                # right here -- the outer handler must not charge it again).
                # A queued home turn beats a 502 the SDK would only retry --
                # roll the overflow back and queue at home (rule 2). The pool
                # has already released the alt reservation EXACTLY once; the
                # tuple hands over the reservation state of the box it chose
                # (live home, or a fresh placement when home raced into DOWN).
                backend.note_connect_failure(method + " " + bare + ": overflow target: " + type(exc).__name__,
                                             max_fails, backoff)
                connect_charged = True
                outcome = self.pool.overflow_rollback(key, ovf_token, backend.id)
                if outcome is None:
                    # nothing to roll back to (an operator cleared this lane's
                    # pending mid-flight): the honest 502 stands; the finally
                    # releases this request's own alt reservation
                    raise
                if outcome[0] is None:
                    # rolled back and found nowhere to go: the honest 502
                    # stands, but the rollback already ended the alt -- the
                    # finally must not end() it a second time (R6-C note-1)
                    reserved = False
                    raise
                LOG.info("%s %s: overflow target %s died before send; %s at %s instead (nothing was lost)",
                         method, bare, backend.id,
                         "queued at home" if outcome[1] == "sticky" else "migrated", outcome[0].id)
                backend, reason, reserved = outcome
                ovf_settled = True
                connect_charged = False   # any FURTHER connect failure is a
                # different backend's (home/alt2 refused too) -- the outer
                # handler must book THAT one; the alt's is already accounted
                conn = open_connection(backend, connect_timeout, read_timeout)
            self._watch_hangup(conn, client_gone)
            fwd_body = body
            hdrs = backend_headers(self.cfg, self.headers, backend)
            if method in BODY_METHODS:
                hdrs["content-length"] = str(len(fwd_body or b""))
                hdrs.setdefault("content-type", "application/json")
                hdrs.setdefault("accept", "application/json, text/event-stream")
            conn.request(method, backend.prefix + path, body=(fwd_body or b"") if method in BODY_METHODS else None, headers=hdrs)
            sent = True
            resp = conn.getresponse()

            # Any HTTP status at all proves the box is alive -- including 429
            # (queue_wait_timeout) and 5xx. Busy is not dead. Rule 4.
            backend.note_success()
            answered = True   # from here on, any break is the CALLER's or the
            # relay's -- the box answered; "did not start answering" must
            # never be booked against it (stress Q2/F1)
            if reason == "overflow" and not is_count_tokens:
                # first byte from the overflow target: the lane earns its new
                # home (this is where a re-home becomes real). NOT for
                # count_tokens: tokenizing warms no cache, and a token-count
                # preview must never be the event that exiles a conversation
                # to the borrowed box (review L1-2/S2) -- its pending entry
                # settles as a fizzle when the request ends.
                self.pool.overflow_commit(key, ovf_token)
                ovf_settled = True
            with backend.lock:
                backend.stats["last_status"] = resp.status
                if 400 <= resp.status < 500:
                    backend.stats["http_4xx"] += 1
                elif resp.status >= 500:
                    backend.stats["http_5xx"] += 1

            # Claude Code calls /v1/messages/count_tokens; plenty of local servers
            # answer 404. A plausible number beats killing the session.
            if bare.endswith(COUNT_TOKENS_SUFFIX) and resp.status in (404, 405, 501):
                try:
                    resp.read()
                except Exception:
                    pass
                with self.pool.lock:
                    self.pool.metrics["count_tokens_synthesized"] += 1
                obj = _json_or_none(body) or {}
                text = _dump(obj)
                return self._json(200, {"input_tokens": max(1, int(len(text) / 4))})

            _reason = resp.reason
            if _reason and re.search(r"[\r\n]", _reason):
                # send_response writes the reason VERBATIM into the status
                # line (probe-verified on 3.13) -- a lying box's CR/LF there
                # is a LINE TERMINATOR to every WHATWG-fetch parser (lone CR
                # included), splitting the status line into a forged header
                # the entire header-side filter above never gets to see.
                # Relay the standard phrase for the code instead; the status
                # NUMBER is untouched (stress Q1/Q2A-1).
                _reason = None
            self.send_response(resp.status, _reason)
            skip = HOP_BY_HOP | {"content-length", "content-type", "date", "server"}
            for k, v in resp.getheaders():
                kl = k.lower()
                if kl in skip or kl.startswith("access-control-"):
                    # access-control-* is stripped by name: the router never
                    # speaks CORS (same-origin by design, OPTIONS answers 405),
                    # and a lying box relaying "access-control-allow-origin:
                    # http://evil" through this passthrough is the ONE channel
                    # by which a browser page could READ our caller's model
                    # output (stress P1/F1).
                    continue
                v = _HDR_VAL_CTL_RE.sub("", v)
                if not _HEADER_NAME_RE.fullmatch(k) or "\r" in v or "\n" in v:
                    # Parser-drift backstop: 3.13's http.client splits bare
                    # CR/LF framing into separate well-formed headers (a lying
                    # box then just sets ordinary headers -- the documented
                    # trust model), but a parser that KEEPS the newline inside
                    # one value would let send_header -- which does not shape-
                    # check -- write a second header line in our voice. Names
                    # must be RFC 7230 tokens, values must be single-line.
                    continue
                self.send_header(k, v)
            # the reattach must pass the SAME sanitizer as the relay loop:
            # content-type is skipped there precisely because it is rebuilt
            # here, so before R6-C/P3-1 a lying box's "text/plain; q\x00z=1"
            # slipped the C0 gate intact and a log that truncates at NUL saw
            # a different type than the router did.
            self.send_header("content-type",
                             _HDR_VAL_CTL_RE.sub("", resp.getheader("content-type")
                                                 or "application/json"))
            chunk_out = not head and self.request_version != "HTTP/1.0"
            if head:
                # a HEAD response is header-only: no chunk framing, no body,
                # or the terminator bytes desync the next response on this socket
                self.send_header("content-length", "0")
            elif chunk_out:
                self.send_header("transfer-encoding", "chunked")
            else:
                # HTTP/1.0 knows no chunked coding: close-delimited is the
                # only honest framing for that caller (stress P1/F9), and
                # the close is the end-of-body signal it gets.
                self.close_connection = True
            if self.cfg.get("expose_affinity"):
                # --no-expose-affinity hides all of it, the box id included
                self.send_header("x-strata-backend", backend.id)
                if key:
                    self.send_header("x-strata-affinity", short(key))
                    self.send_header("x-strata-placement", reason)
            self.end_headers()
            headers_out = True
            self.wfile.flush()

            # read1, NEVER read: Strata ends SSE by closing the connection
            # (HTTP/1.0, no length, no chunking), and HTTPResponse.read(n) on
            # such a body is a FILL-read -- it blocks until n bytes or EOF.
            # That would hold every token delta and every queue keep-alive
            # until the turn ended, and stop propagating client aborts.
            # read1 returns whatever has arrived; b"" still marks EOF.
            while True:
                try:
                    chunk = resp.read1(65536)
                except Exception as exc:
                    read_break = True
                    if not client_gone.is_set():   # a shutdown the watchdog caused
                        backend.note_stream_error("backend side: " + str(exc))
                    raise
                if not chunk:
                    break
                if ttfb is None:
                    ttfb = time.monotonic() - started
                total += len(chunk)
                if head:
                    continue            # drain the box, never relay a body:
                                        # a lying box's HEAD body must not
                                        # reach the caller behind "length: 0"
                if chunk_out:
                    self.wfile.write(b"%X\r\n" % len(chunk))
                    self.wfile.write(chunk)
                    self.wfile.write(b"\r\n")
                else:
                    self.wfile.write(chunk)
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n" if chunk_out else b"")
            self.wfile.flush()

            duration = time.monotonic() - started
            sse = "event-stream" in (resp.getheader("content-type") or "")
            with backend.lock:
                backend.stats["streams"] += 1
                backend.stats["dur_sum"] += duration
                backend.stats["bytes_out"] += total
                if ttfb is not None:
                    backend.stats["ttfb_sum"] += ttfb
                    backend.stats["ttfb_n"] += 1
                    backend.stats["last_ttfb"] = round(ttfb, 2)
                    backend.recent_ttfb.append(round(ttfb, 2))
                    if len(backend.recent_ttfb) > RECENT_TTFB_WINDOW:
                        backend.recent_ttfb.pop(0)
            # A big ttfb while nothing else was running means the request was
            # sitting in the backend FIFO. That is the queue working -- watch it.
            LOG.info(
                "%s %s -> %s %s %s ttfb=%s dur=%.2fs out=%dB key=%s place=%s",
                method, bare, backend.id, resp.status, "sse" if sse else "body",
                ("%.2fs" % ttfb) if ttfb is not None else "-", duration, total, short(key), reason,
            )
        except (ConnectionError, socket.timeout, TimeoutError, BrokenPipeError, http.client.HTTPException,
                OSError, UnicodeError, ValueError) as exc:
            duration = time.monotonic() - started
            if client_gone.is_set():
                # The watchdog saw the caller hang up and already released the
                # backend socket: this is a hangup, not a box failure -- never
                # a 502, no stream-error debt, no retry invitation.
                backend.note_client_abort()
                self.close_connection = True
                LOG.info("%s %s -> %s caller hung up after %.2fs (box released unharmed)",
                         method, bare, backend.id, duration)
            elif not headers_out:
                if sent and answered and isinstance(exc, (ConnectionError, socket.timeout, TimeoutError)):
                    # The box ANSWERED -- it was the CALLER that vanished
                    # while we were writing its answer (on a reset socket
                    # end_headers/flush raises, and headers_out flips only
                    # one line later). That is a client abort: the abort
                    # path's own ghost-debt covers whatever the box may
                    # still be generating. Booking a backend stall plus a
                    # timeout debt here blames a box that answered AND hides
                    # a real unit of foreign load for the whole grace window
                    # (stress Q2/F1). No 502 is attempted -- the socket died
                    # mid-write; writing more is not a response.
                    backend.note_client_abort()
                    self.close_connection = True
                    LOG.info("%s %s -> %s caller gone while relaying answer (%s; box had answered)",
                             method, bare, backend.id, type(exc).__name__)
                elif sent and answered:
                    # The box answered; the ROUTER could not relay it (a
                    # header the stdlib refuses to write, say). Bytes may sit
                    # half-written in our header buffer, so nothing more goes
                    # on this socket -- and no timeout claim: the box is done
                    # answering (stress Q1/Q2A-7 family, relay side).
                    backend.note_stream_error("answer could not be relayed: " + type(exc).__name__)
                    self.close_connection = True
                    LOG.warning("%s %s -> %s answered but the router could not relay it (%s)",
                                method, bare, backend.id, type(exc).__name__)
                elif sent and isinstance(exc, http.client.HTTPException) and not isinstance(exc, http.client.RemoteDisconnected):
                    # The box DID answer -- with framing this router refuses
                    # to parse (LineTooLong, InvalidURL...). Nothing was
                    # relayed and nothing is still running to duplicate; the
                    # stall wording below ("may still complete") would be a
                    # lie here. RemoteDisconnected is a BadStatusLine that
                    # really NEVER answered, so it keeps the stall branch.
                    backend.note_stream_error("unparseable box response: " + type(exc).__name__)
                    self._json(502, {"error": {
                        "message": "strata-router: backend " + backend.id + " answered with a response the router "
                                   "could not parse (" + type(exc).__name__ + "). Nothing was relayed to the caller, "
                                   "and the request is not still running on the box.",
                        "type": "backend_protocol_error",
                    }})
                    self.close_connection = True
                    LOG.warning("%s %s -> %s UNPARSEABLE box response after %.2fs: %s",
                                method, bare, backend.id, duration, exc)
                elif sent:
                    # The request bytes reached the box -- it is thinking
                    # (likely parked in its FIFO) and may still finish there.
                    # A slow box is not a dead box (rule 4): record the stall,
                    # do NOT eject, and do not invite a retry that would run
                    # the same agent turn a second time.
                    backend.note_stream_error("no first byte after send: " + type(exc).__name__)
                    backend.note_timeout_release()  # our corpse is not the owner's load (L2-3/M2)
                    self._json(502, {"error": {
                        "message": "strata-router: backend " + backend.id + " accepted the request but did not start "
                                   "answering within the read timeout. It stays in rotation. The request was handed "
                                   "to that box and may still complete there -- retrying can duplicate the turn.",
                        "type": "backend_timeout",
                    }})
                    LOG.warning("%s %s -> %s no first byte after %.2fs (stays healthy, not retried)", method, bare, backend.id, duration)
                else:
                    if not connect_charged:   # the overflow pre-send rollback
                        # already booked this exact failure; twice means the
                        # box hits DOWN at half the real failures
                        backend.note_connect_failure(method + " " + bare + ": " + type(exc).__name__ + ": " + str(exc), max_fails, backoff)
                    self._json(502, {"error": {
                        "message": "strata-router: backend " + backend.id + " unreachable (" + str(exc) + "). "
                                   "It is out of rotation; if the request never reached it nothing was lost.",
                        "type": "backend_unreachable",
                    }})
                    LOG.warning("%s %s -> %s FAILED after %.2fs: %s", method, bare, backend.id, duration, exc)
            else:
                # First byte already delivered: retrying would duplicate a partial
                # agent turn, so we surface the break and never auto-retry.
                if read_break:
                    pass        # the BACKEND broke (crash / tailnet RST): already
                                # recorded above -- do not blame the client
                elif isinstance(exc, ConnectionError):
                    # a write refused (reset/aborted/pipe): client abort the
                    # hard way -- the watchdog catches the polite (EOF) way
                    backend.note_client_abort()
                else:
                    backend.note_stream_error(str(exc))
                self.close_connection = True
                LOG.warning("%s %s -> %s stream broke after %.2fs (headers already sent; not retried)", method, bare, backend.id, duration)
        finally:
            client_gone.set()   # stop the watchdog before the socket goes away
            if was_overflow and not ovf_settled:
                # ended without ever answering (read timeout, caller hangup,
                # stream break before the first status): the provisional
                # re-home dies here, counted -- no stale entry can landmine
                # this lane's next turn, and the placement counters stay a
                # closed identity (requests == SUM(terminals); pin_misses is
                # diagnostic -- a pin miss still places and ticks its own
                # terminal, README's identity clause is the correct formula)
                self.pool.overflow_fizzle(key, ovf_token)
            if reserved:
                backend.end()
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def _rewrite_model(self, body):
        rules = self.cfg.get("rewrite_model") or {}
        if not rules or not body:
            return body
        obj = _json_or_none(body)
        if isinstance(obj, dict) and isinstance(obj.get("model"), str) and obj["model"] in rules:
            obj["model"] = rules[obj["model"]]
            # ensure_ascii=True on purpose: a lone surrogate ANYWHERE in the
            # body (a valid JSON escape like "\ud800") makes the utf-8 encode
            # of an ensure_ascii=False dump raise -- and a failure after the
            # connection opens gets charged to a healthy box, x-strata-pin
            # included deciding WHICH box eats the charges (review L2-2/M3).
            return json.dumps(obj, ensure_ascii=True).encode("utf-8")
        return body


class Router(ThreadingHTTPServer):
    daemon_threads = True
    # On Windows SO_REUSEADDR lets a SECOND process bind a port that another
    # is still actively listening on -- two routers would split traffic
    # silently. SO_EXCLUSIVEADDRUSE makes a double start fail loudly instead.
    # (POSIX keeps SO_REUSEADDR for fast restarts.)
    allow_reuse_address = os.name != "nt"
    request_queue_size = 256

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        super().server_bind()

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError,
                            ConnectionAbortedError, TimeoutError)):
            # the agent hung up mid-stream; noise, not a fault. The aborted
            # variant is the Windows shape of exactly that: a killed agent's
            # SO_LINGER hard-close hits the keep-alive readline with WinError
            # 10053, and killed CLI agents are this router's client base
            # (R6-C/P3-3: without it every such death was a traceback).
            return
        super().handle_error(request, client_address)


# ---------------------------------------------------------------------------
# --probe: verify every assumption against the real boxes before you trust config
# ---------------------------------------------------------------------------

def probe(cfg):
    """Settles the per-box questions the docs disagree about: which base path the
    Anthropic Messages API lives on, and which status endpoint exposes load."""
    rc = 0
    pool = make_pool(cfg)
    validate_cfg(cfg, pool, strict=False)
    for be in pool.backends:
        print("")
        print("=== %s  http%s://%s:%s%s" % (be.id, "s" if be.https else "", be.host, be.port, be.prefix))
        for path in ("/v1/models", "/models", "/v1/status", "/metrics"):
            code, body = _probe_get(be, path)
            snippet = (body or "")[:200].replace(chr(10), " ")
            print("  GET  %-28s -> %-6s %s" % (path, code if code is not None else "ERR", snippet))
            if path == "/v1/status" and code == 200 and body:
                parsed = parse_status(body)
                print("       load parsed from /v1/status: %r" % (parsed,))
        for path in ("/v1/messages", "/anthropic/v1/messages"):
            code, body = _probe_messages(be, path)
            if code is None:
                verdict = "unreachable"
            elif code < 400:
                verdict = "OK -- Anthropic Messages answers here"
            elif code in (404, 405):
                verdict = "not served on this path"
            else:
                verdict = "rejected (path exists, request refused)"
            print("  POST %-28s -> %-6s %s" % (path, code if code is not None else "ERR", verdict))
            if code is not None and code < 400:
                rc = 0 if rc != 2 else rc
                break
        else:
            rc = 1
            print("  !! no Anthropic Messages path answered; check the box is up and the key is set")
    print("")
    print("If /v1/messages 404s but /anthropic/v1/messages works, run the router with")
    print("--path-prefix /anthropic (or per box: --backend a=http://host:8080,/anthropic).")
    return rc


def _probe_get(be, path):
    try:
        conn = open_connection(be, 3.0, 6.0)
        conn.request("GET", be.prefix + path, headers=backend_headers(be.cfg, None, be))
        r = conn.getresponse()
        body = r.read(4000).decode("utf-8", "replace")
        conn.close()
        return r.status, body
    except Exception as exc:
        return None, str(exc)


def _probe_messages(be, path):
    model = be.cfg.get("probe_model") or "probe"
    body = json.dumps({"model": model, "max_tokens": 1, "stream": True,
                       "messages": [{"role": "user", "content": "ping"}]}).encode()
    try:
        conn = open_connection(be, 3.0, 60.0)
        hdrs = backend_headers(be.cfg, None, be)
        hdrs["content-length"] = str(len(body))
        hdrs["content-type"] = "application/json"
        conn.request("POST", be.prefix + path, body=body, headers=hdrs)
        # The HEADERS are the verdict: a healthy-but-BUSY box parks this stream
        # in its own FIFO with the 200 and SSE headers already out, beating
        # keep-alive comments while its slot is taken. The old non-streaming
        # fill-read waited out the whole wait (up to 60 s) on a busy box and
        # printed "unreachable" -- a healthy box declared dead (review L1-3/S2).
        # The probe's ping is a queued request like any other: closing here
        # makes the box cancel it at its next beat (<= ~10 s), seat freed.
        r = conn.getresponse()
        status = r.status
        conn.close()
        return status, ""
    except Exception as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

DEFAULTS = {
    "listen": "127.0.0.1",
    "port": 8088,
    "backends": [],
    "path_prefix": "",
    "sticky_ttl": 21600,          # 6h: a Codex session should never drift boxes
    "sticky_max": 20000,
    "connect_timeout": 5.0,
    "read_timeout": 3600.0,       # 0 = never time out a request parked in a queue
    "max_connect_failures": 3,
    "down_backoff": 20.0,
    "status_interval": 1.0,
    "status_timeout": 3.0,
    "status_paths": ["/v1/status", "/metrics"],
    "max_body_mb": 512,
    "backend_api_key": "",
    "keys_file": "",
    "control_token": "",            # optional gate for x-strata-pin and
                                    # sticky/clear (keys-file "control" entry
                                    # preferred -- keeps it out of the config)
    "tls_insecure": False,          # https backends only: skip cert verification
                                    # (named in DEFAULTS so an unknown-key
                                    # warning can never lie about being ignored)
    "expose_affinity": True,
    "rewrite_model": {},
    "log_level": "INFO",
}


def parse_backend_specs(specs, default_prefix):
    """id=URL  or  id=URL,/anthropic  (JSON objects accepted too)."""
    out = []
    for spec in specs:
        if spec.lstrip().startswith("{"):
            out.append(json.loads(spec))
            continue
        bid, sep, rest = spec.partition("=")
        if not sep:
            raise SystemExit("--backend needs id=URL[,/path-prefix] (got " + repr(spec) + ")")
        url, sep2, prefix = rest.partition(",")
        out.append({
            "id": bid.strip(),
            "url": url.strip(),
            "path_prefix": (prefix.strip() or default_prefix or ""),
        })
    return out


def build_cfg(argv):
    ap = argparse.ArgumentParser(
        description="Affinity + least-queued passthrough router for identical local inference boxes.",
    )
    ap.add_argument("--config", help="JSON file; any key from DEFAULTS")
    ap.add_argument("--backend", action="append", default=[], help="id=URL[,/path-prefix], repeat per box")
    ap.add_argument("--path-prefix", help="prefix for every box, e.g. /anthropic")
    ap.add_argument("--listen")
    ap.add_argument("--port", type=int)
    ap.add_argument("--keys-file", help="JSON file of backend id -> key; default: router.keys.json next to --config")
    ap.add_argument("--set-key", metavar="BACKEND_ID",
                    help="store one backend key at a hidden prompt into the keys file, then exit ('global' = the fallback key)")
    ap.add_argument("--sticky-ttl", type=float)
    ap.add_argument("--connect-timeout", type=float)
    ap.add_argument("--read-timeout", type=float, help="0 = never time out a queued request")
    ap.add_argument("--max-connect-failures", type=int)
    ap.add_argument("--down-backoff", type=float)
    ap.add_argument("--status-interval", type=float)
    ap.add_argument("--max-body-mb", type=int)
    ap.add_argument("--rewrite-model", action="append", default=[], help="FROM=TO, repeatable")
    ap.add_argument("--no-expose-affinity", action="store_true")
    ap.add_argument("--log-level")
    ap.add_argument("--probe", action="store_true", help="inspect the boxes and exit")
    ap.add_argument("--version", action="store_true")
    a = ap.parse_args(argv)
    if a.version:
        print(VERSION)          # before any key/config parsing: a broken keys
        raise SystemExit(0)     # file must not hide the version
    cfg = dict(DEFAULTS)
    if a.config:
        with open(a.config, "r", encoding="utf-8") as fh:
            cfg.update(json.load(fh))
    if a.backend:
        cfg["backends"] = parse_backend_specs(a.backend, a.path_prefix or cfg.get("path_prefix") or "")
    elif a.path_prefix:
        cfg["path_prefix"] = a.path_prefix
    for name in ("listen", "port", "sticky_ttl", "connect_timeout",
                 "read_timeout", "max_connect_failures", "down_backoff",
                 "status_interval", "max_body_mb", "log_level"):
        val = getattr(a, name, None)
        if val is not None:
            cfg[name] = val
    if a.no_expose_affinity:
        cfg["expose_affinity"] = False
    if a.keys_file:
        cfg["keys_file"] = a.keys_file
    if a.config:
        cfg["_config_path"] = a.config
    apply_keys(cfg, a.config, creating=bool(a.set_key))
    if a.set_key:
        cfg["_set_key"] = a.set_key
    if a.rewrite_model:
        rules = dict(cfg.get("rewrite_model") or {})
        for item in a.rewrite_model:
            f, sep, t = item.partition("=")
            if sep:
                rules[f] = t
        cfg["rewrite_model"] = rules
    return cfg


# ---- keys at rest: DPAPI ciphertext (v1.2.14) -------------------------------
# On Windows the keys file stores ONE DPAPI blob (user scope + fixed entropy),
# so an accidental grep, agent scan or file copy sees base64 noise, not key
# material. The blob opens only for the same Windows user on the same machine:
# keys were never meant to travel -- now they cannot travel by accident either.
# Other platforms keep the plaintext JSON (0600); --set-key stays available.
_DPAPI_TAG = "dpapi_v1"
_DPAPI_ENTROPY = b"strata-router-keys-v1"


def _dpapi_enabled():
    return os.name == "nt"


def _dpapi_crypt(data, encrypt):
    import ctypes
    import ctypes.wintypes

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    sig = [ctypes.POINTER(_BLOB), ctypes.c_wchar_p, ctypes.POINTER(_BLOB),
           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(_BLOB)]
    crypt32.CryptProtectData.argtypes = sig
    crypt32.CryptUnprotectData.argtypes = sig
    crypt32.CryptProtectData.restype = ctypes.c_bool
    crypt32.CryptUnprotectData.restype = ctypes.c_bool

    def blob(b):
        buf = ctypes.create_string_buffer(b, len(b))
        return _BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    src, _keep1 = blob(data)            # keep the buffers alive across the call
    ent, _keep2 = blob(_DPAPI_ENTROPY)
    out = _BLOB()
    fn = crypt32.CryptProtectData if encrypt else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0x01, ctypes.byref(out))
    if not ok:
        raise OSError("DPAPI %s failed (%d)" % ("protect" if encrypt else "unprotect",
                                                ctypes.GetLastError()))
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def _wrap_keys(obj):
    """Plain dict -> the on-disk form (DPAPI envelope on Windows, JSON elsewhere)."""
    if not _dpapi_enabled():
        return obj
    blob = _dpapi_crypt(json.dumps(obj, sort_keys=True).encode("utf-8"), True)
    return {_DPAPI_TAG: base64.b64encode(blob).decode("ascii")}


def _unwrap_keys(data, path):
    """On-disk form -> (plain dict, was_encrypted). Envelope detection is by
    SHAPE: exactly one key, and it is the tag. A blob that will not open is
    fatal (fail-closed like every other half-config), and says WHY: blobs are
    bound to one Windows user on one machine, so an unopenable blob almost
    always means this file was copied from somewhere else."""
    if not (isinstance(data, dict) and list(data) == [_DPAPI_TAG]
            and isinstance(data[_DPAPI_TAG], str)):
        return data, False
    if not _dpapi_enabled():
        raise SystemExit("keys file %s: DPAPI envelope but this platform has no DPAPI" % path)
    try:
        out = json.loads(_dpapi_crypt(base64.b64decode(data[_DPAPI_TAG], validate=True), False)
                         .decode("utf-8"))
    except SystemExit:
        raise
    except Exception:
        raise SystemExit("keys file %s: the DPAPI blob does not open -- it was created by another "
                         "Windows user or on another machine (blobs never travel). "
                         "Retype the keys with --set-key." % path)
    if not isinstance(out, dict):
        raise SystemExit("keys file %s: ciphertext opened to a non-object -- refusing" % path)
    return out, True


def _keys_lock(path, timeout=15.0):
    """Exclusive cross-process lock around the keys-file read-modify-write
    (review R4-B/F3): two concurrent --set-key runs used to lose one another's
    entry -- a box's key silently gone until its next 401. Lock a sibling
    <keys>.json.lock so the payload file itself is never the lock."""
    fh = open(path + ".lock", "a+b")
    deadline = time.monotonic() + timeout
    while True:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except OSError:
            if time.monotonic() >= deadline:
                fh.close()
                raise TimeoutError("another keys writer still holds %s.lock" % path)
            time.sleep(0.1)


def _keys_unlock(fh):
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
    except OSError:
        pass
    try:
        fh.close()   # closing releases the flock on POSIX
    except OSError:
        pass


def _write_keys_file(path, keys):
    """Atomic, ACL-hardened write of the keys file, encrypted where the platform
    allows. Shared by --set-key and the boot-time plaintext migration.
    Atomic rewrite (L2-3/L3): O_TRUNC on the real path meant a crash or a
    ctrl-C mid-write left half a file, and every later boot refused to start
    (fail-closed, but an outage until an operator blind-fixes it). Write a
    sibling temp, lock its ACL, then os.replace() in one atomic rename."""
    payload = _wrap_keys(keys)          # before touching the filesystem: a failed
    #                                    # encryption must leave the file untouched
    tmp = path + ".new.%d" % os.getpid()   # unique: two --set-key runs must not
    #                                       # write the same temp (review R1-B/F11)
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        if os.name != "nt":
            try:
                os.chmod(tmp, 0o600)   # O_CREAT mode is ignored on an existing file
            except OSError:
                pass
        note = ""
        if os.name == "nt":
            try:
                me = os.environ.get("USERNAME") or os.getlogin()
                subprocess.run(["icacls", tmp, "/inheritance:r", "/grant:r", "%s:F" % me],
                               capture_output=True, timeout=15, check=True)
                note = "; NTFS inheritance stripped (only %s can read it)" % me
                note += "; DPAPI ciphertext (opens only for this user on this machine)"
            except Exception as exc:
                note = ('; WARNING icacls failed (%s) -- run it yourself on %s: icacls "%s" '
                        '/inheritance:r /grant:r "%%USERNAME%%:F"' % (exc, path, path))
        # replace AFTER icacls: no inherited-ACL window on the real path.
        # Bounded retry for the Windows sharing race (R6-D/P2): a concurrent
        # --set-key process holds the REAL path open -- apply_keys' boot read
        # and set_key's pre-prompt read open it WITHOUT FILE_SHARE_DELETE --
        # and os.replace needs DELETE access on the target, so it fails with
        # WinError 5/32 while any such reader sits in its ms-scale window
        # (>=3 concurrent writers used to lose the FIRST one's value, silently
        # keeping the old key). We hold the writer lock, so nobody else can
        # WRITE meanwhile -- there is only nothing to do but wait out readers.
        for _attempt in range(100):
            try:
                os.replace(tmp, path)
                break
            except OSError as exc:
                if (os.name != "nt" or getattr(exc, "winerror", None) not in (5, 32)
                        or _attempt == 99):
                    raise
                time.sleep(0.1)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)         # never leave a stale .new behind
        except OSError:
            pass
    return note


def _read_keys_file2(path):
    """JSON object of backend id -> key ("global" for the fallback key), plus
    whether the file was DPAPI ciphertext. A present-but-broken file is fatal:
    silently dropping keys turns an authenticated deployment into an anonymous
    one."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}, False
    except Exception as exc:
        raise SystemExit("keys file %s: unreadable (%s) -- fix or delete it; refusing to guess keys"
                         % (path, exc.__class__.__name__))
    if not isinstance(data, dict):
        raise SystemExit("keys file %s: must be a JSON object of backend id -> key" % path)
    data, was_enc = _unwrap_keys(data, path)
    out = {}
    for k, v in data.items():
        if not isinstance(v, str):
            # str(None) == "None" would become a USABLE key -- and a "control":
            # null would arm a gate whose secret is the word "None" while boot
            # logs say GATED (L2-3/L2). Refuse, like every other half-config.
            raise SystemExit("keys file %s: entry %r is %s, not a string -- fix or delete it"
                             % (path, str(k), type(v).__name__))
        out[str(k)] = v  # stored RAW: --set-key re-serialises this dict and must
        #                # not silently strip siblings (L2-3/L4); users strip at use
    return out, was_enc


def _read_keys_file(path):
    keys, _enc = _read_keys_file2(path)
    return keys


def _usable_key(value):
    v = str(value or "").strip()
    return v if v and not v.startswith("REPLACE-WITH") else ""


def _keys_path_for(cfg, config_path, must_exist=True):
    path = str(cfg.get("keys_file") or "").strip()
    if path:
        # an explicit keys_file means the operator: a relative path anchors
        # next to the config (same as the default), and it MUST exist -- a
        # typo'd name must abort, never silently boot a keyed box keyless.
        # (--set-key passes must_exist=False: it creates the file.)
        if config_path and not os.path.isabs(path):
            path = os.path.join(os.path.dirname(os.path.abspath(config_path)), path)
        if must_exist and not os.path.exists(path):
            raise SystemExit("keys_file %r does not exist -- fix the path or drop the field "
                             "(refusing to boot keyless where keys were configured)" % path)
        return path
    base = os.path.dirname(os.path.abspath(config_path)) if config_path else os.getcwd()
    cand = os.path.join(base, "router.keys.json")
    return cand if os.path.exists(cand) else ""


def apply_keys(cfg, config_path, creating=False):
    """Fill backend keys from the safe input ports, in memory only -- the
    config file is never rewritten. Order: inline field (unless a leftover
    placeholder) > keys file [<id>] > backend_api_key_env > keys file
    [global] > global field > STRATA_BACKEND_API_KEY (resolved at Backend).
    creating=True (--set-key) tolerates a not-yet-existing explicit keys
    file: that command is the one that makes it."""
    path = _keys_path_for(cfg, config_path, must_exist=not creating)
    keys, was_enc = _read_keys_file2(path) if path else ({}, True)
    if path:
        cfg["_keys_path"] = path
        # hygiene sweep (review R4-B/F4): a hard crash between temp-write and
        # replace leaves <keys>.json.new.<pid> behind forever -- ours to
        # delete, and on the non-Windows plaintext fallback path those stale
        # temps are the worst of it
        try:
            d, stem = os.path.split(path)
            for name in os.listdir(d or "."):
                if name.startswith(stem + ".new."):
                    try:
                        os.unlink(os.path.join(d or ".", name))
                    except OSError:
                        pass
        except OSError:
            pass
        for k, v in keys.items():
            if v.startswith("REPLACE-WITH"):
                raise SystemExit("keys file %s: entry %r still holds a placeholder" % (path, k))
            try:
                vb = v.encode("latin-1")
            except UnicodeEncodeError:
                raise SystemExit("keys file %s: entry %r cannot be encoded as an HTTP header" % (path, k))
            if _ILLEGAL_HV.search(vb):
                # CR/LF/NUL inside a key makes http.client raise mid-request,
                # and its ValueError message carries the FULL header value --
                # straight into the 502 body, the log and stats. Refuse boot.
                raise SystemExit("keys file %s: entry %r contains control bytes (a key must be one printable line; retype it with --set-key)" % (path, k))
        known = {str(s.get("id")) for s in cfg.get("backends") or [] if isinstance(s, dict)} | {"global", "control"}
        for k in keys:
            if k not in known:
                LOG.warning("keys file %s: entry %r matches no backend id (typo?)", path, k)
        if not was_enc and _dpapi_enabled():
            # v1.2.14 one-way migration, AFTER validation: same entries, rewritten
            # as DPAPI ciphertext -- but UNDER the writer lock and re-read
            # (review R4-B/F3 kin): a --set-key that landed while boot was still
            # validating must not be wiped by this migration's stale snapshot.
            # Newer on-disk values win; boot-validated entries absent from disk
            # are kept. Failures only warn -- boot continues on the
            # validated plaintext (monitoring must never be the reason a serving
            # change breaks; the operator sees the warning and can --set-key).
            try:
                _mlk = _keys_lock(path, timeout=5.0)
                try:
                    _disk, _ = _read_keys_file2(path)
                    _write_keys_file(path, {**keys, **_disk})
                finally:
                    _keys_unlock(_mlk)
                LOG.info("keys file %s: migrated to DPAPI ciphertext (same entries; opens only for "
                         "this Windows user on this machine)", path)
            except (Exception, SystemExit) as exc:
                LOG.warning("keys file %s: still plaintext -- migration failed (%s); rerun --set-key "
                            "to store it encrypted", path, exc.__class__.__name__)
    # optional control-surface gate: inline field first, then the keys-file
    # "control" entry (a secret belongs in the 0600 file, not the config)
    tok = str(cfg.get("control_token") or "").strip()
    if not tok:
        tok = str(keys.get("control") or "").strip()
    cfg["_control_token"] = tok
    sources = {}
    for spec in cfg.get("backends") or []:
        if not isinstance(spec, dict):
            continue
        bid = str(spec.get("id") or "?")
        if _usable_key(spec.get("backend_api_key")):
            sources[bid] = "inline"
            continue
        k = keys.get(bid)
        if _usable_key(k):
            src = "keys-file"
        else:
            src = ""
        if not k:
            var = str(spec.get("backend_api_key_env") or "").strip()
            if var:
                k = (os.environ.get(var) or "").strip()
                if not k:
                    raise SystemExit("backend %s: backend_api_key_env names %s, which is not set "
                                     "(export it in a private shell, or remove the field)" % (bid, var))
                src = "env"
        if not k:
            k = keys.get("global")
            if _usable_key(k):
                src = "keys-file global"
        if _usable_key(k):
            spec["backend_api_key"] = k.strip()
            sources[bid] = src
        else:
            sources[bid] = ""
    if not _usable_key(cfg.get("backend_api_key")) and _usable_key(keys.get("global")):
        cfg["backend_api_key"] = keys["global"].strip()
    cfg["_key_sources"] = sources


def set_key(cfg, backend_id, config_path, keys_path):
    """The standard key input port: read a key at a hidden prompt and store it
    in the keys file. It is never echoed, never taken from argv (shell history)
    and never logged -- only its length is ever reported."""
    path = keys_path or _keys_path_for(cfg, config_path, must_exist=False)
    if not path:
        base = os.path.dirname(os.path.abspath(config_path)) if config_path else os.getcwd()
        path = os.path.join(base, "router.keys.json")
    ids = {str(s.get("id")) for s in cfg.get("backends") or [] if isinstance(s, dict)}
    if ids and backend_id not in ids | {"global", "control"}:
        print("unknown backend %r -- configured: %s (or 'global'/'control')" % (backend_id, ", ".join(sorted(ids))))
        return 2
    keys = _read_keys_file(path)
    while True:
        k1 = getpass.getpass("key for %s (input hidden): " % backend_id)
        k2 = getpass.getpass("repeat it: ")
        if k1.strip() and k1 == k2:
            break
        print("mismatch or empty -- try again")
    key = k1.strip()
    if key.startswith("REPLACE-WITH"):
        print("that is the example placeholder, not a real key -- nothing stored")
        return 2
    try:
        kb = key.encode("latin-1")
    except UnicodeEncodeError:
        print("the key contains characters that cannot travel as an HTTP header -- nothing stored")
        return 2
    if _ILLEGAL_HV.search(kb):
        print("the key contains control bytes -- nothing stored")
        return 2
    try:
        lk = _keys_lock(path)
    except Exception as exc:
        print("cannot lock the keys file (%s) -- nothing written" % exc)
        return 2
    try:
        # re-read and merge UNDER the lock (review R4-B/F3): a concurrent
        # --set-key for another backend is additive now -- its fresh entry is
        # merged in instead of being overwritten by this process's stale
        # pre-prompt snapshot (that early read stays: fail on a broken keys
        # file BEFORE asking anyone to type a secret)
        fresh = _read_keys_file(path)
        fresh[backend_id] = key
        note = _write_keys_file(path, fresh)
    except Exception as exc:
        print("cannot store the key (%s) -- nothing written" % exc)
        return 2
    finally:
        _keys_unlock(lk)
    print("stored key for %r (%d chars) in %s%s -- keep this file out of git, chat and cloud drives"
          % (backend_id, len(key), path, note))
    return 0


def make_pool(cfg):
    specs = cfg.get("backends") or []
    if not specs:
        raise SystemExit(
            "no backends configured. Example: python router.py "
            "--backend a=http://127.0.0.1:8080 --backend b=http://192.168.1.24:8080"
        )
    backends = []
    for i, spec in enumerate(specs):
        if isinstance(spec, str):
            spec = {"id": "box" + str(i + 1), "url": spec}
        extra = {k: v for k, v in spec.items() if k not in ("id", "url", "path_prefix")}
        backends.append(Backend(
            spec.get("id") or ("box" + str(i + 1)),
            spec["url"],
            spec.get("path_prefix") or cfg.get("path_prefix") or "",
            cfg=dict(cfg, **extra),
        ))
    return Pool(backends, cfg)


# the knobs that must be numbers: a value that coerces to None, or crashes
# mid-request after a slot was reserved, silently changes security behaviour
_NUM_CFG = {
    "port": int, "sticky_ttl": float, "sticky_max": int,
    "connect_timeout": float, "read_timeout": float,
    "max_connect_failures": int, "down_backoff": float,
    "status_interval": float, "status_timeout": float, "max_body_mb": int,
}
_KNOWN_BE_KEYS = {"id", "url", "path_prefix", "priority", "max_inflight",
                  "require_idle", "backend_api_key", "backend_api_key_env", "probe_model",
                  # these are READ from the per-backend merge -- listing them
                  # keeps the "IGNORED" warning honest about what actually applies
                  "tls_insecure", "status_interval", "status_timeout"}


def validate_cfg(cfg, pool, strict=True):
    """Check every knob that tiering, key injection or the health machine
    depends on, BEFORE serving a single request. A typo'd security knob must
    be indistinguishable from a crash, never from a working default.
    Returns the list of problems; main() treats them as fatal for serving."""
    problems = []
    for k, cast in _NUM_CFG.items():
        v = cfg.get(k)
        if v is None:
            continue
        if isinstance(v, bool):
            problems.append((k, "must be a number, got a boolean"))
            continue
        try:
            cast(v)
        except (TypeError, ValueError):
            problems.append((k, "must be a number, got %r" % (v,)))
    sm = cfg.get("sticky_max")
    if sm is not None and not isinstance(sm, bool):
        # range gate on top of _NUM_CFG's type gate: 0 was silently rewritten
        # to the 20000 default (falsy trap) and a negative cap emptied the
        # affinity table on every write -- neither is a mode we ship
        # (review R4-A/F7)
        try:
            if float(sm) < 1:
                problems.append(("sticky_max", "must be >= 1 (there is no 'affinity off' cap)"))
        except (TypeError, ValueError):
            pass
    for b in pool.backends:
        raw = b.cfg.get("priority")
        if raw is not None and (isinstance(raw, bool) or not isinstance(raw, int)):
            problems.append((b.id + ".priority", "must be a JSON integer, got %r" % (raw,)))
        raw = b.cfg.get("max_inflight")
        if raw is not None and (isinstance(raw, bool) or not isinstance(raw, int)):
            problems.append((b.id + ".max_inflight", "must be a JSON integer, got %r" % (raw,)))
        raw = b.cfg.get("require_idle")
        if raw is not None and not isinstance(raw, bool):
            problems.append((b.id + ".require_idle",
                             "must be true/false (a JSON boolean), got %r -- the string \"false\" is truthy" % (raw,)))
        for nk in ("status_interval", "status_timeout"):
            # these ARE read per-backend (staleness window, poll timeout) --
            # a string here would crash inside try_place/stats after boot
            raw = b.cfg.get(nk)
            if raw is not None and (isinstance(raw, bool) or not isinstance(raw, (int, float))):
                problems.append((b.id + "." + nk, "must be a number, got %r" % (raw,)))
        raw = b.cfg.get("backend_api_key")
        if raw is not None and not isinstance(raw, str):
            # str() would boot `true`/123 as the WORKING key "True"/"123":
            # the keys file refused this shape since v1.2.11 -- the inline
            # config door gets the same doctrine (stress P1/F8).
            problems.append((b.id + ".backend_api_key",
                             "must be a JSON string, got %r -- a non-string never boots, not even as a cast" % (raw,)))
        try:
            kb = b.api_key.encode("latin-1")
        except UnicodeEncodeError:
            problems.append((b.id + ".backend_api_key", "contains non-latin-1 characters and cannot be sent as a header"))
        else:
            if _ILLEGAL_HV.search(kb):
                # never let a control-byte key live: http.client would raise
                # mid-request with the full header value (the key) in the
                # message -- into the 502 body, the log, and stats
                problems.append((b.id + ".backend_api_key", "contains control bytes -- it would leak into error messages when sent; retype with --set-key"))
        if b.api_key.startswith("REPLACE-WITH"):
            problems.append((b.id + ".backend_api_key",
                             "placeholder still in place -- type the real key with --set-key "
                             + b.id + " (deleting the field falls back to the SHARED global key, "
                             "which is wrong for a borrowed box)"))
    if str(cfg.get("backend_api_key") or "").startswith("REPLACE-WITH"):
        problems.append(("backend_api_key", "placeholder still in place (--set-key global fills it without touching this file)"))
    if str(cfg.get("control_token") or "").startswith("REPLACE-WITH"):
        problems.append(("control_token", "placeholder still in place -- set a real token or delete the field"))
    _ctok = str(cfg.get("_control_token") or cfg.get("control_token") or "")
    if _ctok and not _ctok.isascii():
        # headers arrive decoded latin-1: a non-ASCII token is a silent trap
        # whose gate can NEVER open, not even for its owner (L2-3/L1)
        problems.append(("control_token", "contains non-ASCII characters -- no header could ever match it; use ASCII only"))
    elif _ctok and re.search(r"[\x00-\x1f\x7f]", _ctok):
        # same trap shape, ASCII edition: control bytes cannot travel in a
        # header line at all (the parser ends the line at them), so the gate
        # locks out its own owner too (stress Q1/Q2A-2)
        problems.append(("control_token", "contains control bytes -- no header could ever carry them; the gate would be locked forever"))
    for _name in ("backend_api_key", "control_token"):
        _raw = cfg.get(_name)
        if _raw is not None and not isinstance(_raw, str):
            # same inline-door doctrine as the per-backend key above (P1/F8)
            problems.append((_name, "must be a JSON string, got %r -- a non-string never boots, not even as a cast" % (_raw,)))
    _rules = cfg.get("rewrite_model") or {}
    if _rules and not isinstance(_rules, dict):
        problems.append(("rewrite_model", "must be an object of \"old model\": \"new model\" rules, got %r" % (_rules,)))
    elif any(not isinstance(k, str) or not isinstance(v, str) for k, v in (_rules or {}).items()):
        # a non-string replacement value would be re-dumped straight into the
        # body (dict -> {"model": {...}}), rewriting the request with junk
        # that no rewrite screen would pass (stress P1/F8)
        problems.append(("rewrite_model", "every rule must map string -> string; a non-string key or value never boots"))
    # a gate-relevant box whose key came from a shared fallback is the B2
    # trap: boot looked clean, every borrowed turn silently 401s, and the
    # fail-closed courtesy never engages
    srcs = cfg.get("_key_sources") or {}
    for b in pool.backends:
        if not (b.require_idle or b.priority > 0):
            continue
        src = srcs.get(b.id, "")
        if b.api_key and not b.api_key.startswith("REPLACE-WITH") and src not in ("inline", "keys-file", "env"):
            # a placeholder key was already flagged BY NAME above -- warning
            # here too cried "wrong shared key" on a pristine config that
            # holds no key at all (review L1-3/L2)
            LOG.warning("%s: key resolved from the %s fallback -- a borrowed box normally holds a DISTINCT "
                        "borrower key; verify its status polls answer before trusting its idle verdict",
                        b.id, src or "global/env")
        if not b.api_key:
            LOG.warning("%s: gate-relevant box with NO key -- if it requires auth, every poll 401s and its "
                        "require_idle gate stays closed forever (courtesy fails closed, traffic queues local)", b.id)
    for spec in cfg.get("backends") or []:
        if isinstance(spec, dict):
            for k in spec:
                if k not in _KNOWN_BE_KEYS:
                    LOG.warning("backend %s: unknown key %r is IGNORED (typo'd security knobs fail silently)",
                                spec.get("id", "?"), k)
    for k in cfg:
        if k not in DEFAULTS and not k.startswith("_"):
            LOG.warning("config: unknown top-level key %r is IGNORED", k)
    if ":" in str(cfg.get("listen") or ""):
        problems.append(("listen", "must be an IPv4 address or hostname (this stdlib server is AF_INET "
                                   "only, IPv6 cannot bind); use 127.0.0.1"))
    sp = cfg.get("status_paths")
    if sp is not None and (not isinstance(sp, (list, tuple)) or not sp
                           or not all(isinstance(x, str) and x.startswith("/") for x in sp)):
        problems.append(("status_paths", "must be a non-empty list of paths starting with '/', got %r "
                                         "-- a bare string would poll one CHARACTER at a time" % (sp,)))
    if str(cfg.get("listen") or "127.0.0.1") not in ("127.0.0.1", "localhost", "::1"):
        LOG.warning(
            "listen=%s is NOT loopback: this router has no auth of its own and injects "
            "backend keys for callers that send none. Firewall this port to known peers now. "
            "The rebinding guard admits ONLY Host: %s (loopback names prove nothing off-loopback) "
            "-- and gate the control surface: --set-key control.",
            cfg.get("listen"), cfg.get("listen"),
        )
    if problems and strict:
        for k, why in problems:
            LOG.error("config: %s: %s", k, why)
        raise SystemExit("config: %d problem(s) above -- refusing to serve" % len(problems))
    for k, why in problems:
        LOG.warning("config: %s: %s", k, why)      # probe mode: warn, still inspect
    return problems


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cfg = build_cfg(argv)
    config_path = cfg.pop("_config_path", None)
    keys_path = cfg.pop("_keys_path", None)
    set_target = cfg.pop("_set_key", None)
    logging.basicConfig(
        level=getattr(logging, str(cfg.get("log_level", "INFO")).upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    if set_target:
        return set_key(cfg, set_target, config_path, keys_path)
    if "--probe" in argv:
        return probe(cfg)

    pool = make_pool(cfg)
    validate_cfg(cfg, pool, strict=True)
    Handler.pool = pool
    Handler.cfg = cfg
    for b in pool.backends:
        src = (cfg.get("_key_sources") or {}).get(b.id) or ("global fallback" if b.api_key else "none")
        LOG.info("backend %s -> %s:%s%s  key=%s%s", b.id, b.host, b.port, b.prefix or "",
                 "yes" if b.api_key else "none", " (" + src + ")" if b.api_key else "")
    LOG.info(
        "listening on http://%s:%s -- affinity+least-queued passthrough, no rate limiting, "
        "queue stays in the backends", cfg["listen"], cfg["port"],
    )
    LOG.info("client read timeout: %s", cfg.get("read_timeout") or "disabled")
    LOG.info("control surface: %s",
             "GATED -- x-strata-pin and sticky/clear require x-strata-control"
             if cfg.get("_control_token") else
             "open to local callers (any local process: pin lanes, clear affinity). "
             "Gate it with: python router.py --set-key control")

    StatusPoller(pool, cfg).start()
    httpd = Router((str(cfg["listen"]), int(cfg["port"])), Handler)

    def shutdown(signum, _frame):
        LOG.info("signal %s: shutting down", signum)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None), getattr(signal, "SIGBREAK", None)):
        if sig:
            try:
                signal.signal(sig, shutdown)
            except Exception:
                pass
    httpd.serve_forever(poll_interval=0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
