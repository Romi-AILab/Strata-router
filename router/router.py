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
    python router.py --backend a=http://127.0.0.1:8080 --backend b=http://192.0.2.24:8080
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
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

VERSION = "1.2.18"
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

# (DV-R10 R10-P3: POST_PATHS -- "Paths accepted for generation" -- died here:
# zero loads since v4.1, do_POST proxies ANY path; a constant whose comment
# lies is a future bug's invitation. GET_PATHS stays: its /health member is
# genuinely loaded.)
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

        # smart-placement scaffold (design v4.1): every consumer flag defaults
        # OFF, and this state is written ONLY by note_completion /
        # _smart_tick_locked -- both flag-gated -- and read by the OBS panel.
        # cap_slots stays None until L1 (smart_cap_read) reads the whitelist key.
        self.cap_slots = None
        self.sm = {"streams_s": 0, "dur_sum_s": 0.0, "win_streams": 0, "win_dur": 0.0,
                   "t_bar_window": None, "t_bar_base": None, "t_bar_used": None,
                   "t_bar_hist": [], "degraded": True, "feed_blind": True,
                   "cong_streak": 0, "L_hat": None, "tick_n": 0}

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
                # OBS panel (design v4.1 S11): additive, ALWAYS present, null
                # while the scaffold sleeps -- a monitor's parser must never
                # see a field appear only after some flag flips
                "cap_slots": self.cap_slots,
                "t_bar_window_s": self.sm["t_bar_window"],
                "t_bar_base_s": self.sm["t_bar_base"],
                "t_bar_used_s": self.sm["t_bar_used"],
                "t_bar_degraded": self.sm["degraded"],
                "feed_blind": self.sm["feed_blind"],
                "cong_streak": self.sm["cong_streak"],
                # F13 proxy: real failure_pressure needs the estimator's own
                # ledger (L2+); this reads what IS on record -- state plus the
                # hard-error share of the box's own requests
                "failure_pressure": self._failure_pressure_locked(),
                "estimator_mode": ("J" if (self.cfg.get("smart") or {}).get("smart_place")
                                   else "shadow" if (self.cfg.get("smart") or {}).get("smart_shadow")
                                   else "today"),
                "inflation": (round(self.sm["t_bar_window"] / self.sm["t_bar_used"], 3)
                              if self.sm["t_bar_window"] and self.sm["t_bar_used"] else None),
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

    def _failure_pressure_locked(self):
        """F13 OBS proxy (caller holds self.lock): how much of this box's own
        record says "hurt" -- its state away from HEALTHY plus the connect +
        stream error share of its own requests."""
        st = self.stats
        return round((0.0 if self.state == HEALTHY else 1.0)
                     + (st["connect_errors"] + st["stream_errors"]) / max(1, st["requests"]), 3)

    def _smart_tick_locked(self, sm, now):
        """Poll-tick bookkeeping for the smart scaffold (CALLER HOLDS self.lock;
        design S-2: zero resident threads -- every number moves only when a
        status poll lands, and the poller calls this EVERY cycle, fresh sample
        or not, so staleness itself gets a verdict). Returns the OBS line when
        smart_obs is due on this tick (cadence knob obs_every_polls, default
        10); the POLLER logs it -- never log under a lock."""
        self.sm["tick_n"] += 1
        stale = (not self.ever_reported) or (now - self.status_ts) > self._stale_after()
        self.sm["feed_blind"] = stale
        # window T-bar (S2/V3-09-1): a window is N poll ticks (window_n,
        # default 10) and the difference fires on its boundary -- between
        # boundaries the window value HOLDS (a half-window mean would flap).
        # n_min counts FILTERED completions, not raw requests (V3-09-2).
        if self.sm["tick_n"] % max(1, int(sm.get("window_n") or 10)) == 0:
            ds = self.sm["streams_s"] - self.sm["win_streams"]
            dd = self.sm["dur_sum_s"] - self.sm["win_dur"]
            self.sm["win_streams"] = self.sm["streams_s"]
            self.sm["win_dur"] = self.sm["dur_sum_s"]
            hist = self.sm["t_bar_hist"]
            if ds >= max(1, int(sm.get("n_min") or 20)):
                mean = dd / ds
                self.sm["t_bar_window"] = mean
                self.sm["degraded"] = False
                hist.append((now, mean))
            else:
                self.sm["t_bar_window"] = None
                self.sm["degraded"] = True
            keep = float(sm.get("t_bar_base_window_s") or 86400.0)
            while hist and (now - hist[0][0] > keep or len(hist) > 4096):
                hist.pop(0)
            # T̄_base: rolling min of recorded window values (24h). O11 stays
            # true and documented: a quiet-hours service component can pull
            # this BELOW daytime service time -- the clamp bites the placement
            # side; the shipping gate only weighs the move side (D5).
            self.sm["t_bar_base"] = min(v for _t, v in hist) if hist else None
            w, base = self.sm["t_bar_window"], self.sm["t_bar_base"]
            if w is None:
                # DEFAULT-T-bar (F4): named, clamp-EXEMPT (E6-3) -- the honest
                # number for "too few filtered samples to have an opinion"
                self.sm["t_bar_used"] = float(sm.get("default_t_bar") or 120.0)
            elif base is None:
                self.sm["t_bar_used"] = w     # cold start: clamp waived one cycle (E6-3)
            else:
                self.sm["t_bar_used"] = min(w, float(sm.get("t_bar_clamp_factor") or 3.0) * base)
        # F2: OBS reads w/base on EVERY due tick, boundary tick or not --
        # binding them only inside the boundary branch killed the poller with
        # UnboundLocalError the first time obs_every_polls misaligned with
        # window_n. They live in state between boundaries; read from state.
        w, base = self.sm["t_bar_window"], self.sm["t_bar_base"]
        # cong_streak: own-signal congestion L̂ >= k_b, FRESH polls only --
        # a stale feed FREEZES the streak (V3-09-3: a stale-reset streak would
        # make the move trigger "never fires" behind a blind feed)
        if not stale:
            k_b = _k_b_of(self)
            l_hat = _l_hat_of(self, now)
            if k_b is not None and l_hat is not None:
                self.sm["L_hat"] = l_hat
                self.sm["cong_streak"] = self.sm["cong_streak"] + 1 if l_hat >= k_b else 0
        if sm.get("smart_obs") and \
                self.sm["tick_n"] % max(1, int(sm.get("obs_every_polls") or 10)) == 0:
            return ("OBS box=%s L_hat=%s Tbar_w=%s Tbar_base=%s Tbar_used=%s inflight=%d "
                    "cong=%d degraded=%s cap=%s feed_blind=%s" % (
                        self.id,
                        ("%0.1f" % self.sm["L_hat"]) if self.sm["L_hat"] is not None else "-",
                        ("%0.1fs" % w) if w is not None else "DEFAULT",
                        ("%0.1fs" % base) if base is not None else "-",
                        ("%0.1fs" % self.sm["t_bar_used"]) if self.sm["t_bar_used"] is not None else "-",
                        self.inflight, self.sm["cong_streak"], self.sm["degraded"],
                        self.cap_slots, self.sm["feed_blind"]))
        return None


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
            # smart ledger (design v4.1): diagnostics only -- a move re-homes
            # an existing lane and never books a request, so the closed
            # identity stays untouched by any smart flag (S13-13)
            "moves": 0, "homecomings": 0, "preview_passes": 0, "move_gate_locked": 0,
            "shadow_would_moves": 0, "shadow_loss_moves": 0, "shadow_unresolved": 0,
            # B2: the decision layer's OWN witness -- a swallowed failure books
            # here (diagnostics: never in the closed identity), because a
            # DEBUG-only swallow is how F1 hid from every INFO-level run.
            "smart_decision_errors": 0,
        }
        # smart knobs (ALL default OFF, design S9): resolved once at boot.
        # F-F: DEFAULTS["smart"] is EMPTY on purpose -- every read site
        # re-defaults inline with `or X` (24 sites, README's Default column
        # is their ledger), and what keeps those `or`s honest is the
        # validator's refuse-<=0-by-name law, NOT any merged table. (This
        # comment used to claim a merged-defaults shape that never existed.)
        # A non-dict section is IGNORED here -- validate_cfg names it as a
        # boot problem before anything ever serves.
        _sm_raw = cfg.get("smart")
        self.sm_cfg = (dict(DEFAULTS["smart"], **_sm_raw) if isinstance(_sm_raw, dict)
                       else dict(DEFAULTS["smart"]))
        self.smart_any = any(self.sm_cfg.get(f) for f in SMART_FLAGS)
        self.smart_cap_read = bool(self.sm_cfg.get("smart_cap_read"))
        self.smart_shadow = bool(self.sm_cfg.get("smart_shadow"))
        self.smart_place = bool(self.sm_cfg.get("smart_place"))
        self.smart_preview = bool(self.sm_cfg.get("smart_preview"))
        self.smart_move = bool(self.sm_cfg.get("smart_move"))
        self.smart_transient = bool(self.sm_cfg.get("smart_transient"))
        self.smart_homecoming = bool(self.sm_cfg.get("smart_homecoming"))
        # lane + shadow bookkeeping (S2 state list): ALL in-memory, ALL
        # restart-zero (D13: losing samples only delays the shipping gate --
        # zero safety loss, and nothing re-derives identity from it)
        self._lane = OrderedDict()      # key -> {"turns", "R_hat", "last_move"}
        self._shadow_open = {}          # key -> open would-move sample
        self._shadow_cyc = {}           # bucket -> {cycle, samples, resolved, loss, unresolved}
        self._shadow_done = []          # completed cycle dicts, oldest first
        self._shadow_bucket = None
        # F5: the ONE lock the shadow tables know. Deliberately NOT pool.lock:
        # status() reads the gate while holding pool.lock, and the request
        # threads reach the ledger from the sticky branch WITHOUT pool.lock --
        # sharing pool.lock here would let a roll deadlock status() (or worse,
        # the sticky try would swallow the deadlock symptom). Flag-off cost:
        # zero -- nothing takes this lock unless a shadow path runs.
        self._shadow_lock = threading.Lock()
        self._swallow_warn_at = 0.0   # B2 rate limiter: one WARNING per 60s, counter always
        self._settle_warn = []        # P2-2: settle's F16 loss, named OUTSIDE the lock
        self._evict_warn_n = 0        # P3-6b: 4096-cap eviction count, warned OFF pool.lock
        # L6 working memory (volatile like the affinity table it shadows):
        # which home each re-homed lane left, and the per-box homecoming
        # throttle clock
        self._exiled = {}
        self._box_hc = {}

    def note_completion(self, backend, method, bare, duration, key, status):
        """Class-filtered SUCCESS accumulator (design S2/S13-14): ONLY
        POST /v1/messages completions feed T-bar -- count_tokens, other paths,
        other methods and every failure never count, because their seconds are
        not a conversation's answer time. F3 made the docstring the code:
        status is a REQUIRED argument (no default -- silence about a failure
        is exactly how this file's own ledger lied) and >=400 feeds nothing:
        an outage's seconds made HOME look expensive, so failures feeding
        T-bar turn placement FAILURE-ATTRACTING. `key` is reserved for the
        shadow lane ledger (L2). Silent no-op while every smart flag is off."""
        if not self.smart_any:
            return
        if method != "POST" or bare != "/v1/messages":
            return
        if int(status) >= 400:      # an answer time, from an ANSWERED request
            return
        with backend.lock:
            backend.sm["streams_s"] += 1
            backend.sm["dur_sum_s"] += float(duration)
        if self.smart_shadow and key:
            # P2-1: the ledger is ONE region -- settle pops and sorts under
            # _shadow_lock, so this append must live under it too, or the
            # release gate's own evidence resolves mid-write (a cross-lock
            # append is exactly the race the lock exists to close).
            with self._shadow_lock:
                smp = self._shadow_open.get(key)
                if smp is not None and backend.id == smp["home"]:
                    smp["durs"].append(float(duration))

    # ---- smart engine (design S2/S3/S9; every entry point flag-gated) ----
    def _lane_touch(self, key):
        st = self._lane.get(key)
        if st is None:
            st = {"turns": 0, "last_move": 0.0,
                  "R_hat": float(self.sm_cfg.get("r_hat_init") or 4.0)}
            self._lane[key] = st
            while len(self._lane) > 20000:
                self._lane.popitem(last=False)   # bounded like affinity's table
        else:
            try:
                self._lane.move_to_end(key)      # F6: the cap evicts the COLDEST lane, not the first-born -- FIFO eviction voided the HOTTEST lane's tau cooldown row and let the mover hit it twice
            except KeyError:
                # F-E: between our get and our touch, another thread's cap
                # eviction happened to evict exactly THIS lane (cold table,
                # unlucky crowd). A KeyError here died inside the sticky
                # swallow and skipped the turn's homecoming+mover -- the
                # decision layer must never die over the ledger's own
                # bookkeeping: re-seat fresh, the lane's history restarts.
                st = {"turns": 0, "last_move": 0.0,
                      "R_hat": float(self.sm_cfg.get("r_hat_init") or 4.0)}
                self._lane[key] = st
        st["turns"] += 1
        # R̂ (O3, the weakest multiplier, honestly so): a lane is expected to
        # keep going at least as long as it has -- init floors new lanes,
        # observed turns raise the estimate, clamp bounds it (r_hat_min/max).
        st["R_hat"] = max(float(self.sm_cfg.get("r_hat_min") or 1.0),
                          min(float(self.sm_cfg.get("r_hat_max") or 64.0),
                              max(st["turns"], st["R_hat"])))
        return st

    def _r_hat_for(self, affinity_key):
        """The lane's own expected remaining turns for a J round; a lane with
        no recorded state yet is a new lane -- init, the same floor _lane_touch
        seats fresh lanes at (O3)."""
        st = self._lane.get(affinity_key) if affinity_key else None
        return st["R_hat"] if st else float(self.sm_cfg.get("r_hat_init") or 4.0)

    def _j_parts(self, be, now, body_len, r_hat):
        """One currency, three terms (S2): J = R̂xŴ + Ĉ + X.
        Ŵ = max(0, L̂-k_b+[L̂>=k_b])/max(1,k_b) x T̄_used -- expected drain wait
        for a NEW arrival; Ĉ = (len(body)/4) x κ̂ -- the cold-refill cost the
        move would pay at the target (κ̂ is a CONSERVATIVE default: box-level
        cold/warm deltas are unmeasurable here, V3-09-7/O2, and a too-cheap Ĉ
        loosens both directions at once -- §15);
        X = w_cour x max(0, L̂_ext) x T̄_used/k_b -- courtesy for the load the
        box carries for OTHERS (never pays itself, S19-4).
        ANY input missing (stale feed, undeclared cap, no T̄ yet) = None:
        F1/F5 say None is an input, not an invitation to guess."""
        k = _k_b_of(be)
        l = _l_hat_of(be, now)
        t = be.sm["t_bar_used"]
        if k is None or l is None or t is None:
            return None
        rep = float(be.reported.get("serving") or 0.0) + float(be.reported.get("queued") or 0.0)
        w_hat = max(0.0, l - k + (1.0 if l >= k else 0.0)) / k * t
        c_hat = (max(0.0, float(body_len)) / 4.0) * float(self.sm_cfg.get("kappa_hat") or 0.001)
        debt = sum(1 for x in be._ghost_debt if x > be.status_ts)   # F8: ONE clock with the poller's prune -- a debt that settled after the last status still hid real load from J for a whole poll cycle
        x_cour = float(self.sm_cfg.get("w_cour") or 1.0) * max(0.0, rep - be.inflight - debt) * t / k
        return {"W": w_hat, "C": c_hat, "X": x_cour, "J": r_hat * w_hat + c_hat + x_cour}

    def _smart_order(self, cands, now, body_len, r_hat, require_window=False, tail_excluded=False):
        """J order for one placement/decision round (S3). Returns None = the
        round falls back to TODAY's order: J seconds and load_score ordinals
        are different currencies and never mix inside one round (E6-2), and
        ONE candidate with missing inputs degrades the WHOLE round (F1/F5).
        SUSPECT leaves the candidate face while any HEALTHY remains (F11);
        all-SUSPECT is today's order too. DOWN boxes are never scored (their
        feed is their own problem, and scoring one could poison an honest
        round with a None that shouldn't apply) and pin the TAIL whatever:
        the half-open trial belongs behind a live queue, a J number must
        never make a dead box look cheap ahead of a working one.
        tail_excluded (drain callers): keep SUSPECT in the list too, at the
        tail -- begin() is legal on them, dropping them would lose a real
        trial-forward candidate. Ties -- exact at the default k_eps=0, or
        inside the relative band k_eps x min(J1,J2) -- fall to load_score,
        whose own jitter (:440, untouched) is the final tie-break: this is
        the fan-out floor (S3/V3-02), not a coin flip."""
        if not cands:
            return None
        if all(b.state == SUSPECT for b in cands):
            return None
        tail = [b for b in cands if b.state == DOWN or (tail_excluded and b.state == SUSPECT)]
        _tid = {id(b) for b in tail}
        live = [b for b in cands if id(b) not in _tid and b.state != SUSPECT]
        if require_window:
            live = [b for b in live if b.sm["t_bar_window"] is not None]
        if not live:
            return None
        scored = []
        for b in live:
            p = self._j_parts(b, now, body_len, r_hat)
            if p is None:
                return None
            scored.append((p["J"], b))
        scored.sort(key=lambda t: t[0])
        keps = float(self.sm_cfg.get("k_eps") or 0.0)
        out = []
        i = 0
        while i < len(scored):
            j = i + 1
            while j < len(scored) and (scored[j][0] - scored[i][0]) <= keps * max(scored[i][0], 1e-9):
                j += 1
            band = [b for _v, b in scored[i:j]]
            band.sort(key=lambda b: b.load_score())
            out.extend(band)
            i = j
        out.extend(sorted(tail, key=lambda b: b.load_score()))
        return out

    def _new_cycle(self, b):
        return {"cycle": b, "samples": 0, "resolved": 0, "loss": 0, "unresolved": 0}

    def _shadow_roll(self, now):
        """Public entry (the poller's): the ledger tables move under the
        dedicated shadow lock (F5); cores assume it, nothing logs under it
        -- P2-2 made that docstring the code: settle defers its warnings."""
        with self._shadow_lock:
            self._shadow_roll_locked(now)
        self._shadow_drain_warn()

    def _shadow_drain_warn(self):
        """Emit deferred shadow-ledger warnings OUTSIDE the shadow lock --
        house rule, no exemptions: a blocked console sink must never freeze
        the lock that every sticky turn queues behind. F-D: the take must be
        an ATOMIC SWAP -- the poller and every sticky thread drain, and
        `while list: pop(0)` from two of them let the loser pop an emptied
        list: an IndexError that the sticky swallow booked as a decision
        error while silently skipping that turn's homecoming+mover. Same
        scar family, caught in our own fix's plumbing."""
        with self._shadow_lock:
            _w, self._settle_warn = self._settle_warn, []
        for _m in _w:
            LOG.warning(_m)

    def _shadow_roll_locked(self, now):
        """Cycle bookkeeping (CALLER HOLDS self._shadow_lock; poller-called,
        S-2 zero resident threads): the bucket is the release gate's period;
        crossing it closes the old cycle and settles its open samples.
        Forward-only: the monotonic clock never rewinds, and neither do the
        buckets."""
        cyc = float(self.sm_cfg.get("shadow_cycle_s") or 604800.0)
        b = int(now // cyc)
        if self._shadow_bucket is None:
            self._shadow_bucket = b
            self._shadow_cyc.setdefault(b, self._new_cycle(b))
            return
        if b <= self._shadow_bucket:
            return
        self._shadow_done.append(self._shadow_cyc.get(self._shadow_bucket)
                                 or self._new_cycle(self._shadow_bucket))
        while len(self._shadow_done) > 32:
            self._shadow_done.pop(0)
        for s in [x for x in self._shadow_open.values() if x["bucket"] != b]:
            self._shadow_settle(s)
        self._shadow_bucket = b
        self._shadow_cyc.setdefault(b, self._new_cycle(b))
        while len(self._shadow_cyc) > 64:
            _oldb = min(self._shadow_cyc)
            if _oldb == b:
                break
            self._shadow_cyc.pop(_oldb)

    def _shadow_settle(self, s):
        """CALLER HOLDS self._shadow_lock (both call sites run inside it)."""
        self._shadow_open.pop(s["key"], None)
        c = self._shadow_cyc.get(s["bucket"])
        if c is None:
            # F16: 64 buckets at the shipped period is a YEAR -- reaching a
            # missing table is a bug path, and a decision ledger loses
            # NOTHING in silence: name the loss, then drop the sample.
            # P2-2: the naming is DEFERRED -- we run under _shadow_lock and
            # nothing logs under it (a frozen sink would freeze every sticky
            # turn behind the lock); the roll wrapper and note_turn drain.
            self._settle_warn.append(
                "SHADOW: sample lane=%s bucket=%s found no cycle table (trimmed?) -- settled nowhere"
                % (short(s["key"]), s["bucket"]))
            return
        if not s["durs"]:
            c["unresolved"] += 1
            self.metrics["shadow_unresolved"] += 1
            return
        _d = sorted(s["durs"])
        _n = len(_d)
        med = _d[_n // 2] if _n % 2 else 0.5 * (_d[_n // 2 - 1] + _d[_n // 2])
        c["resolved"] += 1
        # D14/E5: the verdict is observation vs observation -- the lane's REAL
        # home durations (median, long-tail resistant) against the target's
        # PRE-CLAMP raw window + the move's own cold cost. Estimator outputs
        # are banned from the gate's scale (SP-J-04: the gate must not be
        # calibrated by the thing it gates). loss = staying home was cheaper.
        if med - (s["target_raw"] + s["c_hat"]) < 0:
            c["loss"] += 1
            self.metrics["shadow_loss_moves"] += 1

    def _move_candidate(self, home, body_len, r_hat):
        """The S4 predicate as ONE definition, shared by the shadow (which
        samples it) and the mover (which acts on it): the home's own trigger
        (cong_streak>=2, fresh-only by construction), the full net
        inequality, and the un-ticked hard-gate probe (V3-09-6). Returns
        (target, parts_home, parts_target) or None. Reads state only --
        safe to ask from any caller, and it ticks nothing on its own."""
        if home.sm["cong_streak"] < 2:      # S4-1 trigger: own signal, 2 fresh polls
            return None
        now = time.monotonic()
        ph = self._j_parts(home, now, body_len, r_hat)
        if ph is None:
            return None
        # F7 tier law: the mover moves WITHIN the home's tier. The step to
        # the next tier is the operator's priority ladder (x-strata-pin is
        # the cross-tier tool, overflow respects the boundary) -- a mover
        # that crossed would silently promote a lane to a tier nobody
        # priced it in. Disclosed in the README's smart_move row.
        order = self._smart_order([b for b in self.backends if b is not home
                                   and b.state == HEALTHY
                                   and b.priority == home.priority],
                                  now, body_len, r_hat, require_window=True)
        if not order:
            return None
        tgt = order[0]
        pt = self._j_parts(tgt, now, body_len, r_hat)
        if pt is None or not tgt.accepts_placement():   # un-ticked probe (S13-17)
            return None
        # S4-2 net inequality -- evaluated blind in L2, acted on in L5:
        if r_hat * (ph["W"] - pt["W"]) <= float(self.sm_cfg.get("k_gain") or 2.0) * pt["C"]:
            return None
        return tgt, ph, pt

    def _shadow_note_turn(self, affinity_key, home, body_len, st=None):
        """Sticky hit at home: roll the lane, and ask the mover's question
        OBSERVATIONALLY (L2 never moves anything -- S9). A sample opens
        exactly where the mover would have moved. F5 discipline: the
        predicate (read-only, bounded skew accepted per F12's recorded
        decline) runs lock-free; the ledger tables move as ONE region under
        the shadow lock; the LOG line is emitted OUTSIDE the lock (house
        rule) -- which is where F1 lived: the unpack bound _ph while the
        line read ph, and the NameError behind the sticky branch's try was
        silently stealing homecoming AND the mover on every would-move turn.
        One binding, one path: the log line and the ledger never disagree."""
        st = st if st is not None else self._lane_touch(affinity_key)
        mv = self._move_candidate(home, body_len, st["R_hat"])
        if mv is None:
            return
        tgt, ph, pt = mv
        now = time.monotonic()
        _dropped17 = None
        with self._shadow_lock:
            old = self._shadow_open.get(affinity_key)
            if old is not None:
                self._shadow_settle(old)   # a superseded sample settles on its facts
            self._shadow_roll_locked(now)
            b = self._shadow_bucket
            # R4-Q1 (open question from the R4 behavioral face, confirmed):
            # _move_candidate filtered None-windows at decision, but a
            # poller boundary tick (:563 branch) may flip THIS target's
            # window to None before booking -- None+number in settle is the
            # TypeError that kills cycle resolution and silently re-locks
            # the gate: the decision-ledger-loses-nothing family. Read the
            # clock once under this lock; a dead window drops the sample
            # (nothing booked, nothing to settle) and says so at DEBUG.
            _tw = tgt.sm["t_bar_window"]
            if _tw is None:
                # R5-F2 (DV-R5): the drop speaks OUTSIDE the lock. A LOG call
                # inside _shadow_lock is this file's own scar family (a blocked
                # console sink freezes every sticky turn's shadow path) -- and
                # this guard shipped committing exactly that sin, caught the
                # next round by a blind face's source scan.
                _dropped17 = tgt.id
            else:
                c = self._shadow_cyc.setdefault(b, self._new_cycle(b))
                c["samples"] += 1
                self.metrics["shadow_would_moves"] += 1
                self._shadow_open[affinity_key] = {"key": affinity_key, "home": home.id,
                                                   "target": tgt.id,
                                                   "target_raw": _tw, "c_hat": pt["C"], "durs": [], "bucket": b}
        if _dropped17 is not None:
            LOG.debug("SHADOW would-move %s -> %s dropped: target T-bar window went None between decision and booking",
                      home.id, _dropped17)
            return
        LOG.info("SHADOW lane=%s would-move %s -> %s (W_home=%.1fs W_tgt=%.1fs C_tgt=%.1fs)",
                 short(affinity_key), home.id, tgt.id, ph["W"], pt["W"], pt["C"])
        self._shadow_drain_warn()   # P2-2: the superseded settle above ran
                                    # under the lock -- its warnings speak here

    def _release_gate_open(self):
        """S9 data gate: L5 ships only on OBSERVED evidence -- the last
        release_gate_shadow_cycles completed cycles each show ZERO loss, and
        the global resolved pool is at least release_gate_min_would_moves
        (E5: zero samples never ships, 禁空轉). Selection bias is on record
        (D9-2): would-move lanes are biased-busy and target same-window
        traffic biased-light -- the scale reads OPTIMISTIC, shadow-period
        calibration knob stays beside it."""
        n = max(1, int(self.sm_cfg.get("release_gate_shadow_cycles") or 2))
        mn = max(1, int(self.sm_cfg.get("release_gate_min_would_moves") or 20))
        with self._shadow_lock:
            if len(self._shadow_done) < n:
                return False
            if sum(c["resolved"] for c in self._shadow_done) < mn:
                return False
            return all(c["loss"] == 0 for c in self._shadow_done[-n:])

    def _smart_move(self, affinity_key, home, body_len, st):
        """L5, one condition per gate (S4): the shared predicate (own signal
        + net inequality + un-ticked probe), the origin=pin exemption
        (V3-07 -- an operator seat is not smart's to move), the per-lane
        tau_pp cooldown on the key its origin OWNS (transient homes cool on
        tau_pp_transient), and the data gate (S9) checked last so
        move_gate_locked counts moved-worthy denials, not traffic. A move
        re-homes the lane and books NO request: diagnostics only, the closed
        identity stays closed over every flag (§4 accountancy)."""
        mv = self._move_candidate(home, body_len, st["R_hat"])
        if mv is None:
            return
        tgt = mv[0]
        with self.lock:
            _hit = self.affinity.get(affinity_key)
        _o = _hit[2] if _hit and len(_hit) > 2 else "sticky"
        if _o == "pin":
            return
        now = time.monotonic()
        tau = float(self.sm_cfg.get("tau_pp_transient" if _o == "transient" else "tau_pp_move")
                    or 900.0)
        if now - st["last_move"] < tau:
            return
        if not self._release_gate_open():
            with self.lock:
                self.metrics["move_gate_locked"] += 1
            return
        if not self._affinity_put_smart(affinity_key, tgt.id, st, now):
            LOG.info("MOVE skipped: lane %s pinned, or stamped a move/homecoming inside tau, during the decision window (V3-07 and the lane clock win AT THE PUT -- seat and counters untouched)",
                     short(affinity_key))
            return
        with self.lock:
            self.metrics["moves"] += 1
        LOG.info("MOVE lane %s %s -> %s (streak=%d R_hat=%.1f J_home=%.1fs J_tgt=%.1fs)",
                 short(affinity_key), home.id, tgt.id, home.sm["cong_streak"],
                 st["R_hat"], mv[1]["J"], mv[2]["J"])

    def _exile_note(self, key, old_home_id):
        """L6's memory of where a re-homed lane came from -- bounded like the
        rest of the volatile tables; a dropped entry only loses a future
        homecoming candidate, which is exactly the honest no-op. OFF means
        OFF: nobody records what nobody will read."""
        if not self.smart_homecoming:
            return
        # F-3 (DV-R3): ONE locked region, crash-proof eviction. _homecoming
        # has always popped this table under pool.lock while both writers ran
        # bare -- two threads evicting at the 4096 cap could race next(iter())
        # against each other's pop, and the loser's KeyError thrown from
        # overflow_commit runs BEFORE send_response: it resets a connection
        # whose box HAD answered. Inside the region the eviction is atomic;
        # the default is belt-and-braces (_exiled is a plain dict -- its
        # popitem takes no `last=`, the probe caught my first draft there).
        with self.lock:
            self._exiled[key] = old_home_id
            while len(self._exiled) > 4096:
                self._exiled.pop(next(iter(self._exiled)), None)

    def _homecoming(self, affinity_key, home, st):
        """L6: bring an exiled lane home when home is PROVABLY empty -- the
        D4' four items (healthy, gate open, the fresh feed showing zero load
        that is not our own with ghost debt subtracted, zero inflight) held
        TWO consecutive fresh polls (stale freezes, never counts nor resets);
        the lane's own tau_pp_homecoming; and a per-box homecoming_box_s
        throttle so a freed box drains lanes one careful step at a time,
        never a storm. Transient homes belong to the mover (§4), pin homes
        belong to the operator. Returns True if the lane came home (this
        turn's mover must then stand down)."""
        old_id = self._exiled.get(affinity_key)
        if old_id is None or old_id == home.id:
            return False
        with self.lock:
            _hit = self.affinity.get(affinity_key)
        if _hit and len(_hit) > 2 and _hit[2] in ("pin", "transient"):
            return False
        old = self.by_id.get(old_id)
        if old is None:
            return False
        now = time.monotonic()
        if now - st["last_move"] < float(self.sm_cfg.get("tau_pp_homecoming") or 900.0):
            return False
        if now - self._box_hc.get(old_id, 0.0) < float(self.sm_cfg.get("homecoming_box_s") or 120.0):
            return False
        # F4/F13: D4' item one is re-asked LIVE, next to the streak that only
        # a live poller advances. feed_blind FREEZES at its last value when
        # the poller stops -- the latch's final word ("fresh, empty x2!")
        # must not open the home door forever for a box nobody watches: the
        # clock and the state table get their own veto.
        if (old.state != HEALTHY or (now - old.status_ts) > old._stale_after()
                or old.sm["feed_blind"] or old.sm.get("empty_streak", 0) < 2):
            return False
        # F-B+F-C: the PUT-TIME GATE -- one pool.lock region that re-asks the
        # seat owner (a pin may have landed while the live re-ask ran) AND
        # enforces the box throttle atomically. The old shape read the box
        # clock, did a lock hand-off (the put), then stamped: N exiled lanes
        # of one freed box ALL passed the check before ANYONE stamped, and
        # the README's "ONE lane per window, never its queue" -- the very
        # law the storm columns rest on -- was advertised but never booked.
        _hc_seat, _hc_ok = False, False
        _box_s = float(self.sm_cfg.get("homecoming_box_s") or 120.0)
        _tau_hc = float(self.sm_cfg.get("tau_pp_homecoming") or 900.0)
        with self.lock:
            _hit = self.affinity.get(affinity_key)
            _cur = _hit[2] if _hit is not None and len(_hit) > 2 else ""
            _row = self._lane.get(affinity_key)   # R4-F4: same law as
            # _affinity_put_smart -- tau is asked and stamped on the CURRENT
            # row; a caller that grabbed st before its lock hand-off may be
            # holding an orphan.
            if _row is not None:
                st = _row
            if _cur in ("pin", "transient"):
                _hc_seat = _cur    # F-10 (DV-R3): re-ask BOTH seats the
                # pre-check stands down for -- a transient that landed mid-
                # window is the MOVER's home, and re-keying it to smart in a
                # race steals the lane's cooldown currency unasked.
            elif now - st["last_move"] < _tau_hc:
                pass               # F-2: a same-lane move/homecoming stamped
                # during the decision window -- the lane clock, like the box
                # throttle, is law inside THIS region, not before it.
            elif now - self._box_hc.get(old_id, 0.0) < _box_s:
                pass          # another lane took this box's window -- next turn
            else:
                self._affinity_write_locked(affinity_key, old_id, "smart")
                self._box_hc[old_id] = now
                self._exiled.pop(affinity_key, None)
                self.metrics["homecomings"] += 1
                st["last_move"] = now     # F-2: the stamp joins the region
                _hc_ok = True
        if _hc_seat:
            LOG.info("HOMECOMING skipped: lane %s seat claimed by %s during the decision window (V3-07 wins at the put; transient homes belong to the mover)",
                     short(affinity_key), _hc_seat)
            return False
        if not _hc_ok:
            return False
        LOG.info("HOMECOMING lane %s %s -> %s (home verifiably empty x%d fresh)",
                 short(affinity_key), home.id, old_id, old.sm.get("empty_streak", 0))
        return True

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
            # P3-6b: the counter books HERE, the WARNING waits -- we run
            # under pool.lock (the caller holds it, the docstring says so)
            # and nothing logs under it; pick's request-tick region drains
            # the count to the next request, off the lock.
            self._evict_warn_n += evicted

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
        # §6: with smart_transient ON the answered overflow homes the lane as
        # what it is -- a commit-then-migrate transient home, auditable in the
        # origin column and coolable/movable on its own tau_pp key. The
        # settlement itself is the existing commit exit: zero new terminal.
        # F-1 (DV-R3): the commit door respects an operator seat that landed
        # after the token popped (the README's law holds in BOTH orderings),
        # and exiles only when the re-home really happened -- a move that did
        # not happen leaves no trail. The booking above stands: the answered
        # request settled as itself; only the seat is refused.
        if self._affinity_put(affinity_key, pend[2], "transient" if self.smart_transient else "sticky"):
            self._exile_note(affinity_key, pend[1])   # L6 remembers where it came from
        else:
            LOG.info("overflow commit: lane %s keeps its operator pin -- the late first byte will not move a pinned lane back; the answered request stays booked",
                     short(affinity_key))

    def overflow_rollback(self, affinity_key, token, failed_id, body_len):
        """The overflow target died BEFORE a single request byte was sent --
        nothing reached it, so nothing is lost by moving on. Release its
        reservation EXACTLY once (the caller must not end() it again; the
        returned tuple carries the reservation state of whatever box takes
        over) and hand the caller a box to queue at instead -- rule 2: the
        gate redirects, it never rejects.

        body_len is REQUIRED (no default): when the home ALSO died, the
        migrate-onward placement must speak the lane's own currency --
        body_len AND the lane's r_hat -- exactly like the normal migration
        round (P3-3: one request, two placement rounds, two currencies
        was the defect; silence about a currency is how J quietly lies).

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
            # R4-F5: the ONE sibling shape that queued at a require_idle home
            # without booking gate_bypass -- pick's home-queue door and this
            # function's own migrate-onward branch both book it (F-7, DV-R8:
            # symbols are the anchor); the metric's documented purpose is that
            # such admits are NEVER invisible. The helper is self-gating (a
            # capacity-only refusal does not tick), so the call is unconditional.
            self._note_gate_bypass(home)
            return home, "sticky", True
        # the home died mid-request too (or raced into its cooldown): migrate
        # this turn onward instead of failing it. Counted as the settled
        # overflow it is (overflow_rollbacks already ticked) plus the home's
        # migrations_from evidence; the lane's later turns re-place fresh on
        # their own once the poller drops the dead home's keys.
        alt2, reserved = self._place(exclude={failed_id} | ({home.id} if home else set()),
                                     body_len=body_len, r_hat=self._r_hat_for(affinity_key))
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
    # Values are (backend_id, monotonic_ts, origin), origin in
    # {pin, sticky, smart, transient}: WHO seated this lane, so L5+ knows what
    # it may move. All readers are arity-tolerant on the 2-form (a value can
    # only be 2-form after a binary rollback -- reading it must not die), and
    # _affinity_get's restamp MUST preserve origin (S13-20: a sticky hit must
    # never launder an operator pin into movable traffic).
    def _affinity_get(self, key):
        ttl = float(self.cfg.get("sticky_ttl") or 0)
        with self.lock:
            hit = self.affinity.get(key)
            if not hit:
                return None
            backend_id, ts = hit[0], hit[1]
            if ttl > 0 and time.monotonic() - ts > ttl:
                del self.affinity[key]
                return None
            # idle-TTL: a live conversation keeps its pin -- ttl counts idle
            # time since the LAST ROUTED READ of this home, not since
            # placement, so a long working night never drifts an active
            # session onto a cold box. (R6a-F4: every routed reader restamps,
            # and a preview routes through the home too -- with a small
            # sticky_ttl a lane fed only by previews keeps its seat warm;
            # the README's preview row names that.)
            self.affinity[key] = (backend_id, time.monotonic(),
                                  hit[2] if len(hit) > 2 else "sticky")
            self.affinity.move_to_end(key)
            return backend_id

    def _affinity_write_locked(self, key, backend_id, origin):
        # CALLER HOLDS self.lock -- the one write shape (value, LRU touch,
        # cap) so every guarded writer gets the identical table law.
        v = self.cfg.get("sticky_max")
        cap = 20000 if v is None else int(v)
        self.affinity[key] = (backend_id, time.monotonic(), origin)
        self.affinity.move_to_end(key)
        while len(self.affinity) > cap:
            self.affinity.popitem(last=False)

    def _affinity_put(self, key, backend_id, origin):
        # origin has NO default on purpose: every seat must SAY who seated it,
        # and a call site that forgot is a TypeError at boot-smoke, not a
        # silent "sticky" that quietly makes an operator pin movable.
        # explicit None check: `or 20000` silently turned a configured 0 into
        # 20000 and a negative cap into "empty the table on every write"
        # (R4-A/F7); validate_cfg rejects non-positive caps at boot now.
        #
        # F-1 (DV-R3): V3-07 lives HERE, not at any one door. The table has
        # several non-pin writers -- overflow commit, migration, fresh
        # placement, last-resort queue, and every future one -- and DV-fix4
        # guarded only the mover's put. A pin landing inside any other
        # door's window was still silently clobbered. Now ANY non-pin write
        # that meets an operator seat at the lock REFUSES (returns False,
        # writes nothing): callers keep their bookings (the request settled
        # as it settled, the identity stays closed) and say the skip out
        # loud. Pin writes stay legal by definition.
        with self.lock:
            if origin != "pin":
                _seat = self.affinity.get(key)
                if _seat is not None and len(_seat) > 2 and _seat[2] == "pin":
                    return False
            self._affinity_write_locked(key, backend_id, origin)
        return True

    def _affinity_put_smart(self, key, backend_id, _st=None, _now=0.0):
        """F-B (V3-07 AT THE PUT) + F-2 (DV-R3, the lane clock's turn).

        The guard lives where the write lives: same lock, re-asked first.
        Returns False and writes NOTHING when a pin holds the seat -- the
        caller must then book nothing at all (no moves, no stamp): a move
        that did not happen may not even be counted.

        With st/now given, the per-LANE tau law joins the same region:
        re-ask the cooldown, write, stamp -- atomically. Two concurrent
        same-lane turns (the README's own expected overlap: an SDK retry
        while the turn is in flight) used to both pass the pre-lock tau
        read and double-move inside tau_pp, exactly the shape F-C fixed
        at the BOX throttle with the lane clock left as its unguarded
        twin. The cooldown currency is read from the CURRENT seat, not
        the decision-time one (finding C: a seat that changed during the
        decision window gets the cooldown it actually owes)."""
        with self.lock:
            hit = self.affinity.get(key)
            if hit is not None and len(hit) > 2 and hit[2] == "pin":
                return False
            if _st is not None:
                # R4-F4: the clock's source of truth is the TABLE ROW, not the
                # object the caller captured before queuing on this lock --
                # _lane_touch is lock-free and its own F-E comment documents
                # the orphan shapes (double-create; a cap eviction catching
                # exactly this lane mid-flight). Trusting the passed dict
                # reads a stale clock AND stamps into an object the ledger
                # no longer holds: the lane moves twice inside tau while the
                # visible row never learns.
                _row = self._lane.get(key)
                if _row is not None:
                    _st = _row
                _cur = hit[2] if hit is not None and len(hit) > 2 else "sticky"
                _tau = float(self.sm_cfg.get("tau_pp_transient" if _cur == "transient"
                                             else "tau_pp_move") or 900.0)
                if _now - _st.get("last_move", 0.0) < _tau:
                    return False
            self._affinity_write_locked(key, backend_id, "smart")
            if _st is not None:
                _st["last_move"] = _now
        return True

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
    def pick(self, affinity_key, pin=None, passthrough=False, body_len=0, preview=False):
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

        preview: a /v1/messages/count_tokens request. With smart_preview ON it
        answers from a real box and reports its placement byte-for-byte, but
        it is NOT a conversation turn: no home written, no exile, no overflow
        stash, no lane roll -- it books preview_passes, its own terminal,
        instead of sticky_hits/new_placements/migrations (S7). A pin on a
        preview is an operator command and keeps today's full pin behavior.
        It DOES route through an existing home, and like every routed reader
        that restamps the home row's idle clock (R6a-F4): previews keep a
        seat warm without claiming a turn.
        """
        with self.lock:
            self.metrics["requests"] += 1
            _ew = self._evict_warn_n
            if _ew:
                self._evict_warn_n = 0
        if _ew:      # P3-6b: the deferred 4096-cap warning, spoken OFF pool.lock
            LOG.warning("overflow ledger hit its 4096 cap and evicted %d pending re-home(s) -- "
                        "this many concurrent parked re-homes means the box fleet is far past "
                        "any real load; their requests will 502 instead of home-queue "
                        "(warning deferred off pool.lock to the next request)", _ew)
        _pv = preview and self.smart_preview

        if pin:
            want = self.by_id.get(pin)
            if want is not None and want.try_place(ignore_cap=True):
                if affinity_key:
                    self._affinity_put(affinity_key, want.id, "pin")
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
            if _pv:
                # F-B1: a preview's fallback placement is NOT the turn's
                # "normal placement" -- previews never write a home, so this
                # steer lands nowhere. The old line promised a fallback that
                # semantically cannot happen; name the real consequence:
                # only a REAL turn can re-seat the lane.
                LOG.warning("pin %r unavailable on a PREVIEW -- the preview answers by placement but writes no home (contract); steer the lane with a real turn", pin)
            else:
                LOG.warning("pin %r unavailable; falling back to normal placement", pin)

        home = None
        if affinity_key:
            want = self._affinity_get(affinity_key)
            home = self.by_id.get(want) if want else None
            if home is not None and home.take_sticky():
                if _pv:
                    # the lane is home, the preview just passes through it --
                    # not a turn: no sticky tick, no shadow roll (S7)
                    with self.lock:
                        self.metrics["preview_passes"] += 1
                else:
                    with self.lock:
                        self.metrics["sticky_hits"] += 1
                    if (self.smart_shadow or self.smart_move or self.smart_homecoming) and affinity_key:
                        # L2 asks the mover's question observationally; L5
                        # may act on it; L6 may bring the lane home first
                        # (an empty-home proof outranks a J round this turn
                        # -- the mover stands down when the lane came home).
                        # All of it rolls the lane ONCE and a failure here
                        # never touches the request in flight (S9).
                        try:
                            _lst = self._lane_touch(affinity_key)
                            if self.smart_shadow:
                                self._shadow_note_turn(affinity_key, home, body_len, _lst)
                            _hc = (self.smart_homecoming
                                   and self._homecoming(affinity_key, home, _lst))
                            if self.smart_move and not _hc:
                                self._smart_move(affinity_key, home, body_len, _lst)
                        except Exception:
                            # B2: the swallow must never be the only witness.
                            # A DEBUG-only line hid F1 through three INFO-level
                            # rounds: diagnostics ticked while the decision layer
                            # died. Same class never again -- named counter
                            # (diagnostics, never in the identity) + rate-limited
                            # WARNING; the full traceback stays at DEBUG so a
                            # storm of failures cannot drown the log.
                            with self.lock:
                                self.metrics["smart_decision_errors"] += 1
                                _due_w = (time.monotonic() - self._swallow_warn_at) >= 60.0
                                if _due_w:
                                    self._swallow_warn_at = time.monotonic()
                                    _tot_w = self.metrics["smart_decision_errors"]
                            if _due_w:
                                LOG.warning("smart decision failed for %s -- serving continues (%d total, detail at DEBUG)",
                                            short(affinity_key), _tot_w, exc_info=True)
                            else:
                                LOG.debug("smart decision failed for %s -- serving continues",
                                          short(affinity_key), exc_info=True)
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
                # A preview never overflows a lane: tokenizing warms no cache,
                # and no token count may be the event that exiles a
                # conversation (S7 -- the same doctrine the commit-side
                # count_tokens skip already applies; F-7: symbol anchor).
                # Its answer just queues at home.
                if not _pv:
                    alt, reserved = self._place(exclude={home.id}, no_trial=True,
                                                body_len=body_len, r_hat=self._r_hat_for(affinity_key))
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
                        self.metrics["preview_passes" if _pv else "sticky_hits"] += 1
                    return home, "sticky", True, None
                # raced into DOWN between the two attempts: fall through to
                # the migration path below
            # The conversation has a home box but it is unreachable or cooling
            # down: move the conversation rather than fail it, and remember the
            # move so later turns do not ping-pong back to the dead box.
            alt, reserved = self._place(exclude={home.id}, body_len=body_len,
                                        r_hat=self._r_hat_for(affinity_key))
            if alt is not None and not reserved:
                reserved = alt.begin()     # queue-anyway box (nothing accepted)
                if reserved:
                    self._note_gate_bypass(alt)
            if alt is not None and reserved:
                with self.lock:
                    self.metrics["preview_passes" if _pv else "migrations"] += 1
                if not _pv:
                    # a preview may not re-home a lane, drop its home or
                    # count a migration -- the conversation was never here (S7)
                    with home.lock:
                        home.stats["migrations_from"] += 1
                    dropped = self._affinity_drop_backend(home.id)
                    LOG.warning(
                        "affinity %s migrating %s -> %s (dropped %d keys); one cold prompt re-read expected",
                        short(affinity_key), home.id, alt.id, dropped,
                    )
                    if self._affinity_put(affinity_key, alt.id, "sticky"):
                        self._exile_note(affinity_key, home.id)   # L6 remembers where it came from
                    else:
                        # F-1 (DV-R3): the dead home's keys are gone, but a
                        # pin to a LIVE box that landed mid-migration is not
                        # migration's to overwrite; the migrated turn stays
                        # booked (identity), the seat is the operator's.
                        LOG.info("migration: lane %s keeps the operator pin that landed mid-migration",
                                 short(affinity_key))
                return alt, "migrated", True, None
        else:
            # New conversation: put it on the shallowest ACCEPTING queue and
            # pin it there. The reservation happens inside _place, atomically
            # with the gate check -- concurrent first turns cannot both take
            # the last slot of a capped box.
            alt, reserved = self._place(body_len=body_len, r_hat=self._r_hat_for(affinity_key))
            if alt is not None and not reserved:
                reserved = alt.begin()     # queue-anyway box (nothing accepted)
                if reserved:
                    self._note_gate_bypass(alt)
            if alt is not None and reserved:
                if affinity_key and not _pv and not self._affinity_put(affinity_key, alt.id, "sticky"):
                    # F-1 (DV-R3): a pin that landed while this placement was
                    # in flight wins the seat; the served turn stays booked.
                    LOG.info("placement: lane %s keeps the operator pin that landed mid-placement",
                             short(affinity_key))
                with self.lock:
                    if _pv:
                        self.metrics["preview_passes"] += 1
                    else:
                        self.metrics["passthrough_gets" if passthrough else "new_placements"] += 1
                return alt, "placed", True, None

        # Every reservation path lost the race or was refused. Give each
        # candidate its real begin() in load order BEFORE booking a
        # last-resort forward: the box whose half-open trial is actually free
        # takes it (that is exactly the last-resort trial forward we forward
        # into anyway) instead of leaving the choice to load_score's random
        # tie-break -- an honest diagnostic beats a coin flip (stress Q2/F2).
        be = None
        _dseq = (self._smart_order(list(self.backends), time.monotonic(), body_len,
                                   self._r_hat_for(affinity_key), tail_excluded=True)
                 if self.smart_place else None)
        for cand in (_dseq if _dseq is not None
                     else sorted(self.backends, key=lambda b: b.load_score())):
            if cand.begin():
                be = cand
                break
        reserved = be is not None
        if be is None:
            be = _dseq[0] if _dseq is not None else min(self.backends, key=lambda b: b.load_score())
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
                    if _pv:
                        self.metrics["preview_passes"] += 1
                    else:
                        self.metrics["passthrough_gets" if passthrough else "new_placements"] += 1
                if affinity_key and not _pv and not self._affinity_put(affinity_key, be.id, "sticky"):   # "placed" means homed
                    # F-1 (DV-R3): same law at the last-resort door
                    LOG.info("last-resort queue: lane %s keeps the operator pin that landed mid-race",
                             short(affinity_key))
                LOG.info("new placement found every gate closed mid-race; queued at live %s", be.id)
                return be, "placed", True, None
        with self.lock:
            self.metrics["last_resort"] += 1
        LOG.warning("every backend is cooling down; last-resort forward to %s", be.id)
        return be, "last_resort", reserved, None

    def _place(self, exclude=None, no_trial=False, body_len=0, r_hat=None):
        """Tiered placement with atomic reserve: returns (backend, reserved).
        Tiers are tried in ascending `priority`; inside a tier boxes are tried
        by ascending score and the first that passes its gate AND takes the
        reservation wins (Backend.try_place). If no box in any tier accepts,
        the FIRST (highest-priority) tier that is merely healthy becomes the
        queue -- returned UNRESERVED so the caller decides (waiting in the
        primary box's FIFO beats borrowing a busy peer or failing; the gate
        redirects, it never rejects, rule 2 stays intact).

        With smart_place ON, INSIDE a tier the walk follows J (_smart_order:
        its None = this round degrades to the load_score walk; ties keep the
        load_score floor), and the queue-anyway head is the J-cheapest box of
        the first healthy tier too -- drain follows the same currency as
        admission. OFF is byte-for-byte today's tier+load_score walk.

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
        _rh = float(r_hat) if r_hat is not None else float(self.sm_cfg.get("r_hat_init") or 4.0)
        now = time.monotonic()
        fallback = None
        for prio in sorted({b.priority for b in cands}):
            tier = [b for b in cands if b.priority == prio]
            usable = [b for b in tier if b.load_state_ok() and (b.state != DOWN or not no_trial)]
            if not usable:
                continue
            _ord = self._smart_order(usable, now, body_len, _rh) if self.smart_place else None
            for b in (_ord if _ord is not None else sorted(usable, key=lambda b: b.load_score())):
                if b.try_place():
                    return b, True
            if fallback is None:
                fallback = usable
        if fallback is not None and self.smart_place:
            _fq = self._smart_order(fallback, now, body_len, _rh)
            if _fq:
                return _fq[0], False
        return min(fallback or cands, key=lambda b: b.load_score()), False

    def status(self):
        with self.lock:
            dist = {}
            origin_dist = {}
            for v in self.affinity.values():
                # v[0]-form: the table's shape must never break the monitor
                # feed, and origin belongs on its own axis (S13-19/S13-20)
                dist[v[0]] = dist.get(v[0], 0) + 1
                _o = v[2] if len(v) > 2 else "sticky"
                origin_dist[_o] = origin_dist.get(_o, 0) + 1
            out = dict(self.metrics)
            out["affinity_keys"] = len(self.affinity)
            out["affinity_by_backend"] = dist
            out["affinity_origin"] = origin_dist
            # the provisional window made observable: overflows that have left
            # home but not yet earned a re-home (each settles within its own
            # request's lifetime -- a number that GROWS is the landmine signal)
            out["overflow_pending"] = len(self._overflow_pending)
            # the release gate and its evidence (S9): an operator deciding
            # whether smart_move may ship reads THIS, not a log grep
            out["release_gate_open"] = self._release_gate_open()
            with self._shadow_lock:               # snapshot the evidence table under its own lock (F5)
                # F-9 (DV-R3): the ROWS too -- json.dumps reads these dicts
                # AFTER the locks release, and the cycle objects in
                # _shadow_done are the same ones the roll/settle paths still
                # touch (a roll archives the dict and then settles its
                # leftover samples into it). A snapshot sharing mutable rows
                # is only half a snapshot.
                out["shadow_cycles"] = [dict(c) for c in list(self._shadow_done)[-4:]]
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


def _k_b_of(be):
    """k_b = max(1, min(max_inflight, cap_slots)); a missing cap falls to the
    other; NOTHING declared is None = missing input (S-1 refuses that shape at
    boot for place/move; shadow and OBS simply see None). ONE definition --
    the tick's cong_streak and the J engine must never disagree about where
    "full" is."""
    caps = [v for v in (be.max_inflight, be.cap_slots) if v is not None]
    return max(1, min(caps)) if caps else None


def _l_hat_of(be, now):
    """L̂ = max(reported_fresh, inflight) (V2-02); a stale feed is a MISSING
    input (None), never a stale number -- the same freshness gate load_score
    applies in _score_locked via _stale_after (F-7, DV-R8: symbols are the
    anchor; line numbers rot), so cong and J cannot disagree about sight."""
    if not be.ever_reported or (now - be.status_ts) > be._stale_after():
        return None
    return max(float(be.reported.get("serving") or 0.0)
               + float(be.reported.get("queued") or 0.0), float(be.inflight))


def _read_cap_slots(body):
    """L1 (design S8): the ONE whitelisted capacity key, read by exact path
    ONLY. concurrency.serving is Strata's declared serving capacity, and the
    ONLY number in that payload the smart scaffold is allowed to want: a walk
    that "finds a capacity-like number" is exactly how a capacity becomes a
    load number wearing the wrong costume (the v1.2.16 decoy family) -- this
    reader never walks, and its result feeds ONLY Backend.cap_slots, never a
    score or a gate. Shape rules: int or integral float in [1, 1e6]; bool is
    refused with the truthy family; NaN/inf/strings/objects refused; a box
    claiming a million serving slots has a broken metric, and an unbounded
    k_b is the same attractive lie S-1 refuses at boot."""
    try:
        obj = json.loads(body)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    sec = obj.get("concurrency")
    if not isinstance(sec, dict):
        return None
    v = sec.get("serving")
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if not math.isfinite(v) or v < 1 or v > 1_000_000 or int(v) != v:
        return None
    return int(v)


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
                if self.pool.smart_any:
                    # the scaffold's ONLY heartbeat (S-2): it ticks whether or
                    # not this poll got a fresh sample -- staleness is a verdict.
                    # F2: the tick runs INSIDE its own try -- an escaping
                    # exception here killed the poller thread, and a dead
                    # poller blinds EVERY box at once (worse than any ledger).
                    try:
                        with be.lock:
                            obs = be._smart_tick_locked(self.pool.sm_cfg, time.monotonic())
                        if obs:
                            LOG.info("%s", obs)
                    except Exception as exc:
                        with be.lock:
                            be.status_error = "smart tick: " + repr(exc)
                        # R5-B1 (DV-R5): this surface booked NOTHING, and its
                        # status_error row is overwritten by the NEXT poll's
                        # success -- a persistent crash was invisible to the
                        # panel the README promises ("never silent"). Book the
                        # witness; the shared 60s limiter keeps a per-poll
                        # storm quiet, and the WARNING speaks outside all locks.
                        _due17 = False
                        with self.pool.lock:
                            self.pool.metrics["smart_decision_errors"] += 1
                            _due17 = (time.monotonic() - self.pool._swallow_warn_at) >= 60.0
                            if _due17:
                                self.pool._swallow_warn_at = time.monotonic()
                                _tot17 = self.pool.metrics["smart_decision_errors"]
                        if _due17:
                            LOG.warning("smart tick failed for %s -- poller survives (%d decision errors total)",
                                        be.id, _tot17, exc_info=True)
            if self.pool.smart_shadow:
                try:
                    self.pool._shadow_roll(time.monotonic())
                except Exception:
                    # R5-B1: the named WARNING existed, the COUNTER did not --
                    # an operator watching smart_decision_errors through a
                    # persistent ledger failure saw a frozen number. Book the
                    # witness (the sticky branch's swallow books its own).
                    # R6a-F2: but the WARNING was UNLIMITED -- a persistent
                    # roll failure fails every cycle, so the door logged every
                    # cycle while the README (and the sticky/tick catches)
                    # promise one named WARNING per minute. Third same-shape
                    # finding in the witness subsystem DV-R5 just built: the
                    # fix taught all three surfaces to BOOK, only two to
                    # LIMIT. The limiter read/stamp lives under pool.lock like
                    # the tick catch's; the counter stays unconditional.
                    with self.pool.lock:
                        self.pool.metrics["smart_decision_errors"] += 1
                        _due18 = (time.monotonic() - self.pool._swallow_warn_at) >= 60.0
                        if _due18:
                            self.pool._swallow_warn_at = time.monotonic()
                    if _due18:
                        LOG.warning("shadow roll failed (poller survives)", exc_info=True)
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
                        if self.pool.smart_cap_read:
                            # L1, fresh-commits-only: an unreachable or silent
                            # box FREEZES its last declared cap rather than
                            # losing it (the cap is a promise, not a sample)
                            be.cap_slots = _read_cap_slots(body)
                        if self.pool.smart_homecoming:
                            # L6's D4' verifiably-empty verdict, ticked on
                            # FRESH commits only (a stale poll freezes the
                            # streak -- it may neither count nor reset). Four
                            # items: healthy, gate open, this very report is
                            # the fresh one showing no FOREIGN load (ghost
                            # debt subtracted), and zero inflight of ours.
                            be.sm["empty_streak"] = (be.sm.get("empty_streak", 0) + 1
                                if (be.state == HEALTHY and be._accepts_locked(be.status_ts)
                                    and total <= be.inflight + debt and be.inflight == 0)
                                else 0)
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

    def send_error(self, code, message=None, explain=None):
        # DV-R8 (L1b P2-1 + red team (a), the 11th AND 13th same-shape lesions):
        # every stdlib dispatch refusal -- unknown method 501, malformed request
        # line 400, too-long line 414, bad version 505 -- ends HERE, and the
        # stdlib closes the connection from here WITHOUT ever touching the bytes
        # the caller still has queued. Windows then RST-flushes both the pending
        # bytes AND the refusal just written (measured 0/10 named arrivals at
        # 1.2 MB in flight, both doors, three independent rigs). After thirteen
        # same-shape lesions the drain law is no longer taught door by door --
        # it lives at this ONE choke point, exactly as the pin law moved into
        # _affinity_put (DV-fix5 doctrine). No fourth per-door drain site is
        # allowed anywhere in this file.
        # Flag-first: the door closes regardless (the stdlib says so below).
        # DV-R9 N-1 (P2, the 14th same-shape lesion): NOT peek-gated anymore.
        # Bytes the sender releases 0.2-0.5 s after the request were not
        # "pending" in this door-time snapshot, the peek let the door close
        # over them, and the Windows RST ate this very refusal (measured 0/10
        # named arrivals, four shapes). _close_drain holds ONE quiet window
        # for bytes that are still arriving.
        self.close_connection = True
        self._close_drain()
        if self.request_version == "HTTP/0.9":
            # DV-R11 F-1 (L1a fidelity face + L2 red team, the 16th same-shape
            # lesion): round 10 built this compensation with a two-word-GET
            # exemption -- and left the router's OWN refusal primitive (_json,
            # some twenty doors) untaught. The same caller then stood one door
            # away from a framed 505 and got a bare body back (r11a live:
            # BARE@0.40 x3 vs FRAMED@2.01; README's own sentence called the
            # file dishonest). The council ruling: the 0.9 close-delimited law
            # governs RELAYED BODIES -- a path that never passes through a
            # refusal writer (two-word GET + Host that wants a body gets it
            # verbatim; S21's relay lock polices it as a control) -- so the
            # REFUSAL face frames UNCONDITIONALLY, here and in _json: one law,
            # two faces, no shape predicate. A refusal is owed a status line
            # to every caller; the exemption's old text is suite-forbidden.
            self.request_version = "HTTP/1.1"
        BaseHTTPRequestHandler.send_error(self, code, message, explain)

    def _json(self, code, obj, extra_headers=()):
        # DV-R11 F-1 (the 16th same-shape lesion, council ruling A'): framing was
        # built at the send_error door only, and THIS -- the router's own
        # refusal primitive, some twenty doors -- answered explicit-HTTP/0.9
        # and default-version callers in bare body, one door away from a
        # framed 505. One law, both faces: while the version is 0.9 the answer
        # is forced through HTTP/1.1 framing. The 0.9 close-delimited law
        # governs RELAYED box bodies (the relay never passes through here on
        # success); a refusal owed a status line to every caller. See
        # send_error for the full ruling.
        if self.request_version == "HTTP/0.9":
            self.request_version = "HTTP/1.1"
        # Optional headers emit before end_headers. First user is the R4-B1
        # (DV-R4) fix: the synth count_tokens rescue must answer through the
        # SAME header face as the relay it replaces -- README promises a
        # preview "reports one of those same words byte-for-byte", and the
        # rescue exists exactly for boxes that 404 the real probe, where the
        # report was silently vanishing.
        data = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", "no-store")
        for _hk, _hv in extra_headers:
            self.send_header(_hk, _hv)
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
            self.close_connection = True   # the flag goes up BEFORE the drain:
            self._drain_body()             # _drain_body only discards queued
            self._json(400, {"error": {"message": "strata-router: request target must be origin-form (path starting with '/')"}})
            return True                    # bytes where the connection WILL close
                                           # (a keep-alive door must leave a
                                           # pipelined request alone -- N-5)
        if not self.path.isascii() or re.search(r"[\x00-\x20\x7f]", self.path):
            # http.client encodes the request line as ASCII: a target with
            # high-bit or control bytes would raise UnicodeEncodeError mid-
            # relay and kill the handler with no response. Refuse at the door
            # (callers percent-encode; that stays pure ASCII).
            self.close_connection = True   # flag first (R7b-F1, see origin-form door)
            self._drain_body()
            self._json(400, {"error": {"message": "strata-router: request path must be ASCII without control characters"}})
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
            self.close_connection = True   # flag first (R7b-F1, see origin-form door)
            self._drain_body()
            self._json(403, {"error": {"message": "strata-router: foreign Host %r refused (rebinding guard)" % host}})
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
                self.close_connection = True   # flag first (R7b-F1, see origin-form door)
                self._drain_body()
                self._json(403, {"error": {"message": "strata-router: cross-origin caller refused (rebinding guard)"}})
                return True
        return False

    def _quiet_finish(self, secs=2.0):
        """Read what is left of an unwanted body politely, under a short
        deadline, so the refusal written after it reaches the sender over a
        still-live socket -- closing right here lets Windows RST-flush the
        bytes the sender still has queued and the caller learns nothing at
        all (stress P1/F3, Q1/Q2A-5)."""
        try:
            deadline = time.monotonic() + secs
            while True:
                _left = deadline - time.monotonic()
                if _left <= 0:
                    break
                self.connection.settimeout(_left)
                try:
                    # DV-R10 (R10-F-2, the 15th same-shape lesion): the deadline
                    # is checked AROUND EACH READ. read(65536) accumulated until
                    # 65536 bytes / EOF / one raw gap longer than the timeout --
                    # a sender trickling faster than that gap never let the loop
                    # regain control, and the "bounded" wait was unbounded. read1
                    # returns after one raw read; the per-op arm bounds the op,
                    # the deadline bounds the whole.
                    if not self.rfile.read1(65536):
                        break
                except Exception:
                    break        # deadline expiry, or trouble
        except Exception:
            pass
        finally:
            try:
                self.connection.settimeout(None)
            except Exception:
                pass

    def _pending_now(self):
        """Zero-cost, non-blocking check for bytes the caller queued but never
        declared (or bytes already sitting in the reader's buffer). An idle
        socket answers immediately, so honest requests pay nothing. Called ONLY
        where the connection will close anyway -- on a keep-alive door the same
        bytes would be a legitimately pipelined request and eating THAT was the
        red team's N-5 catch against the naive 'drain everywhere' fix.
        DV-R9 N-1 retired its DOOR-GATING role -- a peek is a door-time
        snapshot, blind to bytes still arriving. It is now called ONLY by
        _close_drain, to choose full-deadline draining vs a quiet window."""
        try:
            self.connection.settimeout(0.0)
            try:
                return bool(self.rfile.peek(1))
            finally:
                try:
                    self.connection.settimeout(None)
                except Exception:
                    pass
        except Exception:
            return False

    def _close_drain(self, window=0.4, secs=2.0):
        """The drain law at a closing door, arrival-time-proof (DV-R9 N-1 P2,
        the 14th same-shape lesion and the FIRST one inside the drain
        mechanism itself): what the peek found EMPTY at door time, a slow
        sender filled 0.2-0.5 s later -- the door closed over those bytes and
        the RST ate the refusal (0/10 named arrivals, four shapes, WinError
        10053; no surplus -> clean 0.00 s, the controls prove it). So a
        closing door drains what is HERE now under the full deadline, and if
        the peek is EMPTY it still waits ONE quiet window before closing;
        late arrivals inside the window are discarded too. Nothing waits
        past the window: bytes later than that make any wait on this socket
        unbounded -- a thread-starvation door -- so the guarantee is BOUNDED,
        and the README states the boundary. Honest requests pay the window
        ONLY on closing paths (refusal doors); keep-alive doors never call
        this, so pipelining stays untouched (N-5) and the hot paths stay at
        0.00 s (healthz guards ride the suite)."""
        try:
            arm = secs if self._pending_now() else window
            deadline = time.monotonic() + secs
            while True:
                _left = deadline - time.monotonic()
                if _left <= 0:
                    break
                # DV-R10 (R10-F-2): per-operation arm -- the window/deadline
                # choice survives (honest empty door = EXACTLY one window: the
                # first op is armed `window` and silence expires it), but the
                # deadline is now checkable BETWEEN ops because each op is one
                # raw read (read1), not an accumulation the trickle outruns.
                self.connection.settimeout(arm if arm < _left else _left)
                try:
                    if not self.rfile.read1(65536):
                        break
                except Exception:
                    break        # quiet-window / deadline expiry, or trouble
        finally:
            try:
                self.connection.settimeout(None)
            except Exception:
                pass

    def _close_tail(self, secs=0.6):
        """The drain law's FINAL MILE (DV-R11 C-1 + L2 N-R11-1, the 17th
        same-shape lesion and the first that bites AFTER the answer): a door
        may drain perfectly before writing and still be RST-eaten after it.
        When the router closed at its deadline, the caller could STILL be
        trickling and not reading yet -- a Windows close over inbound still
        arriving answers with an RST, and the RST discards the caller's
        UNREAD receive buffer: the named refusal, and on the success doors
        the 200 itself (council r11a/r11b: 8/8 EATEN per door, five doors --
        the dispatch 400 included; reader timing was the determining
        variable: same shape, read-now 8/8 FRAMED). The law is at every door
        and inside every read; this is its single site at the handler's
        close: flush, FIN FIRST (shutdown(SHUT_WR)) so a compliant slow
        reader holds bytes+EOF while we wait, then a bounded drain to EOF
        that absorbs the caller's last arrivals and lets the close be clean.
        The physical limit is documented, not promised away (README, the
        delivery boundary): a caller that keeps dribbling past every bounded
        window AND hands the socket to a reader only afterwards cannot be
        saved by ANY server -- the OS RST law owns that shape. Single site:
        handle()'s finally -- every door, method and stdlib path inherits;
        per-door close tails are the illegal shape this program has now
        measured sixteen times. Keep-alive pays nothing: the request loop
        never returns here between pipelined requests (N-5 intact), and a
        closing door's honest client sees FIN the instant the answer is
        written -- its EOF-read returns earlier, not later."""
        try:
            self.wfile.flush()
        except Exception:
            pass
        try:
            self.connection.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        _end = time.monotonic() + secs
        while True:
            _left = _end - time.monotonic()
            if _left <= 0:
                break
            try:
                self.connection.settimeout(_left)
                if not self.connection.recv(65536):
                    break          # the caller's FIN: inbound done -- clean close
            except Exception:
                break              # deadline, RST-in, or already gone
        try:
            self.connection.settimeout(None)
        except Exception:
            pass

    def handle(self):
        # DV-R11: the close tail hangs off the handler's ONE exit -- not off
        # any door (the sixteen-lesion doctrine: law at the shared surface).
        # Runs after the request loop ends, before socketserver closes down.
        try:
            BaseHTTPRequestHandler.handle(self)
        finally:
            self._close_tail()

    def _drain_body(self, limit=1 << 20):
        """Consume (bounded) whatever body a non-proxy route will not use, so
        the bytes cannot desync the next request on this keep-alive connection.
        R7b-F1 (P2, ninth same-shape lesion): the law lived in this helper's
        CHUNKED branch only -- bad / negative / under-declared Content-Length
        each returned WITHOUT discarding, and the door then RST-flushed its own
        named refusal (measured 0/10 delayed-arrival on every entry door). Now:
        wherever the door is closing (close_connection set BEFORE the call),
        pending bytes are discarded under the quiet deadline first; a door that
        keeps the connection open is left alone -- its pending bytes are the
        next pipelined request, not junk (N-5)."""
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            self.close_connection = True
            self._close_drain()          # escape 1 closed, arrival-proof (N-1):
            return                       # framing garbage -> window-discard, THEN close
        if n < 0:
            self.close_connection = True
            self._close_drain()          # escape 2 closed: a negative CL was
            return                       # never honest framing
        _clock = time.monotonic() + 2.0   # DV-R10 (R10-F-1): the count loop carried
        while n > 0:                      # the file's ONLY unbounded wait -- an
            chunk = min(n, 65536)         # honest-but-undelivered CL pinned the
            _left = _clock - time.monotonic()
            if _left <= 0:                # refusal door (thread-starvation door:
                self.close_connection = True   # one stalled sender = one dead
                return                    # thread forever, named refusal never
            try:                          # written). A declared length is a
                self.connection.settimeout(_left)   # NUMBER TO STOP AT, not a
                got = self.rfile.read1(chunk)       # promise the door must honor
            except Exception:             # waiting on. Nine call sites inherit
                self.close_connection = True
                return
            finally:
                self.connection.settimeout(None)
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
            return
        # escape 3 closed: the count stopped at the DECLARED length (or there
        # was no length at all) while the caller queued MORE than they told
        # us -- a liar's leftovers. Only touch them where this door is closing
        # anyway (flag set before the call); a keep-alive door's pending bytes
        # are a pipelined request and stay untouched (N-5). DV-R9 N-1: the
        # leftovers may still be ARRIVING -- _close_drain keeps the window.
        if self.close_connection:
            self._close_drain()

    # ---- routes -----------------------------------------------------------
    def do_GET(self):
        self._tune()
        if self._entry_denied():
            return
        if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
            # N-1 (red team, P2): this branch used to close WITHOUT draining --
            # and a close over an unread body is an RST on this platform, which
            # was measured eating the SUCCESSFUL 200 (0/10 named arrivals for a
            # 1.2 MB chunked GET at 0.3 s delay; even an immediate reader only
            # got 2/10). _quiet_finish needs no length -- this helper's own
            # chunked branch proves it. Drain, THEN close.
            self._quiet_finish()
            self.close_connection = True
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
            self._quiet_finish()           # N-1 (red team): drain BEFORE closing
            self.close_connection = True   # or the RST eats the answer itself
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
        self.close_connection = True       # flag first (R7b-F1, see origin-form door)
        self._drain_body()
        self._json(405, {"error": {"message": "strata-router: no OPTIONS/CORS surface -- POST inference requests only"}})

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
                    # R7a-F1: the last door DV-fix8's sweep missed -- drain
                    # like every sibling, or the named 400 never arrives
                    # (measured 0/10 for a delayed reader with bytes streaming).
                    self._quiet_finish()
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
                    # FR-1: drain before refusing -- closing on an unread body
                    # RST-flushes the sender's queued bytes on Windows and the
                    # named 400 is never seen (the rebinding doors drain first;
                    # this door's twin-law was missing).
                    self._quiet_finish()
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
                            self._quiet_finish()   # FR-1: reach the sender, don't RST it
                            self._json(400, {"error": {"message": "strata-router: too many trailer headers"}})
                            self.close_connection = True
                            return None
                    break
                if used + n > limit:
                    self._quiet_finish()   # FR-1: refuse OVER THE WIRE, not by RST
                    self._json(413, {"error": {"message": "strata-router: body over max_body_mb"}})
                    self.close_connection = True
                    return None
                parts.append(self.rfile.read(n))
                used += n
                if self.rfile.readline(2) != b"\r\n":
                    # strict CRLF: chunk data not followed by CRLF is framing
                    # the router never agreed to parse; the old blind
                    # readline(2) accepted anything (stress P1/F4)
                    self._quiet_finish()   # FR-1: reach the sender, don't RST it
                    self._json(400, {"error": {"message": "strata-router: chunk data not terminated by CRLF"}})
                    self.close_connection = True
                    return None
            body = b"".join(parts)
            # F-8 (DV-R8): the post-loop 413 twin of the per-chunk door was
            # UNREACHABLE -- the pre-deduction above charges declared bytes
            # BEFORE reading, so used <= limit at every loop exit and the
            # assembled body can never exceed limit here. Dead branch deleted:
            # dead code is where the next blind face burns its round
            # (DV-fix9's dead probe rc, one family). 413 contract unchanged.
            return body
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            self._quiet_finish()   # FR-1: framing is unparseable -- discard under deadline
            self._json(400, {"error": {"message": "strata-router: bad content-length"}})
            self.close_connection = True
            return None
        if n < 0:
            self._quiet_finish()   # FR-1: reach the sender, don't RST it
            self._json(400, {"error": {"message": "strata-router: bad content-length"}})
            self.close_connection = True
            return None
        if n == 0:
            return b""
        if n > limit:
            # check BEFORE reading: never BUFFER a body we will refuse -- and
            # still let the refusal be READ: _drain_body consumes the unwanted
            # bytes under a bounded deadline (discarding is not buffering), so
            # the named 413 reaches the sender instead of being eaten by a
            # Windows RST on close (R6b-FR-1: the v1.2.12 drain law lived at
            # the rebinding doors only; the capacity doors were its twins).
            # DV-R10 (R10-F-3): flag FIRST like every sibling -- this was the
            # family's last flag-LAST door, and the comment above was a lie
            # waiting to happen: an under-delivered giant CL pinned the drain
            # (silent 30s measured) because the count loop had no deadline and
            # the drain could not even SEE that the door was closing.
            self.close_connection = True
            self._drain_body()
            self._json(413, {"error": {"message": "strata-router: body over max_body_mb"}})
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
        On hangup, shut the backend socket down: the BOX learns now (its side
        sees FIN/RST immediately), and a box that watches its clients --
        Strata does -- cancels within its 0.5 s poll and ENDS the response:
        that is what unblocks our parked relay, the box's last byte, not our
        shutdown call. Platform fact (R4-B2, DV-R4, reproduced on the
        shipping box): on Windows shutdown() does NOT wake a recv() already
        parked in getresponse()/read() (it does on Linux) -- so on a box that
        does not watch its clients (plain direct-wire servers, supported
        shape), the reservation and this handler thread stay held until the
        prefill completes, and the abort books at that point. "A hang-up is
        heard, not waited for" is a BOX-side law: it closes fast via the
        box's own watcher; the slot does not free by our will alone.
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
        # R5-F3: one float(), NUMERIC zero test (see resolve_read_timeout).
        read_timeout = resolve_read_timeout(self.cfg.get("read_timeout"))

        # DV-R8 L2-regrade: the 400 door that used to wrap this call was DEAD
        # proven -- the parser admits only bodies json.dumps(ensure_ascii=True)
        # survives, and the three shapes that could have raised (normal rewrite,
        # lone-surrogate escape, 400-deep nesting) live-forwarded 200 in BOTH
        # the red team's and the council's rigs. _rewrite_model is now TOTAL
        # (it forwards verbatim on any internal trouble), so there is no door
        # to guard: the ONE sanctioned body edit can neither bill a healthy box
        # nor stand as a closing door that never learned the drain law.
        body = self._rewrite_model(body)

        # N-2 (red team): NO body-shortcut -- the documented lane channel
        # (inbound x-strata-affinity, "either alone when only one is known")
        # works bodyless too; affinity_key_of already returns None when
        # neither a header nor a body exists, so keyless shapes are unchanged.
        key = affinity_key_of(bare, body, self.headers)
        pin = (self.headers.get("x-strata-pin") or "").strip() or None
        if pin and not self._control_ok():
            # F-3 (DV-R8 P2): a CLOSING door among the post-buffer ones -- it
            # drains exactly like the entry doors, or its own refusal rides the
            # RST (the lying-CL surplus is still in flight when this fires;
            # measured 0/10 named arrivals pre-fix -- deterministic, unlike the
            # unparseable-502 twin below).
            self.close_connection = True
            self._close_drain()   # DV-R9 N-1: no peek gate -- the 0.2 s late
                                  # surplus rode the peek's blind spot (0/10)
            self._json(403, {"error": {"message": "strata-router: x-strata-pin refused -- control token required (x-strata-control)"}})
            return
        is_count_tokens = bare.endswith(COUNT_TOKENS_SUFFIX)
        backend, reason, reserved, ovf_token = self.pool.pick(
            key, pin=pin, passthrough=(key is None and method in ("GET", "HEAD")),
            body_len=len(body or b""), preview=is_count_tokens)
        was_overflow = reason == "overflow"   # its pending entry must settle EXACTLY once
        # before this request ends: commit (it answered), rollback (target died
        # pre-send) or fizzle (ended any other way). ovf_settled tracks that.
        ovf_settled = False

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
                outcome = self.pool.overflow_rollback(key, ovf_token, backend.id, len(body or b""))
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
                # R4-B1: the placement face of the preview contract survives
                # the rescue -- same three headers, same exposure gate, same
                # affinity/placement-only-with-a-key rule as the relay leg.
                _ex = ()
                if self.cfg.get("expose_affinity"):
                    _ex = [("x-strata-backend", backend.id)]
                    if key:
                        _ex += [("x-strata-affinity", short(key)),
                                ("x-strata-placement", reason)]
                _syn = {"input_tokens": max(1, int(len(text) / 4))}
                if head:
                    # F-4 (DV-R8, L2 upgraded P3->P2): a HEAD carries NO body.
                    # The rescue used to emit its JSON anyway, and a COMPLIANT
                    # client (http.client reads a HEAD's headers and stops)
                    # then parsed the leftover bytes as the NEXT status line:
                    # BadStatusLine('{') -- the poison rode the same connection
                    # to the next request (measured live, red team + council).
                    # Header-only, like the relay's own HEAD branch: the
                    # synthesized count travels in x-strata-input-tokens.
                    self.send_response(200)
                    for _hk, _hv in _ex:
                        self.send_header(_hk, _hv)
                    self.send_header("x-strata-input-tokens", str(_syn["input_tokens"]))
                    self.send_header("content-length", "0")
                    self.end_headers()
                    return None
                return self._json(200, _syn, _ex)

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
            # the statuses the body/framing decisions below treat as done at
            # the header block -- single source, law and measurements at the
            # framing gate (DV-R12)
            nobody = resp.status in (204, 304)     # terminated by the empty line
            drop205 = resp.status == 205           # body dropped by policy, declared CL:0
            drop_body = head or nobody or drop205
            skip = HOP_BY_HOP | {"content-length", "content-type", "date", "server"}
            for k, v in resp.getheaders():
                kl = k.lower()
                # x-strata-* is OUR channel (DV-R12 N-R1): a lying box must not
                # forge x-strata-backend/affinity/placement and poison the very
                # observability headers the README tells operators to watch --
                # the request lane already strips the prefix (INBOUND_STRIP);
                # the response lane's sister cell was untaught. The router
                # appends its OWN x-strata-* headers AFTER this loop.
                if kl in skip or kl.startswith("access-control-") or kl.startswith("x-strata-"):
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
            if not nobody:
                # a 204/304 forbids Content-Type outright (9110 15.4.5: a
                # message terminated by the empty line has no content to
                # describe) -- the framing gate's sister cell, taught the
                # same day (DV-R12); 205 keeps its type (its body is only
                # dropped by policy, so its type stays truthful)
                self.send_header("content-type",
                                 _HDR_VAL_CTL_RE.sub("", resp.getheader("content-type")
                                                     or "application/json"))
            # N-2 (DV-R9, P3): HTTP/0.9 is the stdlib's DEFAULT request_version --
            # a two-word request line ("GET /v1/models") lands here, and the old
            # `!= "HTTP/1.0"` gate chunk-framed THAT caller: an HTTP/0.9 client
            # knows no chunked coding, so the framing hex and the "0\r\n\r\n"
            # terminator print as body to it. Close-delimited is its only honest
            # framing, and the stdlib already closed the connection on it.
            # DV-R12 (round 12's P2 pair -- the program's 18th same-shape
            # lesion, the framing family's fourth): this gate knew the METHOD
            # and the VERSION but not the STATUS. A no-content response is
            # done at its header block, yet the relay chunk-framed it anyway:
            # `0\r\n\r\n` (204/304/205) or even a smuggled `6\r\nSNEAKY`
            # (205+CL, N-R12L2-2) rode the wire between responses -- the
            # baseline raw-wire matrix showed poison bytes in all five shapes
            # (r12c3 te=True 5/5) and a compliant pipelined client read them
            # as the next status line (r12c strict 204 desync 3/3; L1b 12/12).
            # The HEAD doctrine one cell over already knew the law. r14a then
            # split the rest of the row by MEASUREMENT, not by the status
            # list: 204/304 are terminated by the empty line (RFC 9112 6.3)
            # and every client measured length-zeros them -- assert nothing.
            # A 205 is NOT on that no-content list: a bare 205 starves
            # http.client of a length signal and it blocked reading to EOF
            # (r14a: TimeoutError). This router's policy drops the box's 205
            # body, so it must DECLARE the drop -- `content-length: 0`, the
            # exact framing HEAD already speaks, legal for a 205 and illegal
            # for the two above, which is why this is two cells, not one.
            chunk_out = not drop_body and self.request_version not in ("HTTP/1.0", "HTTP/0.9")
            if head or drop205:
                # a bodyless response needs its zero stated or the framing
                # (or a terminator) desyncs the next response on this socket;
                # content-length: 0 is legal for HEAD and 205 -- and is the
                # only honest way to announce a policy-dropped 205 body
                self.send_header("content-length", "0")
            elif nobody:
                # 204/304 are terminated by the header block's empty line
                # (RFC 9112 6.3) and Content-Length is forbidden there
                # (9110 15.3.2/15.4.5) -- so this cell asserts NOTHING.
                # keep-alive stays legal either way; the close branch below
                # is NOT for this cell.
                pass
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
                if drop_body:
                    continue            # drain the box, never relay a body:
                                        # a lying box's HEAD or no-body-status
                                        # body must not reach the caller --
                                        # discard BEFORE the count, so booked
                                        # bytes_out is strictly forwarded
                                        # bytes (DV-R12: the old order only
                                        # stayed honest because 3.13 length-
                                        # zeros HEAD at runtime; a law must
                                        # not depend on the client library)
                total += len(chunk)
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
            self.pool.note_completion(backend, method, bare, duration, key, resp.status)
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
                    # F-3 (DV-R8 P2): this door closes too -- drain BEFORE
                    # writing. The red team caught this window as a race (the
                    # named 502 arrived only 2/10 when a lying CL left bytes in
                    # flight); drain-first makes every arrival deterministic.
                    self.close_connection = True
                    self._close_drain()   # DV-R9 N-1: the peek was the window
                                          # itself -- late surplus escaped it
                    self._json(502, {"error": {
                        "message": "strata-router: backend " + backend.id + " answered with a response the router "
                                   "could not parse (" + type(exc).__name__ + "). Nothing was relayed to the caller, "
                                   "and the request is not still running on the box.",
                        "type": "backend_protocol_error",
                    }})
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
            try:
                obj["model"] = rules[obj["model"]]
                # ensure_ascii=True on purpose: a lone surrogate ANYWHERE in the
                # body (a valid JSON escape like "\ud800") makes the utf-8 encode
                # of an ensure_ascii=False dump raise -- and a failure after the
                # connection opens gets charged to a healthy box, x-strata-pin
                # included deciding WHICH box eats the charges (review L2-2/M3).
                return json.dumps(obj, ensure_ascii=True).encode("utf-8")
            except Exception as exc:
                # DV-R8: the TOTAL form of the old dead 400 door -- internal
                # trouble forwards the caller's bytes VERBATIM: never billed to
                # a healthy box, and a forward opens no closing door. If the
                # body truly troubled the router, the box answers with its own
                # named error; the caller always learns something specific.
                LOG.debug("model rewrite skipped on this body (%s) -- forwarding verbatim",
                          type(exc).__name__)
                return body
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
        # DV-R13 (a NEW lesion caught live by DV-fix13's GREEN run -- lesson #6
        # ran its course the other way this time: rig suspected first, engine
        # stood charged; faulthandler stack named it inside server_bind):
        # Python 3.13's HTTPServer.server_bind ends with
        #     self.server_name = socket.getfqdn(host)
        # and on Windows the reverse lookup of a bindable-but-nameless address
        # -- 127.0.0.2 in the lab, and the DOCUMENTED tailnet listen in
        # production -- stalls ~5 s (measured 4.96 s x2) between the bind and
        # every boot sentence. Bind-first doctrine says the boot may not hang
        # on anything the bind itself does not need; the router never reads
        # server_name (the Server header comes from server_version, the
        # handler log uses address_string). So the stdlib's attributes are set
        # from the ONE truth already in hand -- the name of a listen address
        # is that IP -- and the resolver call is skipped.
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])

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
                # R7a-F2: a later healthy box must NOT erase an earlier dead
                # one -- the aggregate only goes up. (The old line reset rc to
                # 0 whenever it was not 2, and NOTHING ever set 2: the tri-state
                # was dead code and the exit gate lied for CI and boot users.)
                break
        else:
            rc = 1
            print("  !! no Anthropic Messages path answered; check the box is up and the key is set")
    print("")
    print("If /v1/messages 404s but /anthropic/v1/messages works, run the router with")
    print("--path-prefix /anthropic (or per box: --backend a=http://host:8080,/anthropic).")
    return rc


def _probe_get(be, path):
    conn = None   # DV-R11 F-3 (L1a P3): close() used to sit INSIDE the try --
    # any throw after open_connection skipped it and leaked the connection.
    try:
        conn = open_connection(be, 3.0, 6.0)
        conn.request("GET", be.prefix + path, headers=backend_headers(be.cfg, None, be))
        r = conn.getresponse()
        body = r.read(4000).decode("utf-8", "replace")
        return r.status, body
    except Exception as exc:
        return None, str(exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _probe_messages(be, path):
    model = be.cfg.get("probe_model") or "probe"
    body = json.dumps({"model": model, "max_tokens": 1, "stream": True,
                       "messages": [{"role": "user", "content": "ping"}]}).encode()
    conn = None   # DV-R11 F-3: same close-in-finally law as _probe_get
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
        return status, ""
    except Exception as exc:
        return None, str(exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

# smart-placement ladder (design v4.1 S9): flags gate behavior layers, all
# default OFF; numbers are the engine knobs. validate_cfg checks shape here;
# unknown knobs warn-and-ignore, never silently trusted as something else.
SMART_FLAGS = ("smart_obs", "smart_cap_read", "smart_shadow", "smart_place",
               "smart_preview", "smart_move", "smart_transient", "smart_homecoming")
SMART_NUMS = ("k_gain", "tau_pp_move", "tau_pp_homecoming", "tau_pp_transient",
              "default_t_bar", "n_min", "w_cour", "kappa_hat", "r_hat_init",
              "r_hat_min", "r_hat_max", "k_eps", "t_bar_clamp_factor",
              "t_bar_base_window_s", "window_n", "release_gate_shadow_cycles",
              "release_gate_min_would_moves", "shadow_cycle_s",
              "homecoming_box_s", "obs_every_polls")
# five of those numbers are TICK counters and minimums: every read site int()s
# them, so a float there is a number that silently truncates behind the
# operator's back (F15: window_n 2.7 "worked" as 2). Refused by name at boot.
SMART_INT_KNOBS = ("window_n", "n_min", "obs_every_polls",
                   "release_gate_shadow_cycles", "release_gate_min_would_moves")

DEFAULTS = {
    "listen": "127.0.0.1",
    "port": 8088,
    "backends": [],
    "smart": {},                    # the ladder lives here; empty = every flag off
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
    # R4-F8d: --probe reads probe_model THROUGH the per-backend merge
    # (be.cfg carries the globals), so a top-level probe_model was HONORED
    # while the unknown-key warning swore it was IGNORED. A real default
    # makes the warning loop tell the truth (and the value is unchanged:
    # the read site's `or "probe"` fallback stays as the belt).
    "probe_model": "probe",
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
            try:
                out.append(json.loads(spec))
            except ValueError as exc:
                # DV-R9 B-9a family sweep: this JSON door died as a raw
                # JSONDecodeError traceback -- every other config death is
                # named, this one is named too.
                raise SystemExit("--backend JSON object did not parse (%s): %r"
                                 % (exc, spec[:60]))
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
        try:
            with open(a.config, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if not isinstance(loaded, dict):
                raise ValueError("top level must be a JSON object, not a %s"
                                 % type(loaded).__name__)
            cfg.update(loaded)
        except FileNotFoundError:
            raise SystemExit(
                "config file not found: %s -- create it first (README 'Start' "
                "step 0: copy router.remote.example.json to router.json and "
                "edit it), or pass --backend id=URL flags instead of --config."
                % a.config)
        except (OSError, ValueError):
            # the sibling frames of the same typo door (OS-C/C-5): every way
            # a --config can fail to be a config dies BY NAME, pre-bind,
            # traceback-free. OSError = a directory or an unreadable file
            # (Windows raises PermissionError on open(directory)); ValueError
            # = JSONDecodeError and UnicodeDecodeError.
            raise SystemExit(
                "config file not readable: %s -- it must be a UTF-8 JSON "
                "object; start from router.remote.example.json (README "
                "'Start' step 0)." % a.config)
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
    if a.probe:
        cfg["_probe"] = True     # DV-R12 F-1: parsed, so --prob/--pro reach the
                                 # probe path too; main() used to exact-string
                                 # scan argv and silently booted a server instead
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
                         "Delete the file, then retype the keys with --set-key: while this file "
                         "is unreadable, boot refuses BEFORE --set-key can rewrite it (F-5, DV-R8: "
                         "the old message pointed at a door the boot gate itself locked)." % path)
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


_MERGED_READ_KEYS = ("priority", "max_inflight", "require_idle")
# DV-R8 F-1 (P2): these three top-level keys are NOT in DEFAULTS, yet make_pool
# merges every top-level field into each box's cfg (dict(cfg, **extra)) and
# Backend.__init__ READS them -- so the unknown-top-level loop must speak their
# truth instead of "is IGNORED" (the R4-F8d probe_model lie, same lesion).
# This is NOT a documented top-level feature: the tiering contract stays
# per-backend (README); a top-level spelling just sets every box's default.


def _backend_ids(cfg):
    """ONE id law (DV-R8 F-2 P2 + red team (c)): the ids a pool built from this
    cfg ACTUALLY carries -- mirrors make_pool's auto-id exactly, so apply_keys'
    known set, its apply loop and set_key can never drift from the ids the boot
    log and /stats speak. The old per-site spellings invented ghosts:
    str(spec.get('id')) minted the id \"None\" for an id-less dict spec (a
    --set-key 'None' entry was ACCEPTED, stored, warned about by nobody, and
    installed never), and string specs' real boxN ids were invisible to the
    typo check. Thirteenth lesson of this program: the law moves INTO the
    shared primitive."""
    ids = []
    _bi_specs = cfg.get("backends") or []
    if not isinstance(_bi_specs, list):
        # DV-R9 B-9a (P3, a DV-fix10 regression): a non-list shape's death belongs
        # to the NAMED door (make_pool, "backends must be a LIST") -- an id reader
        # that iterates it first would die as a raw "not iterable" traceback from
        # main()'s apply_keys, BEFORE that door ever runs. Empty view, not a crash.
        _bi_specs = []
    for _i, spec in enumerate(_bi_specs):
        bid = spec.get("id") if isinstance(spec, dict) else None
        ids.append(str(bid) if bid else "box" + str(_i + 1))
    return ids


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
        known = set(_backend_ids(cfg)) | {"global", "control"}
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
    _ids2k = _backend_ids(cfg)
    _bs2k = cfg.get("backends") or []
    # DV-R9 B-9a: a non-list top-level backends must die at the NAMED door
    # (make_pool), not here -- enumerate(int) raises, enumerate(dict) iterates
    # keys and the string-spec promotion writes them (dictionary-changed-size).
    # Skip the whole per-backend key pass; the door below owns shape death.
    if not isinstance(_bs2k, list):
        _bs2k = []
    for _ik, spec in enumerate(_bs2k):
        if isinstance(spec, str):
            # F-2 second limb (DV-R8 GREEN-run catch -- engine-wrong this time,
            # found by its own suite lock): a STRING spec has no dict to carry
            # the resolved key, so the box's key chain dead-ended here even
            # once the known set learned its real boxN id. Promote to exactly
            # the dict form make_pool would synthesize (explicit id from the
            # ONE law), and the loop below resolves it like any written dict
            # spec. id/url live in _KNOWN_BE_KEYS -- no new warnings anywhere.
            _bs2k[_ik] = spec = {"id": _ids2k[_ik], "url": spec}
        if not isinstance(spec, dict):
            continue
        bid = _ids2k[_ik]    # F-2: the ONE id law -- never "None", never "?"
        if _usable_key(spec.get("backend_api_key")):
            sources[bid] = "inline"
            continue
        k = keys.get(bid)
        if _usable_key(k):
            src = "keys-file"
        else:
            src = ""
        # R7a-F3: the fallback doors spoke bare `if not k:` while FIVE other
        # sites in this function use _usable_key -- so a whitespace sidecar
        # entry was "truthy": it skipped the env fail-loud door AND the global
        # fallback, silently dropping the backend's key. Same law at every door.
        if not _usable_key(k):
            var = str(spec.get("backend_api_key_env") or "").strip()
            if var:
                k = (os.environ.get(var) or "").strip()
                if not k:
                    raise SystemExit("backend %s: backend_api_key_env names %s, which is not set "
                                     "(export it in a private shell, or remove the field)" % (bid, var))
                src = "env"
        if not _usable_key(k):    # R7a-F3: same law as the env door above
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
    ids = set(_backend_ids(cfg))    # F-2: the ghost id "None" is DEAD -- membership speaks the ids the pool actually gets
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
            "--backend a=http://127.0.0.1:8080 --backend b=http://192.0.2.24:8080"
        )
    if not isinstance(specs, list):
        # R5-F6 (DV-R5): make_pool runs BEFORE validate_cfg, so a bad shape
        # here must die NAMED at THIS door -- it used to die as a raw
        # KeyError/AttributeError traceback, against the whole startup-refuses
        # doctrine the config doors were built to honor.
        raise SystemExit("backends must be a LIST of URL strings or objects, got %s"
                         % type(specs).__name__)
    backends = []
    _ids2mp = _backend_ids(cfg)     # F-2: this loop IS the id law now -- every reader sees THESE ids
    for i, spec in enumerate(specs):
        if isinstance(spec, str):
            spec = {"id": "box" + str(i + 1), "url": spec}
        elif not isinstance(spec, dict):
            raise SystemExit("backend #%d: each backend must be a URL string or an object, got %s"
                             % (i, type(spec).__name__))
        if not isinstance(spec.get("url"), str) or not spec["url"]:
            raise SystemExit("backend #%d: needs a non-empty \"url\" string (id=URL) -- a spec without it is a traceback, not a config"
                             % i)
        extra = {k: v for k, v in spec.items() if k not in ("id", "url", "path_prefix")}
        backends.append(Backend(
            _ids2mp[i],
            spec["url"],
            spec.get("path_prefix") or cfg.get("path_prefix") or "",
            cfg=dict(cfg, **extra),
        ))
    return Pool(backends, cfg)


def resolve_read_timeout(raw):
    """R5-F3 (DV-R5): the never-time-out sentinel used to be MIXED-TYPE
    membership -- `raw in (0, None, "0")`. The numeric door floats strings
    through ("0.0" is finite and >= 0), the membership test missed the
    spelling, and float("0.0") reached settimeout(): a NON-BLOCKING socket,
    every getresponse a BlockingIOError, every forwarded request a 502 with
    ghost debt -- under a boot log that printed "0.0" as if it meant
    something. Compare NUMERICALLY after one float(); absent and every zero
    spelling mean the same documented thing: never cut a parked stream."""
    if raw is None:
        return None
    _f = float(raw)
    return None if _f == 0.0 else _f


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
                  # keeps the "IGNORED" warning honest about what actually
                  # applies. status_timeout was KILLED here (DV-R3 F-4/B):
                  # its only read site is the poller's GLOBAL cfg -- a door
                  # that validates a knob no per-backend read obeys lends it
                  # false authority; the honest shape is the IGNORED warning
                  # (C9's dead-knob doctrine, generalized past SMART_NUMS).
                  "tls_insecure", "status_interval"}

# R5-F1 (DV-R5): the non-bool law in ONE place per domain. The file already
# spoke it twice -- `the string "false" is truthy` at require_idle's door and
# at every SMART flag -- while tls_insecure, a SECURITY knob, had no door at
# all: `"tls_insecure": "false"` is truthy at open_connection and SILENTLY
# TURNS TLS CERTIFICATE VERIFICATION OFF for that box (a security default
# inverted by a plausible spelling, invisible in /stats and logs), and
# `"expose_affinity": "false"` keeps the x-strata-* headers ON under
# --no-expose-affinity expectations. A future bool knob joins the list;
# every door reads the same sentence. (Third layer of the same lesion:
# the law stood at two doors and not the third.)
_BOOL_KNOBS_TOP = ("expose_affinity", "tls_insecure")
_BOOL_KNOBS_BE = ("require_idle", "tls_insecure")


def validate_cfg(cfg, pool, strict=True):
    """Check every knob that tiering, key injection or the health machine
    depends on, BEFORE serving a single request. A typo'd security knob must
    be indistinguishable from a crash, never from a working default.
    Returns the list of problems; main() treats them as fatal for serving."""
    problems = []
    # R5-F4 (DV-R5): an explicit null is a VALUE. {"port": null} passed every
    # door (the numeric loop skips None, the guards test `is not None`) and
    # build_cfg's update() let it CLOBBER the merged DEFAULTS -- port died by
    # a raw int(None) traceback at the bind (not the named error the startup
    # paragraph promises), sticky_ttl/read_timeout silently landed on
    # DOCUMENTED MODES that are not the documented defaults, expose_affinity
    # inverted its default. The listen gate had already refused its own null
    # (:4027's comment); the law now covers its siblings. To take a default,
    # REMOVE the key.
    for _k17, _v17 in cfg.items():
        if _v17 is None and _k17 in DEFAULTS and not _k17.startswith("_"):
            problems.append((_k17, "explicit null overrides the merged default -- the read sites disagree on what null means; remove the key to take the default"))
    for _i17, _sp17 in enumerate(cfg.get("backends") or []):
        if isinstance(_sp17, dict):
            for _k17, _v17 in _sp17.items():
                if _v17 is None:
                    problems.append(("backends[%d] %s.%s" % (_i17, _sp17.get("id") or "?", _k17),
                                     "explicit null in a backend spec overrides the merged global -- remove the key to inherit the default"))
    # R5-F1: top-level bool knobs speak the SAME sentence as the backend
    # loop's (SMART flags keep their own door; all three read one law).
    for _bk17 in _BOOL_KNOBS_TOP:
        _rv17 = cfg.get(_bk17)
        if _rv17 is not None and not isinstance(_rv17, bool):
            problems.append((_bk17, "must be true/false (a JSON boolean), got %r -- the string \"false\" is truthy" % (_rv17,)))
    for k, cast in _NUM_CFG.items():
        v = cfg.get(k)
        if v is None:
            continue
        if isinstance(v, bool):
            problems.append((k, "must be a number, got a boolean"))
            continue
        try:
            _fv = float(v)
        except (TypeError, ValueError):
            problems.append((k, "must be a number, got %r" % (v,)))
            continue
        # P3-6a: json.load happily produces NaN/Infinity literals, and a
        # non-finite knob is not "a number that behaves oddly" -- it is the
        # death of a comparison: status_interval=NaN makes every
        # `> _stale_after()` permanently False (the feed is NEVER stale and
        # the freshness doctrine dies silently at boot). Refuse by name,
        # mirroring the smart block's finite rule so the file speaks ONE law.
        if _fv != _fv or _fv in (float("inf"), float("-inf")):
            problems.append((k, "must be finite, got %r" % (v,)))
            continue
        if cast is int and _fv != int(_fv):
            # R4-F1 (DV-R4): the SMART_INT_KNOBS doctrine, extended to the
            # top-level int knobs -- the read sites int()-TRUNCATE whatever
            # passes, so max_body_mb 0.5 booted clean with a body cap of
            # ZERO bytes (every request with a non-empty body 413s; only
            # empty POSTs pass). "Nearly whole" is refused by
            # name; the door's cast result was discarded and nobody re-asked.
            problems.append((k, "must be a whole number -- the read site truncates it (%r silently becomes %d)" % (v, int(_fv))))
            continue
        if k in ("status_interval", "status_timeout", "connect_timeout",
                 "down_backoff", "max_body_mb", "max_connect_failures") and _fv <= 0:
            # F-A twin of the per-backend door + F-7 (DV-R3) siblings: the
            # read sites `or`-default these (max_body_mb `or 512`,
            # max_connect_failures `or 3` (R4-F2: 0 whispered through it as
            # "default 3"), down_backoff `or 20.0`), so 0 is a value the operator wrote
            # and nobody obeys; and a negative connect_timeout raises
            # ValueError from create_connection -- _proxy's ValueError catch
            # then CHARGES IT TO A HEALTHY BOX, and after
            # max_connect_failures of the operator's own typos a good box
            # is ejected (rule-4 laundering). ONE law, named at boot.
            problems.append((k, "must be > 0 -- the read site's `or` would silently re-default it (%r is not what you wrote)" % (v,)))
            continue
        if k == "read_timeout" and _fv < 0:
            # F-7: 0 is the DOCUMENTED never-time-out mode; negative is not
            # it -- sock.settimeout(-1) raises INSIDE open_connection's
            # except-pass, so every parked stream silently keeps
            # connect_timeout, under the README section that promises parked
            # streams are never cut. Refuse by name.
            problems.append((k, "must be >= 0 (0 = the documented never-time-out mode), got %r" % (v,)))
            continue
        if k == "port" and not 1 <= _fv <= 65535:
            # R4-F3: this knob has no documented zero mode. 0 binds an
            # EPHEMERAL port while the boot log swears ":0" and clients aim
            # at nothing; 70000 dies at the bind -- a raw traceback AFTER the
            # lying "listening" INFO (the file's own OS-O scar family).
            # R7b-F2: only 0 gets 0's story -- -1/70000 must not be handed the
            # wrong reason for their own number.
            if _fv == 0:
                problems.append((k, "must be 1..65535, got %r (0 would bind an ephemeral port while the log names it)" % (v,)))
            else:
                problems.append((k, "must be 1..65535, got %r" % (v,)))
            continue
        if k == "sticky_ttl" and _fv < 0:
            # R4-F2: a negative ttl makes the read site's `ttl > 0` False --
            # silently the DOCUMENTED 0 mode (never expire). 0 is that mode;
            # negative is a typo wearing its costume. (Second face this round
            # to land here independently -- corroboration, not speculation.)
            problems.append((k, "must be >= 0 (0 = the documented never-expire mode), got %r" % (v,)))
            continue
        try:
            cast(v)
        except (TypeError, ValueError, OverflowError):
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
        elif raw is not None and isinstance(raw, int) and raw < 0:
            # F-7 (DV-R3): Backend.__init__ turns ANY negative into None =
            # UNLIMITED capacity, silently -- the opposite of a typo'd -1.
            # (0 stays legal: accept-no-new-work, the drain shape.)
            problems.append((b.id + ".max_inflight",
                             "negative max_inflight silently means UNLIMITED -- omit the key if that is what you mean, got %r" % (raw,)))
        for _bk in _BOOL_KNOBS_BE:
            # R5-F1: ONE list, ONE sentence -- require_idle's law now covers
            # its unguarded sibling (b.cfg carries the merged globals, so a
            # top-level "false" is caught here per box as well).
            _rv = b.cfg.get(_bk)
            if _rv is not None and not isinstance(_rv, bool):
                problems.append((b.id + "." + _bk,
                                 "must be true/false (a JSON boolean), got %r -- the string \"false\" is truthy" % (_rv,)))
        for nk in ("status_interval",):
            # status_interval IS read per-backend (_stale_after) -- a string
            # here would crash inside stats after boot. status_timeout was
            # dropped from this door with its _KNOWN_BE_KEYS entry (DV-R3).
            raw = b.cfg.get(nk)
            if raw is None:
                continue
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                problems.append((b.id + "." + nk, "must be a number, got %r" % (raw,)))
                continue
            # F-A: the finite law admits no twin-door exemption -- this door
            # type-checked while the top-level one learned (DV-fix3) to
            # refuse non-finite. NaN is an int/float for isinstance, survives
            # `or` (bool(NaN) is True), and makes _stale_after() return NaN:
            # every age comparison for THAT BOX goes permanently False in
            # BOTH directions -- the require_idle blind-box refusal dies,
            # feed_blind never latches, homecoming's live re-ask always
            # passes. One box, silently, forever. ONE law, both doors.
            _rv = float(raw)
            if _rv != _rv or _rv in (float("inf"), float("-inf")):
                problems.append((b.id + "." + nk, "must be finite, got %r" % (raw,)))
            elif _rv <= 0:
                problems.append((b.id + "." + nk,
                                 "must be > 0 -- the read site's `or` would silently re-default it (%r is not what you wrote)" % (raw,)))
        raw = b.cfg.get("backend_api_key")
        if raw is not None and not isinstance(raw, str):
            # str() would boot `true`/123 as the WORKING key "True"/"123":
            # the keys file refused this shape since v1.2.11 -- the inline
            # config door gets the same doctrine (stress P1/F8). The VALUE
            # is never echoed (pre-1.2.18 M/TP-P3): a key-shaped field may
            # hold a real secret even when its shape is wrong.
            problems.append((b.id + ".backend_api_key",
                             "must be a JSON string, got %s -- value not echoed; a non-string never boots, not even as a cast"
                             % (type(raw).__name__,)))
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
            # same inline-door doctrine as the per-backend key above (P1/F8);
            # value never echoed -- see the M/TP-P3 note there
            problems.append((_name, "must be a JSON string, got %s -- value not echoed; a non-string never boots, not even as a cast"
                             % (type(_raw).__name__,)))
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
            if k in _MERGED_READ_KEYS:
                # F-1 (DV-R8 P2): the loop used to shout "IGNORED" about keys
                # make_pool merges into EVERY box's cfg and Backend.__init__
                # reads -- the R4-F8d probe_model lie, same lesion, caught by
                # the warning loop telling the truth one key short.
                LOG.warning("config: top-level %r is applied as a DEFAULT to EVERY backend (make_pool merges it into each box's cfg and Backend reads it); move it into the per-backend spec to steer ONE box", k)
            else:
                LOG.warning("config: unknown top-level key %r is IGNORED", k)
    # pre-1.2.18 M/TP-P2: an empty listen binds EVERY interface (0.0.0.0) while the
    # rebinding guard keeps trusting Host: localhost -- and any remote caller can send
    # that header freely (loopback names prove nothing off-loopback, the guard's own
    # comment says so). Fail closed by name instead of silently serving the world.
    # An ABSENT key means the DEFAULTS value -- build_cfg merges DEFAULTS before
    # calling -- so only an EXPLICIT empty listen is the fail-open this guard can't see.
    # pre-1.2.18 R2 (OS-O F-1/F-3): a non-string listen dies at the same door, BY TYPE
    # NAME. Passed through, str() pretends, then bind gaierrors AFTER a lying
    # "listening on http://None" INFO; int 0 is worse -- glibc parses "0" as
    # INADDR_ANY (binds every interface on Linux) while the guard's falsy branch
    # (str(0 or "")) still trusts Host: localhost: the family fix5 just closed.
    _ln_raw = cfg.get("listen", DEFAULTS["listen"])
    _ln = _ln_raw if isinstance(_ln_raw, str) else None
    if _ln is None:
        problems.append(("listen", "must be a JSON string, got %s -- it cannot name a bind "
                                   "target; write \"127.0.0.1\", or the ONE exact address "
                                   "your clients use (the rebinding guard admits only that "
                                   "Host; a wildcard bind is refused below)"
                                   % (type(_ln_raw).__name__,)))
    else:
        _ln_norm = _ln.strip().lower()
        if _ln_norm != _ln:
            # DV-R9 N-4/N-5 (P3s): ONE normalized string for ALL three read-sites
            # (this validator, the bind, the rebinding guard). " 127.0.0.1 " used to
            # pass the validator, pass the stripping guard, and die at the raw bind
            # with a gaierror traceback; "Localhost" earned a WARNING whose BOTH
            # sentences were false (the guard admits it). Writing back makes the cfg
            # carry the truth every reader shares -- same doctrine as DV-fix10's
            # _backend_ids: one truth, one read-point.
            cfg["listen"] = _ln = _ln_norm
        if ":" in _ln:
            problems.append(("listen", "must be an IPv4 address or hostname (this stdlib server is AF_INET "
                                       "only, IPv6 cannot bind); use 127.0.0.1"))
        _wv4 = None
        try:
            _wv4 = socket.inet_aton(_ln)     # the resolver's law, not hand-typed strings
        except OSError:
            pass
        if _ln == "*" or _wv4 == b"\x00\x00\x00\x00":
            # DV-R10 (R10-P5): the wildcard FAMILY is what the resolver AGREES it
            # is -- inet_aton is glibc semantics on every platform ("0.0",
            # "0.0.0", "00", "0x0" all resolve to INADDR_ANY; measured here on
            # Windows, where they then died at getaddrinfo as raw gaierrors; on
            # Linux the BIND obeys the same rules, so the old exact tuple left
            # these spellings binding the whole network in F-9a's shape).
            # Values inet_aton cannot parse and the resolver cannot resolve
            # ("0.", typos) die at the bind -- NAMED now, never as a traceback.
            # F-9a/N-3 (DV-R9, the wildcard family): binding EVERY interface while
            # the rebinding guard admits only Host == the listen STRING locks out
            # every real client -- nobody sends Host: 0.0.0.0, loopback included --
            # so the router would serve the whole network and answer everyone a 403.
            # "0" and "*" were worse: they bind NOTHING (raw gaierror traceback at
            # the bind, against the boot doctrine) while the WARNING taught callers
            # to send Host: 0. A wildcard listen is not a shape this router serves;
            # the old error texts that RECOMMENDED "0.0.0.0" were prescriptions for
            # self-lockout and are gone.
            problems.append(("listen", "%r is a WILDCARD: the rebinding guard admits only "
                                       "Host: %s, so every real caller (loopback included) "
                                       "would be 403-locked out while the port serves the "
                                       "whole network -- name the ONE address your clients "
                                       "use (e.g. the tailnet address)" % (_ln_raw, _ln)))
        if not _ln:
            problems.append(("listen", "must not be empty: an empty listen binds EVERY interface "
                                       "(0.0.0.0) while the rebinding guard still trusts Host: "
                                       "localhost, which any remote caller can send -- that leaves "
                                       "an unauthenticated key-injecting port on the network; "
                                       "write the exact address your clients will use (a wildcard "
                                       "bind is refused -- the guard would 403 every real caller)"))
    sp = cfg.get("status_paths")
    if sp is not None and (not isinstance(sp, (list, tuple)) or not sp
                           or not all(isinstance(x, str) and x.startswith("/") for x in sp)):
        problems.append(("status_paths", "must be a non-empty list of paths starting with '/', got %r "
                                         "-- a bare string would poll one CHARACTER at a time" % (sp,)))
    # pre-1.2.18 M/TP-P2: the old `or "127.0.0.1"` made an empty listen look loopback and
    # muted this warning on the one value that binds everything -- empty warns too.
    # A non-string listen is refused above; it never gets a warning naming a phantom Host.
    # DV-R9 N-5: `_ln` is the NORMALIZED string written back above -- this loopback test
    # now agrees with the guard's (also-normalized) view, so "Localhost" earns no false
    # "admits ONLY Host: Localhost / IS NOT loopback" sentence.
    # DV-R11 C-4 (L1b P3): the firewall sermon MOVED off this line. It used to
    # print HERE -- before the bind -- so an unresolvable listen got "Firewall
    # this port" advice for a port that would never exist (r11a live: sermon
    # line, then the named death). R4-F3's bind-first doctrine covers WORDS
    # too: main() prints the sermon only after the bind SUCCEEDED. The
    # normalizing write-back above stays the single source; the value's
    # loopback status is tested where it is spoken, against this same triple.
    # ---- smart ladder section (design v4.1 S9/S-1) ------------------------
    _sm_sec = cfg.get("smart")
    if _sm_sec is not None:
        if not isinstance(_sm_sec, dict):
            problems.append(("smart", "must be an object of smart.* knobs, got %s"
                             % (type(_sm_sec).__name__,)))
        else:
            for fk in SMART_FLAGS:
                v = _sm_sec.get(fk)
                if v is not None and not isinstance(v, bool):
                    problems.append(("smart." + fk,
                                     "must be true/false (a JSON boolean), got %r -- the string \"false\" is truthy" % (v,)))
            for nk in SMART_NUMS:
                v = _sm_sec.get(nk)
                if v is None:
                    continue
                if isinstance(v, bool):
                    problems.append(("smart." + nk, "must be a number, got a boolean"))
                    continue
                try:
                    f = float(v)
                except (TypeError, ValueError):
                    problems.append(("smart." + nk, "must be a number, got %s" % (type(v).__name__,)))
                    continue
                if f != f or f in (float("inf"), float("-inf")):
                    problems.append(("smart." + nk, "must be finite, got %r" % (v,)))
                elif nk == "k_eps":
                    if f < 0:
                        problems.append(("smart.k_eps", "must be >= 0 (it is a tolerance), got %r" % (v,)))
                elif f <= 0:
                    problems.append(("smart." + nk, "must be > 0, got %r" % (v,)))
                elif nk in SMART_INT_KNOBS and f != int(f):
                    # F15: a tick counter is not a dial -- the read sites int()
                    # these, so a fraction is an operator lie that silently
                    # truncates (window_n 2.7 would run as 2). Refuse by name.
                    problems.append(("smart." + nk,
                                     "is a tick counter/minimum -- whole numbers only, got %r" % (v,)))
                elif nk == "release_gate_shadow_cycles" and f > 32:
                    # P3-2: the gate reads the last 32 completed cycles -- a
                    # knob above the ledger is a gate that can NEVER open.
                    # The move-alone row promises lockouts that SAY SO; a
                    # boot-time lockout refuses boot by name instead.
                    problems.append(("smart." + nk,
                                     "above the 32-cycle ledger -- the release gate could never open, got %r" % (v,)))
            for k in _sm_sec:
                if k not in SMART_FLAGS and k not in SMART_NUMS:
                    LOG.warning("smart: unknown knob %r is IGNORED -- knobs never guess a spelling", k)
            if _sm_sec.get("smart_place") or _sm_sec.get("smart_move"):
                # S-1: J costs divide by k_b; an undeclared max_inflight makes
                # k_b the attractive lie "infinite capacity". Refuse boot by
                # name -- never substitute a silent cap for an absent promise.
                for b in pool.backends:
                    if b.max_inflight is None:
                        problems.append((b.id + ".max_inflight",
                                         "S-1: smart_place/smart_move need every box to declare max_inflight -- k_b would be unbounded"))
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
    probe_mode = cfg.pop("_probe", False)
    logging.basicConfig(
        level=getattr(logging, str(cfg.get("log_level", "INFO")).upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    if set_target:
        return set_key(cfg, set_target, config_path, keys_path)
    if probe_mode:
        return probe(cfg)

    pool = make_pool(cfg)
    validate_cfg(cfg, pool, strict=True)
    Handler.pool = pool
    Handler.cfg = cfg
    for b in pool.backends:
        src = (cfg.get("_key_sources") or {}).get(b.id) or ("global fallback" if b.api_key else "none")
        LOG.info("backend %s -> %s:%s%s  key=%s%s", b.id, b.host, b.port, b.prefix or "",
                 "yes" if b.api_key else "none", " (" + src + ")" if b.api_key else "")
    # R4-F3: bind FIRST -- this file named its own scar ("bind gaierrors
    # AFTER a lying 'listening' INFO", the listen-knob gate's comment); the
    # same family was live here: a bad port logged "listening", started the
    # poller, and only then died at the bind. If the bind fails, nothing was
    # claimed and no sentence lied.
    try:
        httpd = Router((str(cfg["listen"]), int(cfg["port"])), Handler)
    except OSError as _be:
        # DV-R10 (R10-P5): a listen the resolver cannot place ("0.", typos,
        # dead names) is a BOOT DEATH with a name, not an unhandled gaierror
        # the operator reads as a crash -- the doctrine every other boot door
        # already honors (S21/N-3: "dies NAMED, no traceback").
        print("router: listen %r port %s could not be resolved or bound (%s: %s) -- refusing boot; "
              "name the ONE address your clients use (wildcards and their inet_aton shorthands are refused by name at the config door)"
              % (cfg["listen"], cfg["port"], type(_be).__name__, _be), file=sys.stderr)
        return 1
    # DV-R11 C-4: the firewall sermon speaks only where the port EXISTS --
    # after the bind succeeded (it used to fire inside validate_cfg, before
    # this try: an unresolvable listen got firewall advice for a port that
    # never came up). Same text, same triple as the guard's loopback view;
    # validate_cfg wrote the normalized listen back, so this reads the ONE
    # truth the guard also reads.
    _ln_firewall = str(cfg["listen"])
    if _ln_firewall not in ("127.0.0.1", "localhost", "::1"):
        LOG.warning(
            "listen=%s is NOT loopback: this router has no auth of its own and injects "
            "backend keys for callers that send none. Firewall this port to known peers now. "
            "The rebinding guard admits ONLY Host: %s (loopback names prove nothing off-loopback) "
            "-- and gate the control surface: --set-key control.",
            _ln_firewall, _ln_firewall,
        )
    LOG.info(
        "listening on http://%s:%s -- affinity+least-queued passthrough, no rate limiting, "
        "queue stays in the backends", cfg["listen"], cfg["port"],
    )
    LOG.info("client read timeout: %s",
             resolve_read_timeout(cfg.get("read_timeout")) or "disabled")
    LOG.info("control surface: %s",
             "GATED -- x-strata-pin and sticky/clear require x-strata-control"
             if cfg.get("_control_token") else
             "open to local callers (any local process: pin lanes, clear affinity). "
             "Gate it with: python router.py --set-key control")

    StatusPoller(pool, cfg).start()

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
