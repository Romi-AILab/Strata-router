#!/usr/bin/env python3
"""
End-to-end checks for strata-router against two fake boxes that behave like
Strata with "parallel" OFF: one request at a time, everyone else waits in the
server FIFO. A NON-streaming wait is silent; a STREAMING one emits Strata's
": keep-alive" comments (the slow-stream fake route), because that is exactly
the behavior a fill-read relay would destroy. That wait is the thing a proxy
usually breaks with a read timeout or a home-made 429, so it is simulated
faithfully here.

The four rules under test:
  1 passthrough  -- SSE event names, thinking/tool_use blocks, cache_control,
                     Retry-After and status codes all arrive intact
  2 queue        -- a request parked behind another one waits and succeeds;
                     the router never invents a 429; a backend 429 is relayed
  3 affinity     -- one conversation stays on one box, its key is stable as the
                     transcript grows, and new work avoids the box with queue depth
  4 failover     -- only connection failure removes a box; its conversations
                     migrate and the survivor keeps answering

    python smoke_test.py
"""
from __future__ import annotations

import http.client
import json
import logging
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:                     # M2-A/P1-3: check() 的紅字 detail 可能含 CJK fixture,
    sys.stdout.reconfigure(errors="replace")   # cp950/Big5 控制台只能印成 mojibake,
    sys.stderr.reconfigure(errors="replace")   # 絕不許把 summary 與 verdict 一起吞掉
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROUTER = os.path.join(HERE, "router.py")
sys.path.insert(0, HERE)
import router as R  # noqa: E402  -- direct import for startup-validation unit checks

# RED LINE, and it is load-bearing: a router booted WITHOUT --config anchors
# the keys-file default to the CURRENT DIRECTORY. Smoke may be launched from
# anywhere (repo root, router/, any friend folder) and any of those cwds can
# be a live deployment whose router.keys.json is its working keyring -- every
# subprocess boot and every in-process apply_keys(cfg, None) below would
# silently READ that file. Anchor all of it in a private temp dir first.
# (Wording per M2-B/P3-3; the chdir itself is untouched and stays load-bearing.)
os.chdir(tempfile.mkdtemp(prefix="strata-smoke-cwd-"))

ROUTER_PORT, ROUTER2_PORT, ROUTER3_PORT, ROUTER4_PORT, A_PORT, B_PORT, C_PORT, D_PORT = \
    9199, 9196, 9195, 9194, 9197, 9198, 9192, 9191
ROUTER5_PORT, E_PORT, F_PORT, G_PORT = 9190, 9189, 9188, 9187
P_PROBE_PORT = 9186  # dedicated fake for the --probe honesty guards (v1.2.9)
RW_FAKE, RW_ROUTER, TOK_ROUTER, LAN_ROUTER = 9182, 9183, 9184, 9185  # v1.2.10 L2-2 guards
GH_A, GH_B, GH_ROUTER = 9181, 9180, 9179                              # v1.2.11 L2-3 guards
LIE_FAKE, LIE_ROUTER = 9178, 9177                                     # v1.2.12 stress-P1 guards

FAILS, CHECKS = [], []
FAKE_ERRORS = []          # last swallowed FakeStrata tracebacks (see handle_error)


def check(label, cond, detail=""):
    (CHECKS if cond else FAILS).append(label + ((" -- " + detail) if detail and not cond else ""))
    print(("  PASS  " if cond else "  FAIL  ") + label + (("  [" + detail + "]") if detail and not cond else ""))


class FakeStrata:
    """Enough of the Strata surface for the router: OpenAI+Anthropic endpoints,
    /v1/status load reporting, and -- with serial=True -- one-slot service with
    a real FIFO in front of it."""

    def __init__(self, port, box_id, hold=0.0, serial=False, deny_count_tokens=False):
        self.port, self.box_id = port, box_id
        self.hold = hold                       # seconds of "prompt read" per request
        self.serial = serial                   # one request at a time, like parallel=off
        self.deny_count_tokens = deny_count_tokens
        self.always_429 = False
        self.force_load = None    # when set, the status endpoints return exactly this
        self.blind = False        # when True, status endpoints answer 500 (mid-update box)
        self.lie = False          # when True, GET /v1/lie answers with RAW smuggled framing
                                  # (v1.2.12, stress P1/F1: bare-CR split + CORS passthrough)
        self.require_key = None   # when set, every endpoint demands this exact key
        self.seen_auths = []      # every auth header ever received (endpoint or poll)
        self.seen_controls = []   # every x-strata-control ever received (must stay EMPTY -- L2-3/M1)
        self.seen_hdr_names = []  # header NAMES of each POST served (v1.2.13 Q2/F4:
                                  # junk names must never ride the request path in)
        self.hang_seen_at = None  # when the hang-stream route saw ITS client (the router) hang up
        self.beat_lag_s = 0.0     # after a hangup, keep COUNTING the dead request
                                  # this long -- real Strata notices a parked
                                  # stream only at its next keep-alive beat
        self.gate = threading.Semaphore(1 if serial else 1000)
        self.lock = threading.Lock()
        self.arriving = 0                      # requests inside the box (queued + serving)
        self.busy = 0                          # requests actually decoding
        self.httpd = None

    def load(self):
        if self.force_load is not None:
            return self.force_load
        with self.lock:
            arriving = self.arriving
        # Strata's real /v1/status schema, decoys included: concurrency.serving
        # is the slot COUNT (capacity), the vram section reports MiB numbers --
        # the router must read activity.in_flight (running + waiting) and never
        # let a capacity field outrank it.
        return {"concurrency": {"serving": 1 if self.serial else 16, "requested": 1 if self.serial else 16},
                "activity": {"requests": 0, "in_flight": arriving, "last_request_at": None},
                "vram": {"reserve_mib": 700, "expert_slots": 1200, "expert_cache_mib": 1536, "elastic": True}}

    def start(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):
                pass

            def _key_state(self):
                # distinguish MISSING from WRONG so a test can tell "no key was
                # injected" apart from "a different key was injected"
                outer.seen_auths.append(self.headers.get("authorization") or self.headers.get("x-api-key") or "")
                outer.seen_controls.append(self.headers.get("x-strata-control"))
                if outer.require_key is None:
                    return "ok"
                auth = self.headers.get("authorization") or ""
                given = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
                given = given or (self.headers.get("x-api-key") or "")
                if not given:
                    return "missing"
                return "ok" if given == outer.require_key else "wrong"

            def _key_ok(self):
                return self._key_state() == "ok"

            def _deny(self):
                return self._send(401, ('{"error":{"type":"authentication_error","message":"%s API key"}}'
                                        % self._key_state()).encode())

            def _send(self, code, body, ctype="application/json", extra=None):
                self.send_response(code)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("content-type", ctype)
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()

            def do_GET(self):
                if not self._key_ok():
                    return self._deny()
                if outer.lie and self.path == "/v1/lie":
                    # RAW response, no http.server framing: a bare CR splits
                    # X-Box into two headers for http.client (it rebuilds them
                    # clean -- indistinguishable downstream), and the CORS
                    # header is the one relayed shape a browser could read
                    # through. The router must strip CORS and keep the wire.
                    self.wfile.write(
                        b"HTTP/1.1 200 OK\r\nX-Box: yes\rX-Injected: yes\r\n"
                        b"access-control-allow-origin: http://evil.test\r\n"
                        b"content-type: application/json\r\ncontent-length: 2\r\n\r\n{}")
                    self.wfile.flush()
                    self.close_connection = True
                    return
                if outer.lie and self.path == "/v1/lieline":
                    # v1.2.13, stress Q1/Q2A-1: the reason PHRASE is written
                    # verbatim into the status line by send_response, so a CR
                    # inside it is a second line to WHATWG-fetch parsers --
                    # a forged header riding ABOVE every header-side filter.
                    self.wfile.write(
                        b"HTTP/1.1 200 ok\rAccess-Control-Allow-Origin: http://evil.test\r\n"
                        b"content-type: application/json\r\ncontent-length: 2\r\n\r\n{}")
                    self.wfile.flush()
                    self.close_connection = True
                    return
                if outer.lie and self.path == "/v1/liect":
                    # R6-C/P3-1 (v1.2.17): NUL smuggled INSIDE the content-type
                    # value -- the one header the router skips in the sanitized
                    # relay loop and rebuilds from getheader afterwards, so
                    # that reattach gate must sanitize too. RAW write keeps the
                    # \x00 exactly as a lying box's socket would send it.
                    self.wfile.write(
                        b"HTTP/1.1 200 OK\r\nx-nul: a\x00b\r\n"
                        b"content-type: text/plain; q\x00z=1\r\ncontent-length: 2\r\n\r\n{}")
                    self.wfile.flush()
                    self.close_connection = True
                    return
                if self.path == "/v1/status":
                    if outer.blind:
                        return self._send(500, b'{"error":"updating"}')
                    return self._send(200, json.dumps(outer.load()).encode())
                if self.path == "/metrics":
                    if outer.blind:
                        return self._send(500, b"unavailable 1\n", "text/plain")
                    with outer.lock:
                        bus, arr = outer.busy, outer.arriving
                    # Strata's /metrics in Prometheus form (llama.cpp names):
                    # processing = running, deferred = waiting for the turn
                    return self._send(200, ("llamacpp:requests_processing %d\nllamacpp:requests_deferred %d\n"
                                            % (bus, max(0, arr - bus))).encode(), "text/plain")
                if self.path in ("/v1/models", "/models"):
                    return self._send(200, json.dumps({"object": "list", "data": [{"id": "test-model"}]}).encode())
                return self._send(404, b'{"error":"nope"}')

            def do_POST(self):
                if not self._key_ok():
                    return self._deny()
                with outer.lock:
                    outer.arriving += 1
                try:
                    self._handle()
                finally:
                    with outer.lock:
                        outer.arriving -= 1

            def _handle(self):
                n = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(n) if n else b""
                obj = json.loads(raw.decode()) if raw else {}
                outer.seen_hdr_names.append([k.lower() for k in self.headers.keys()])

                if outer.lie and self.path == "/v1/big":
                    # v1.2.13, stress Q1/Q2A-7: a header line past http.client's
                    # 64 KB cap makes the ROUTER's getresponse raise LineTooLong
                    # -- the box DID answer, in framing nobody should parse.
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Big: " + b"A" * 100000 +
                                     b"\r\ncontent-length: 2\r\n\r\n{}")
                    self.wfile.flush()
                    self.close_connection = True
                    return

                if self.path.endswith("/responses"):
                    # OpenAI Responses API, what Codex actually speaks
                    return self._send(200, json.dumps({
                        "id": "resp_" + outer.box_id, "object": "response", "status": "completed",
                        "model": obj.get("model"),
                        "output": [{"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "thinking on " + outer.box_id}]},
                                   {"type": "message", "id": "msg_1", "role": "assistant", "content": [{"type": "output_text", "text": "ok", "annotations": []}]}],
                        "usage": {"input_tokens": 11, "output_tokens": 3},
                    }).encode())

                if self.path.endswith("/count_tokens"):
                    if outer.deny_count_tokens:
                        return self._send(404, b'{"error":{"message":"not implemented"}}')
                    return self._send(200, b'{"input_tokens":123}')
                if outer.always_429:
                    # exactly what Strata does once an admission cap + queue timeout is on
                    return self._send(429, b'{"error":{"type":"rate_limit_error","code":"queue_wait_timeout"}}',
                                      extra={"retry-after": "1"})

                if obj.get("model") == "stall":
                    # (v1.2.11, review L2-3/M2) parked WITHOUT first byte --
                    # the exact shape a read-timeout abandons: the router is
                    # gone but we keep COUNTING the request like real Strata
                    # does until its next beat would notice.
                    time.sleep(4.0)
                    try:
                        self._send(200, b'{"id":"stalled","model":"stall"}')
                    except OSError:
                        pass
                    return

                if obj.get("model") == "slow-stream":
                    # what real Strata does with a STREAM parked behind the
                    # single turn (server.py QUEUE_BEAT_S=10): the 200 + SSE
                    # headers are already out and a ": keep-alive" comment
                    # trickles every ~10 s (0.5 s here) while the stream stays
                    # open. The relay must carry it through LIVE -- a fill-read
                    # buffers everything to EOF and the client sees nothing.
                    self.send_response(200)
                    self.send_header("content-type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    time.sleep(0.5)
                    self.wfile.write(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
                    self.wfile.flush()
                    return

                if obj.get("model") == "hang-stream":
                    # A long parked stream that pings for up to 10 s. The fake
                    # watches ITS client (the router) with MSG_PEEK -- exactly
                    # real Strata's _watch_client -- so the test can measure
                    # whether a hung-up CALLER actually releases the box.
                    self.send_response(200)
                    self.send_header("content-type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    _t = time.monotonic()
                    while time.monotonic() - _t < 10.0:
                        try:
                            _r, _, _ = select.select([self.connection], [], [], 0.25)
                            if _r and self.connection.recv(1, socket.MSG_PEEK) == b"":
                                outer.hang_seen_at = time.monotonic()   # the router hung up on us
                                time.sleep(min(outer.beat_lag_s, 10.0))  # dead until the beat notices
                                return
                        except (ConnectionError, OSError, ValueError):
                            outer.hang_seen_at = time.monotonic()
                            time.sleep(min(outer.beat_lag_s, 10.0))
                            return
                        try:
                            self.wfile.write(b": keep-alive\n\n")
                            self.wfile.flush()
                        except OSError:
                            return
                    return

                if obj.get("model") == "die-midway":
                    # The box dies WHILE PARKING the request -- never a first
                    # byte, then the connection itself goes away (the friend
                    # closing their laptop mid-queue). The request reached the
                    # box, so this is a stall (rule 4: no eject, no retry
                    # invitation), and the overflow's provisional re-home must
                    # fizzle -- not linger to landmine the lane's next turn.
                    time.sleep(1.0)
                    try:
                        self.connection.close()
                    except OSError:
                        pass
                    return

                # the FIFO: wait for the single slot, then decode. Nothing is sent
                # to the client while waiting, which is what breaks naive proxies.
                got = outer.gate.acquire(timeout=60)
                if not got:
                    return self._send(503, b'{"error":"gate"}')
                with outer.lock:
                    outer.busy += 1
                try:
                    if outer.hold:
                        time.sleep(outer.hold)
                    self.send_response(200)
                    self.send_header("content-type", "text/event-stream")
                    self.end_headers()
                    events = [
                        {"type": "message_start", "message": {"id": "msg_1", "role": "assistant", "model": "test-model", "usage": {"input_tokens": 7, "output_tokens": 1}}},
                        {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "hmm " + outer.box_id}},
                        {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "x"}},
                        {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "tu_1", "name": "exec_command", "input": {}}},
                        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"cmd\":\"ls\"}"}},
                        {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 4}},
                        {"type": "message_stop"},
                    ]
                    for e in events:
                        self.wfile.write(("event: " + e["type"] + "\ndata: " + json.dumps(e) + "\n\n").encode())
                        self.wfile.flush()
                        time.sleep(0.02)
                finally:
                    with outer.lock:
                        outer.busy -= 1
                    outer.gate.release()

        class S(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True
            # request_queue_size was raised to 256 chasing the ~0.5% reset
            # flakes -- WORSE. Backlog 5 RSTs the overflow connection in ms
            # (poll fails, poller retries next tick, nobody notices); a deep
            # queue holds those connections UNREAD instead, and one stalled
            # poll blocks the poller's whole tick (status_timeout 3s), making
            # every box look blind at once -- tier placement flips to the
            # peer on a bench race. The default stays; the flakes live in the
            # TCP stack, and the checks that could get bitten re-ask once.

            def handle_error(self, *a):
                # Swallow the noise (client aborts are constant on this bench)
                # but never swallow the EVIDENCE: the last 50 tracebacks live
                # in FAKE_ERRORS for the repro loops and the suite footer to
                # read. A silent swallow made the 1-in-300 reset invisible for
                # three rounds of chasing.
                try:
                    import traceback as _tb
                    FAKE_ERRORS.append("".join(_tb.format_exception(*sys.exc_info()))[:400])
                    while len(FAKE_ERRORS) > 50:
                        FAKE_ERRORS.pop(0)
                except Exception:
                    pass

        self.httpd = S(("127.0.0.1", self.port), H)
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def kill(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass


def call(port, path, body, extra=None, timeout=60.0):
    """POST a Messages request; returns (status, headers, raw_body, wall_seconds)."""
    data = json.dumps(body).encode()
    hdrs = {"content-type": "application/json", "x-api-key": "strata-local"}
    for k, v in (extra or {}).items():
        if v is None:
            hdrs.pop(k, None)
        else:
            hdrs[k] = v
    t0 = time.monotonic()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.request("POST", path, body=data, headers=hdrs)
    r = conn.getresponse()
    chunks = []
    while True:
        b = r.read(8192)
        if not b:
            break
        chunks.append(b)
    out = b"".join(chunks).decode("utf-8", "replace")
    got = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return r.status, got, out, round(time.monotonic() - t0, 2)


def get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15.0)
    conn.request("GET", path)
    r = conn.getresponse()
    body = r.read().decode()
    conn.close()
    return r.status, body


def stats(port):
    return json.loads(get(port, "/__router/stats")[1])


def conv(tag, turns=1):
    msgs = [{"role": "user", "content": "conversation " + tag + " turn 1"}]
    for i in range(2, turns + 1):
        msgs.append({"role": "assistant", "content": "answer " + str(i)})
        msgs.append({"role": "user", "content": "conversation " + tag + " turn " + str(i)})
    return {
        "model": "test-model",
        "max_tokens": 16,
        "system": [{"type": "text", "text": "You are a coding agent.", "cache_control": {"type": "ephemeral", "ttl": "1h"}}],
        "tools": [{"name": "exec_command", "description": "run", "input_schema": {"type": "object"}}],
        "metadata": {"user_id": json.dumps({"session_id": "sess-" + tag})},
        "messages": msgs,
    }


def wait_for(cond, timeout=25.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


def _term(p):
    """Terminate a lab router Popen. Windows reclaims a dead child's handle
    under us sometimes (WinError 6 seen at suite teardown, twice) -- and a
    crash at teardown swallows the suite's VERDICT, which is worse than the
    race. A handle already gone is the state terminate() wanted anyway."""
    try:
        p.terminate()
    except OSError:
        pass


def spawn(fn, *a):
    box = {}

    def run():
        try:
            box["r"] = fn(*a)
        except Exception as exc:
            box["err"] = repr(exc)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, box


def main():
    # both boxes identical, like the real setup: same model, same config,
    # parallel OFF (one slot, FIFO in front)
    a = FakeStrata(A_PORT, "a", hold=0.55, serial=True)
    b = FakeStrata(B_PORT, "b", hold=0.55, serial=True, deny_count_tokens=True)
    a.start()
    b.start()
    proc = subprocess.Popen(
        [sys.executable, ROUTER,
         "--backend", "a=http://127.0.0.1:%d" % A_PORT,
         "--backend", "b=http://127.0.0.1:%d" % B_PORT,
         "--listen", "127.0.0.1", "--port", str(ROUTER_PORT),
         "--max-connect-failures", "2", "--down-backoff", "2",
         "--status-interval", "0.2", "--log-level", "WARNING"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        check("router starts and /healthz is green",
              wait_for(lambda: get(ROUTER_PORT, "/healthz")[0] == 200, 20))

        print("")
        print("1) passthrough -- nothing is translated")
        st, h, body, _ = call(ROUTER_PORT, "/v1/messages", conv("alpha"))
        check("Anthropic SSE stream arrives intact", st == 200 and "event: message_stop" in body and "thinking_delta" in body, "status=%s %s" % (st, body[:100]))
        check("tool_use / input_json_delta preserved", '"input_json_delta"' in body and "exec_command" in body)
        check("thinking block preserved", '"type": "thinking"' in body)
        check("chosen box and placement exposed", h.get("x-strata-backend") in ("a", "b") and h.get("x-strata-placement") == "placed", str(h))
        st2, body2 = get(ROUTER_PORT, "/v1/models")
        check("GET /v1/models passes through", st2 == 200 and "test-model" in body2, body2[:60])

        # Codex: Responses API, no metadata.user_id, so the conversation has to be
        # recognised from its stable prompt prefix instead
        resp_body = {"model": "test-model", "input": [{"role": "user", "content": "codex task 42"}],
                     "tools": [{"type": "function", "name": "exec_command"}]}
        st5, h5, b5, _ = call(ROUTER_PORT, "/v1/responses", resp_body)
        j5 = json.loads(b5) if b5.startswith("{") else {}
        check("Responses API passes through untranslated", st5 == 200 and j5.get("object") == "response" and "reasoning" in b5, "status=%s %s" % (st5, b5[:90]))
        grew = dict(resp_body)
        grew["input"] = resp_body["input"] + [{"type": "function_call", "name": "exec_command", "arguments": "{}"},
                                              {"role": "user", "content": "keep going"}]
        st6, h6, b6, _ = call(ROUTER_PORT, "/v1/responses", grew)
        check("without metadata, the prompt prefix pins the conversation",
              h5.get("x-strata-affinity", "").startswith("prefix:") and h6.get("x-strata-backend") == h5.get("x-strata-backend"),
              "%s on %s then %s on %s" % (h5.get("x-strata-affinity"), h5.get("x-strata-backend"), h6.get("x-strata-affinity"), h6.get("x-strata-backend")))
        other = dict(resp_body)
        other["input"] = [{"role": "user", "content": "a different codex task 43"}]
        st7, h7, _b7, _ = call(ROUTER_PORT, "/v1/responses", other)
        check("a different first input is a different conversation", h7.get("x-strata-affinity") != h5.get("x-strata-affinity"), str(h7.get("x-strata-affinity")))

        print("")
        print("3) affinity -- one conversation, one box")
        picks = [call(ROUTER_PORT, "/v1/messages", conv("alpha", turns=3))[1].get("x-strata-backend") for _ in range(4)]
        check("same conversation pinned to one box across turns", len(set(picks)) == 1, str(picks))
        k1 = call(ROUTER_PORT, "/v1/messages", conv("beta"))[1].get("x-strata-affinity")
        k2 = call(ROUTER_PORT, "/v1/messages", conv("beta", turns=5))[1].get("x-strata-affinity")
        check("affinity key from metadata.user_id is stable as the transcript grows",
              bool(k1) and k1.startswith("meta:") and k1 == k2, "%s vs %s" % (k1, k2))

        # lanes: one SESSION id (metadata.user_id) carries many parallel
        # branches (Claude Code subagents share it). The session is only the
        # SCOPE; the first-turn hash makes each branch its own lane --
        # otherwise every subagent queues behind the session's single sticky
        # box while the second box idles (observed in production).
        _l1 = conv("shared-session")
        _l2 = conv("shared-session")
        _l2["messages"][0]["content"] = "conversation shared-session BRANCH-2 task 1"
        _s1, h_l1, _b1, _w = call(ROUTER_PORT, "/v1/messages", _l1)
        _s2, h_l2, _b2, _w = call(ROUTER_PORT, "/v1/messages", _l2)
        check("same session id + different first turn = separate lanes",
              h_l1.get("x-strata-affinity") != h_l2.get("x-strata-affinity")
              and h_l1.get("x-strata-affinity", "").startswith("meta:")
              and "/prefix:" in h_l1.get("x-strata-affinity", ""),
              "%s vs %s" % (h_l1.get("x-strata-affinity"), h_l2.get("x-strata-affinity")))
        _l2g = json.loads(json.dumps(_l2))
        _l2g["messages"] += [{"role": "assistant", "content": "x"},
                             {"role": "user", "content": "branch-2 turn 2"}]
        _s3, h_l2b, _b3, _w = call(ROUTER_PORT, "/v1/messages", _l2g)
        check("a lane keeps its box across its own turns (sticky, lane-level)",
              h_l2b.get("x-strata-placement") == "sticky"
              and h_l2b.get("x-strata-backend") == h_l2.get("x-strata-backend"),
              "%s/%s" % (h_l2b.get("x-strata-backend"), h_l2b.get("x-strata-placement")))
        got, cthr = [], []

        def fire(i):
            _st, hh, _bb, _w = call(ROUTER_PORT, "/v1/messages", conv("conc-%d" % i))
            got.append(hh.get("x-strata-backend"))

        for i in range(4):
            tt = threading.Thread(target=fire, args=(i,), daemon=True)
            tt.start()
            cthr.append(tt)
        for tt in cthr:
            tt.join(90)
        check("4 concurrent conversations spread over both boxes", set(got) == {"a", "b"}, str(got))

        print("")
        print("2) queue -- a request parked behind another one waits, it does not fail")
        parked = []

        def park(i):
            st, hh, bb, wall = call(ROUTER_PORT, "/v1/messages", conv("park-%d" % i), extra={"x-strata-pin": "a"})
            parked.append((st, wall, "message_stop" in bb, hh.get("x-strata-placement")))

        threads = []
        for i in range(3):
            t = threading.Thread(target=park, args=(i,), daemon=True)
            t.start()
            threads.append(t)
        # sample WHILE all three are inside the box: the during-load call below
        # waits out one hold, by which time the first parked request is gone
        maxbox, maxin = 0, 0
        for _ in range(8):
            bx = {x["id"]: x for x in stats(ROUTER_PORT)["backends"]}
            maxbox = max(maxbox, bx["a"]["reported"].get("serving") or 0)   # Strata activity.in_flight = running + waiting
            maxin = max(maxin, bx["a"]["inflight"])
            time.sleep(0.1)
        stq, hq, bq, wallq = call(ROUTER_PORT, "/v1/messages", conv("during-load"))
        check("new work routes around the box that is queueing", hq.get("x-strata-backend") == "b", "landed on %s" % hq.get("x-strata-backend"))
        for t in threads:
            t.join(90)
        check("router accounted for the full queue depth", max(maxin, maxbox) >= 3, "inflight=%s box in_flight=%s" % (maxin, maxbox))
        check("router read the backend's own load report (activity.in_flight)", maxbox >= 3, str(maxbox))
        check("queued requests all completed -- none dropped, none refused", len(parked) == 3 and all(x[0] == 200 and x[2] for x in parked), str(parked))
        waits = [x[1] for x in parked]
        check("they really waited behind a single slot",
              min(waits) >= 0.6 and max(waits) >= 1.4 and max(waits) - min(waits) >= 0.6, str(waits))
        bx = {x["id"]: x for x in stats(ROUTER_PORT)["backends"]}
        # the wait must surface as TIME, not as an error. The box-wide avg_ttfb
        # is a rolling mix of every stream this run (the fast count_tokens 200s
        # dilute it) -- asserted as a soft floor only; the hard signal is
        # last_ttfb: the parked request is the freshest stream on the pinned box,
        # so its 1.4-2.2 s wait lands there deterministically (T4 flake fix).
        check("the wait is visible as time-to-first-byte, not as an error",
              (bx["a"]["avg_ttfb_s"] or 0) >= 0.4 and (bx["a"]["stats"]["last_ttfb"] or 0) >= 0.9,
              json.dumps({k: (v["avg_ttfb_s"], v["stats"]["last_ttfb"]) for k, v in bx.items()}))
        r0 = stats(ROUTER_PORT)["router"]
        check("explicit pin honoured", r0.get("pinned", 0) >= 3, json.dumps(r0)[:160])
        stz, hz, bz, _ = call(ROUTER_PORT, "/v1/messages", conv("badpin"), extra={"x-strata-pin": "ghost"})
        check("pin to an unknown box falls back instead of failing", stz == 200 and hz.get("x-strata-backend") in ("a", "b"), "status=%s box=%s" % (stz, hz.get("x-strata-backend")))

        a.always_429 = b.always_429 = True
        st4, h4, b4, _ = call(ROUTER_PORT, "/v1/messages", conv("pushback"))
        check("backend 429 relayed verbatim; the router adds none", st4 == 429 and "queue_wait_timeout" in b4, "status=%s %s" % (st4, b4[:80]))
        check("Retry-After and backend id survive the relay", h4.get("retry-after") == "1" and h4.get("x-strata-backend") in ("a", "b"), str(h4)[:120])
        bx = {x["id"]: x for x in stats(ROUTER_PORT)["backends"]}
        check("busy boxes stay healthy after 429s", all(x["state"] == "healthy" for x in bx.values()), json.dumps({k: v["state"] for k, v in bx.items()}))
        a.always_429 = b.always_429 = False

        before = stats(ROUTER_PORT)["router"]["count_tokens_synthesized"]
        stc, hc, bc, _ = call(ROUTER_PORT, "/v1/messages/count_tokens", conv("gamma"), extra={"x-strata-pin": "b"})
        after = stats(ROUTER_PORT)["router"]["count_tokens_synthesized"]
        check("count_tokens synthesized when the box 404s it", stc == 200 and "input_tokens" in bc and after == before + 1, "status=%s %s" % (stc, bc[:60]))
        stc2, _, bc2, _ = call(ROUTER_PORT, "/v1/messages/count_tokens", conv("gamma2"), extra={"x-strata-pin": "a"})
        check("count_tokens passed through when the box implements it", stc2 == 200 and '"input_tokens":123' in bc2.replace(" ", ""), bc2[:60])

        print("")
        print("4) failover -- only connection failure removes a box")
        home = call(ROUTER_PORT, "/v1/messages", conv("alpha"))[1].get("x-strata-backend")
        victim, survivor = (a if home == "a" else b), (b if home == "a" else a)
        victim.kill()
        check("dead box detected from connection errors",
              wait_for(lambda: {x["id"]: x for x in stats(ROUTER_PORT)["backends"]}[victim.box_id]["state"] == "down", 25))
        st2, h2, b2, _ = call(ROUTER_PORT, "/v1/messages", conv("alpha"))
        check("the conversation keeps working after failover", st2 == 200 and "message_stop" in b2, "status=%s" % st2)
        check("its turns migrated to the survivor", h2.get("x-strata-backend") == survivor.box_id, str(h2.get("x-strata-backend")))
        check("the move is labelled migrated", h2.get("x-strata-placement") == "migrated", str(h2.get("x-strata-placement")))
        sth, hb = get(ROUTER_PORT, "/healthz")
        check("/healthz green while one box survives", sth == 200, hb[:100])
        st3, h3, b3, _ = call(ROUTER_PORT, "/v1/messages", conv("alpha"))
        check("migrated conversation stays on the survivor (no ping-pong)", h3.get("x-strata-backend") == survivor.box_id, str(h3.get("x-strata-backend")))

        print("")
        print("recovery")
        back = FakeStrata(victim.port, victim.box_id, hold=0.55, serial=True)
        back.start()
        if victim.box_id == "a":
            a = back          # the live server on A_PORT is now `back`, not `a`
        else:
            b = back
        check("dead box rejoins by itself (status-poller recovery; the one-slot trial is phase 7)",
              wait_for(lambda: {x["id"]: x for x in stats(ROUTER_PORT)["backends"]}[victim.box_id]["state"] != "down", 30))
        st4, h4, b4, _ = call(ROUTER_PORT, "/v1/messages", conv("after-recovery"))
        check("new work uses the recovered box again", st4 == 200, str(h4.get("x-strata-backend")))
        r = stats(ROUTER_PORT)["router"]
        # The audit predates passthrough_gets (v1.2.16 gave keyless GETs their
        # own terminal); without subtracting that term, ANY passive monitor
        # poking /v1/models eats the 6-request slack and this check fails on
        # a router that decided everything correctly. Generalize the formula
        # like the closed identity did.
        check("decisions fully accounted for",
              r["sticky_hits"] + r["new_placements"] + r["migrations"] + r["pinned"] + r.get("pin_misses", 0) + r.get("last_resort", 0) + r.get("passthrough_gets", 0) >= r["requests"] - 6,
              json.dumps(r)[:220])
        print("")
        print("router decisions:", json.dumps(r, indent=2)[:420])

        print("")
        print("5) tiers -- local first; the borrowed box only when it is verifiably idle")
        a.hold = b.hold = 1.2   # widen the window so busy-phase assertions cannot race
        proc2 = subprocess.Popen(
            [sys.executable, ROUTER,
             "--backend", '{"id":"L","url":"http://127.0.0.1:%d","priority":0,"max_inflight":1,"require_idle":true}' % A_PORT,
             "--backend", '{"id":"R","url":"http://127.0.0.1:%d","priority":1,"max_inflight":1,"require_idle":true}' % B_PORT,
             "--listen", "127.0.0.1", "--port", str(ROUTER2_PORT),
             "--max-connect-failures", "2", "--down-backoff", "2",
             "--status-interval", "0.2", "--log-level", "WARNING"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            check("tiered router starts", wait_for(lambda: get(ROUTER2_PORT, "/healthz")[0] == 200, 20))

            def tcall(tag, turns=1, extra=None):
                return call(ROUTER2_PORT, "/v1/messages", conv(tag, turns), extra=extra)

            def tiers():
                return {x["id"]: x for x in stats(ROUTER2_PORT)["backends"]}

            st, h, _b, _w = tcall("tier-idle")
            check("idle primary takes the conversation", h.get("x-strata-backend") == "L", str(h.get("x-strata-backend")))
            bx = tiers()
            check("tier knobs visible in stats",
                  bx["L"]["priority"] == 0 and bx["R"]["priority"] == 1 and bx["L"]["max_inflight"] == 1
                  and bx["R"]["require_idle"] is True,
                  json.dumps({k: [v["priority"], v["max_inflight"], v["require_idle"], v["accepting"]] for k, v in bx.items()}))

            t1, r1 = spawn(tcall, "tier-hold-L")
            check("primary occupancy visible live", wait_for(lambda: tiers()["L"]["inflight"] >= 1, 5))
            t2, r2 = spawn(tcall, "tier-overflow")
            t2.join(30)
            t1.join(30)
            check("local full -> overflow goes to the idle peer", r2["r"][1].get("x-strata-backend") == "R",
                  str(r2.get("r", r2.get("err")))[:80])

            st, h, _b, _w = tcall("tier-overflow", turns=3)
            check("an overflowed conversation stays where it warmed its cache",
                  h.get("x-strata-backend") == "R" and h.get("x-strata-placement") == "sticky",
                  str(h.get("x-strata-backend")) + "/" + str(h.get("x-strata-placement")))

            # lane overflow: a lane that ALREADY lives on a box queues to a
            # peer that is open NOW instead of queueing at home behind whoever
            # holds the slot (this is what spreads subagent branches). The
            # other lane's holder must leave before the next block's timing.
            _ov0, h_ov0, _bo0, _wo0 = tcall("lane-home-L")          # homes on L (idle)
            th, rh = spawn(tcall, "lane-home-holder")                # takes L's slot
            wait_for(lambda: tiers()["L"]["inflight"] >= 1, 5)
            _ov1, h_ovf, _bo1, _wo1 = tcall("lane-home-L", turns=3)  # follow-up: home full
            th.join(30)
            check("a lane whose home is FULL overflows to the open peer (placement=overflow)",
                  h_ovf.get("x-strata-backend") == "R" and h_ovf.get("x-strata-placement") == "overflow",
                  "%s/%s" % (h_ovf.get("x-strata-backend"), h_ovf.get("x-strata-placement")))
            _r_ovf = json.loads(get(ROUTER2_PORT, "/__router/stats")[1])["router"]
            check("overflow is counted in the router metrics",
                  _r_ovf.get("overflow_placements", 0) >= 1, json.dumps(_r_ovf)[:160])
            _ov2, h_ovs, _bo2, _wo2 = tcall("lane-home-L", turns=5)
            check("the overflowed lane now sticks to where it re-homed",
                  h_ovs.get("x-strata-backend") == "R" and h_ovs.get("x-strata-placement") == "sticky",
                  "%s/%s" % (h_ovs.get("x-strata-backend"), h_ovs.get("x-strata-placement")))

            tl, rl = spawn(tcall, "tier-hold-L2")
            check("primary full", wait_for(lambda: tiers()["L"]["inflight"] >= 1, 5))
            tr, rr = spawn(tcall, "tier-hold-R")
            check("borrowed box full too", wait_for(lambda: tiers()["R"]["inflight"] >= 1, 5))
            t3, r3 = spawn(tcall, "tier-both-busy")
            tl.join(30)
            tr.join(30)
            t3.join(30)
            check("when neither box accepts, the conversation queues at the primary -- never refused",
                  r3["r"][0] == 200 and r3["r"][1].get("x-strata-backend") == "L" and r3["r"][3] >= 1.2,
                  "status=%s box=%s wall=%s" % (r3["r"][0], r3["r"][1].get("x-strata-backend"), r3["r"][3]))

            b.force_load = {"concurrency": {"serving": 1},                        # capacity, must be ignored
                            "activity": {"in_flight": 2},                          # the peer's owner is working
                            "vram": {"reserve_mib": 700, "expert_slots": 1200}}    # MiB decoys
            check("peer's own (external) load confirmed by two consecutive reports",
                  wait_for(lambda: tiers()["R"].get("ext_streak", 0) >= 2, 6))
            tp, rp = spawn(tcall, "tier-pin-L", 1, {"x-strata-pin": "L"})
            wait_for(lambda: tiers()["L"]["inflight"] >= 1, 5)
            tc, rc = spawn(tcall, "tier-courtesy")
            tp.join(30)
            tc.join(30)
            check("never borrowed past the peer's own work -- waits at home instead",
                  rc["r"][0] == 200 and rc["r"][1].get("x-strata-backend") == "L",
                  "status=%s box=%s" % (rc["r"][0], rc["r"][1].get("x-strata-backend")))
            b.force_load = None

            b.blind = True    # the peer is mid-update: inference fine, load reporting dead
            check("a silent peer ages out of the idle verdict",
                  wait_for(lambda: (tiers()["R"].get("reported_age_s") or 0) > 5.4, 12))
            bx = tiers()
            check("blind but still healthy: blind never ejects a box (rule 4)",
                  bx["R"]["state"] == "healthy" and bx["R"]["accepting"] is False,
                  "state=%s accepting=%s" % (bx["R"]["state"], bx["R"]["accepting"]))
            tp2, rp2 = spawn(tcall, "tier-pin-L2", 1, {"x-strata-pin": "L"})
            wait_for(lambda: tiers()["L"]["inflight"] >= 1, 5)
            tb, rb = spawn(tcall, "tier-blind-peer")
            tp2.join(30)
            tb.join(30)
            check("blind peer is not borrowed -- queues at home",
                  rb["r"][0] == 200 and rb["r"][1].get("x-strata-backend") == "L", str(rb["r"][1].get("x-strata-backend")))
            b.blind = False
            check("peer becomes borrowable again the instant its reporting returns",
                  wait_for(lambda: (tiers()["R"].get("reported_age_s") or 99) < 1.0 and tiers()["R"]["accepting"], 10))

            # v1.2.6 guards (L2 review): a peer that dies AFTER pick() chose it
            # must cost the turn a queue, never a 502 (M1); queueing at a
            # closed-gate home must stay visible in gate_bypass_borrow (M2).
            _dp0, _h_dp0, _b_dp0, _w_dp0 = tcall("lane-dead-peer")      # homes on L (idle)
            thk, rhk = spawn(tcall, "lane-dead-holder")                 # takes L's slot
            wait_for(lambda: tiers()["L"]["inflight"] >= 1, 5)
            _ov_before = json.loads(get(ROUTER2_PORT, "/__router/stats")[1])["router"].get("overflow_placements", 0)
            b.kill()                                                    # peer unreachable from here
            _dp1, h_dp1, b_dp1, _w_dp1 = tcall("lane-dead-peer", turns=3)
            thk.join(30)
            check("a peer that dies mid-overflow costs the turn a QUEUE, never a 502",
                  _dp1 == 200 and h_dp1.get("x-strata-backend") == "L"
                  and h_dp1.get("x-strata-placement") == "sticky"
                  and "unreachable" not in (b_dp1 or ""),
                  "status=%s box=%s placement=%s body=%s" % (_dp1, h_dp1.get("x-strata-backend"),
                                                             h_dp1.get("x-strata-placement"), (b_dp1 or "")[:80]))
            _r_after = json.loads(get(ROUTER2_PORT, "/__router/stats")[1])["router"]
            check("an overflow that never got a first byte does not count as a placement",
                  _r_after.get("overflow_placements", 0) == _ov_before, json.dumps(_r_after)[:200])
            b = FakeStrata(B_PORT, "b", hold=1.2, serial=True, deny_count_tokens=True)
            b.start()
            _gb0 = json.loads(get(ROUTER2_PORT, "/__router/stats")[1])["router"].get("gate_bypass_borrow", 0)
            b.force_load = {"activity": {"in_flight": 2}}               # the owner is back: gate closes
            check("borrowed home's gate confirmed closed (two reports of foreign load)",
                  wait_for(lambda: tiers()["R"].get("ext_streak", 0) >= 2, 12))
            tg2, rg2 = spawn(tcall, "tier-hold-L3")                     # L full: overflow has nowhere to go
            wait_for(lambda: tiers()["L"]["inflight"] >= 1, 5)
            _g2s, h_g2s, _g2b, _g2w = tcall("lane-home-L", turns=7)     # this lane lives on R (re-homed above)
            _gb1 = json.loads(get(ROUTER2_PORT, "/__router/stats")[1])["router"].get("gate_bypass_borrow", 0)
            tg2.join(30)
            b.force_load = None
            check("queueing at a closed-gate borrowed home is counted -- never invisible",
                  _g2s == 200 and h_g2s.get("x-strata-backend") == "R"
                  and h_g2s.get("x-strata-placement") == "sticky" and _gb1 >= _gb0 + 1,
                  "status=%s box=%s bypass=%s->%s" % (_g2s, h_g2s.get("x-strata-backend"), _gb0, _gb1))

            # v1.2.7 F1 guard (L1-1 review): the router releases an aborted
            # request immediately, but the box keeps COUNTING it until its own
            # next keep-alive beat. That ghost must never close the courtesy
            # gate and exile an innocent lane onto the borrowed box.
            a.beat_lag_s = 2.5
            _gh0 = json.loads(get(ROUTER2_PORT, "/__router/stats")[1])["router"].get("overflow_placements", 0)
            tm, rm = spawn(tcall, "ghost-main")            # homes on L (idle right now)
            wait_for(lambda: tiers()["L"]["inflight"] >= 1, 5)
            _ghb = conv("ghost-sib")
            _ghb["model"] = "hang-stream"
            _ghr = json.dumps(_ghb).encode()
            _gs = socket.create_connection(("127.0.0.1", ROUTER2_PORT), timeout=10)
            _gs.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                        b"content-type: application/json\r\nx-strata-pin: L\r\ncontent-length: %d\r\n\r\n"
                        % (ROUTER2_PORT, len(_ghr)) + _ghr)
            _gs.settimeout(8)
            _gd = b""
            while b": keep-alive" not in _gd:
                _gg = _gs.recv(65536)
                if not _gg:
                    break
                _gd += _gg
            check("guard setup: ghost sibling pinned onto the home box L",
                  b"x-strata-backend: l" in _gd.lower() and b"placement: pinned" in _gd.lower(),
                  _gd[:60].decode("latin-1", "replace"))
            tm.join(30)                                   # main lane's turn completes; sibling keeps pinging
            _ab0g = tiers()["L"]["stats"]["aborted_by_client"]
            _gs.close()                                   # kill the sibling's caller (the ESC)
            # wait for the release to be BOOKED (watchdog latency is load-
            # dependent) -- still deep inside the box's 2.5 s ghost window.
            # Firing on a fixed sleep here once raced a slow watchdog and
            # measured the sibling's own CAP hold, not the ghost.
            check("the abort releases the home slot and is booked as an abort, not a failure",
                  wait_for(lambda: tiers()["L"]["stats"]["aborted_by_client"] > _ab0g
                           and tiers()["L"]["inflight"] == 0, 5))
            time.sleep(0.8)   # let the poller sample the ghost twice: the OLD code's
            # ext_streak hits 2 here and exiles the lane -- this instant is the guard
            _gst, hgs, _gbb, _gw = tcall("ghost-main", turns=3)   # follow-up lands inside the ghost window
            _gL = tiers()["L"]
            check("an aborted request of OURS never closes home's gate and exiles the lane",
                  _gst == 200 and hgs.get("x-strata-backend") == "L"
                  and hgs.get("x-strata-placement") == "sticky",
                  "%s/%s L@followup=%s" % (hgs.get("x-strata-backend"), hgs.get("x-strata-placement"),
                  json.dumps({k: _gL.get(k) for k in ("inflight", "ext_streak", "state", "reported", "accepting")})[:220]))
            check("the ghost window also does not tick overflow_placements",
                  json.loads(get(ROUTER2_PORT, "/__router/stats")[1])["router"].get("overflow_placements", 0) == _gh0)
            wait_for(lambda: (tiers()["L"].get("reported") or {}).get("serving", 9) == 0, 10)
            a.beat_lag_s = 0.0
        finally:
            _term(proc2)
            try:
                proc2.wait(timeout=5)
            except Exception:
                proc2.kill()
            a.hold = b.hold = 0.55
            b.force_load = None
            b.blind = False

        print("")
        print("5b) the retry door -- one lane's overlapping overflows settle alone (v1.2.8)")
        # SDK retries of a parked turn are EXPECTED traffic (README says so).
        # When a retry overflows while the lane's first overflow is still in
        # flight, the lane-keyed provisional entry used to be silently
        # overwritten: whichever request answered first re-homed the lane
        # onto the OTHER one's box, and the second one's rollback popped a
        # mismatched entry and 502'd over a live home (review L1-2/M1). A
        # third box with tier order makes the overlap reachable on loopback.
        e = FakeStrata(E_PORT, "e", hold=1.2, serial=True)
        f = FakeStrata(F_PORT, "f", hold=2.2, serial=True)
        g = FakeStrata(G_PORT, "g", hold=2.2, serial=True)
        e.start(), f.start(), g.start()
        proc7 = subprocess.Popen(
            [sys.executable, ROUTER,
             "--backend", '{"id":"N1","url":"http://127.0.0.1:%d","priority":0,"max_inflight":1,"require_idle":true}' % E_PORT,
             "--backend", '{"id":"N2","url":"http://127.0.0.1:%d","priority":1,"max_inflight":1,"require_idle":true}' % F_PORT,
             "--backend", '{"id":"N3","url":"http://127.0.0.1:%d","priority":2,"max_inflight":1,"require_idle":true}' % G_PORT,
             "--listen", "127.0.0.1", "--port", str(ROUTER5_PORT),
             "--max-connect-failures", "2", "--down-backoff", "2",
             "--status-interval", "0.2", "--log-level", "WARNING"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            check("retry-door router starts (three tiers)",
                  wait_for(lambda: get(ROUTER5_PORT, "/healthz")[0] == 200, 20))

            def qcall(tag, turns=1, extra=None, path="/v1/messages", model=None):
                body = conv(tag, turns)
                if model:
                    body["model"] = model
                return call(ROUTER5_PORT, path, body, extra=extra)

            def qtiers():
                return {x["id"]: x for x in stats(ROUTER5_PORT)["backends"]}

            def qm():
                return stats(ROUTER5_PORT)["router"]

            # ---- M1: the same lane overflows twice; the retry's box dies ----
            _s0, _h0, _, _ = qcall("retry-lane")                     # homes on N1
            th1, rh1 = spawn(qcall, "retry-holder")                  # takes N1's slot
            wait_for(lambda: qtiers()["N1"]["inflight"] >= 1, 5)
            tA, rA = spawn(qcall, "retry-lane")                      # lane turn: N1 full -> overflow N2 (parks)
            time.sleep(0.25)
            tB, rB = spawn(lambda: qcall("retry-lane", model="die-midway"))  # the RETRY, same lane: N2 at cap -> overflow N3
            wait_for(lambda: qtiers()["N3"]["inflight"] >= 1, 5)
            check("both provisional re-homes are in flight together (the old lane-keyed map held ONE)",
                  qm().get("overflow_pending") == 2, json.dumps(qm())[:160])
            tA.join(30)
            tB.join(30)
            check("two overlapping overflows of ONE lane were in flight together, each with its own pending entry",
                  rA["r"][1].get("x-strata-backend") == "N2" and rA["r"][1].get("x-strata-placement") == "overflow"
                  and rB["r"][0] == 502 and "may still complete" in (rB["r"][2] or ""),
                  "tA=%s/%s tB=%s %s" % (rA["r"][1].get("x-strata-backend"), rA["r"][1].get("x-strata-placement"),
                                         rB["r"][0], (rB["r"][2] or "")[:60]))
            check("the retry that died mid-park FIZZLES its provisional re-home (counted, drained)",
                  wait_for(lambda: qm().get("overflow_pending", 99) == 0, 6)
                  and qm().get("overflow_fizzles", 0) >= 1,
                  json.dumps({k: qm().get(k) for k in ("overflow_pending", "overflow_fizzles", "overflow_placements")}))
            _st3, _hst3, _, _ = qcall("retry-lane", turns=3)
            check("the lane re-homed to the box that ANSWERED -- not the retry's dead-end box",
                  _hst3.get("x-strata-backend") == "N2" and _hst3.get("x-strata-placement") == "sticky",
                  "%s/%s" % (_hst3.get("x-strata-backend"), _hst3.get("x-strata-placement")))
            th1.join(30)

            # ---- M2: capacity-only queueing with the gate OPEN is not a bypass ----
            _gb0 = qm().get("gate_bypass_borrow", 0)
            th2, rh2 = spawn(qcall, "cap-e")                          # ours, on every box...
            th3, rh3 = spawn(qcall, "cap-f")
            th4, rh4 = spawn(qcall, "cap-g")
            wait_for(lambda: all(qtiers()[i]["inflight"] >= 1 for i in ("N1", "N2", "N3")), 6)
            _s4, _h4, _b4, _w4 = qcall("cap-fourth")                  # ...so this one queues at N1
            _gb1 = qm().get("gate_bypass_borrow", 0)
            th2.join(30), th3.join(30), th4.join(30)
            check("pure-CAPACITY queueing (gate open, load is all ours) never ticks gate_bypass_borrow",
                  _s4 == 200 and _h4.get("x-strata-backend") == "N1" and _gb1 == _gb0,
                  "status=%s box=%s bypass=%s->%s wall=%s" % (_s4, _h4.get("x-strata-backend"), _gb0, _gb1, _w4))

            # ---- S1: an operator pin survives a late overflow commit ----
            th7, rh7 = spawn(qcall, "pin-block-e")                    # N1 busy with OURS...
            wait_for(lambda: qtiers()["N1"]["inflight"] >= 1, 5)
            th5, rh5 = spawn(qcall, "pin-holder", 1, {"x-strata-pin": "N2"})   # ...N2 busy too...
            wait_for(lambda: qtiers()["N2"]["inflight"] >= 1, 5)
            tC, rC = spawn(qcall, "retry-lane")                        # lane (at N2) -> overflow parks at N3
            wait_for(lambda: qtiers()["N3"]["inflight"] >= 1, 5)
            _sp, hp, _, _ = qcall("retry-lane", turns=4, extra={"x-strata-pin": "N1"})   # operator pins it N1
            tC.join(30)                                                # N3 answers -> commit must NOT stomp the pin
            _sf, hsf, _, _ = qcall("retry-lane", turns=5)
            th5.join(30), th7.join(30)
            check("an operator pin is not silently overwritten by a pending overflow commit",
                  _sf == 200 and hsf.get("x-strata-backend") == "N1" and hsf.get("x-strata-placement") == "sticky",
                  "%s/%s pinned=%s" % (hsf.get("x-strata-backend"), hsf.get("x-strata-placement"),
                                       hp.get("x-strata-placement")))

            # ---- S2: count_tokens (warms nothing) must not exile the lane ----
            th6, rh6 = spawn(qcall, "ct-holder")                       # N1 busy with OURS
            wait_for(lambda: qtiers()["N1"]["inflight"] >= 1, 5)
            _sc, hc, bc, _ = qcall("retry-lane", path="/v1/messages/count_tokens")   # overflows to N2, answers 200
            th6.join(30)
            wait_for(lambda: qtiers()["N1"]["inflight"] == 0, 8)
            _s7, hs7, _, _ = qcall("retry-lane", turns=3)
            check("a count_tokens preview that overflowed does NOT re-home the conversation",
                  _sc == 200 and "input_tokens" in bc and hs7.get("x-strata-backend") == "N1"
                  and hs7.get("x-strata-placement") == "sticky",
                  "ct=%s follow=%s/%s" % (_sc, hs7.get("x-strata-backend"), hs7.get("x-strata-placement")))
            check("its provisional entry fizzles too -- nothing stays pending after every request ended",
                  wait_for(lambda: qm().get("overflow_pending", 99) == 0, 6),
                  json.dumps(qm())[:200])

            # ---- the closed identity: every request settles in ONE counter ----
            _r7 = qm()
            _term_sum = (_r7["sticky_hits"] + _r7["new_placements"] + _r7["migrations"]
                         + _r7["pinned"] + _r7.get("last_resort", 0) + _r7.get("overflow_placements", 0)
                         + _r7.get("overflow_rollbacks", 0) + _r7.get("overflow_fizzles", 0))
            check("placement counters form a CLOSED identity (one terminal per request; only the"
                  " operator-cancelled overflow is allowed uncounted)",
                  _r7["requests"] - _term_sum == 1 and _r7.get("pin_misses", 0) == 0,
                  "requests=%s terminals=%s diff=%s %s" % (_r7["requests"], _term_sum, _r7["requests"] - _term_sum,
                                                           json.dumps({k: _r7.get(k) for k in
                                                           ("sticky_hits", "new_placements", "pinned",
                                                            "overflow_placements", "overflow_rollbacks",
                                                            "overflow_fizzles")})[:220]))
        finally:
            _term(proc7)
            try:
                proc7.wait(timeout=5)
            except Exception:
                proc7.kill()
            for bx3 in (e, f, g):
                try:
                    bx3.kill()
                except Exception:
                    pass

        # Direct Pool contracts for the two deaths HTTP timing cannot stage
        # (review L1-2 M1's destructive-pop door and M3's double-release):
        # rollback must release the alt reservation EXACTLY once, leave a
        # SIBLING request's pending entry untouched, and when the home raced
        # into DOWN it must MIGRATE onward -- never hand back a None that the
        # handler would turn into a 502 over still-live boxes.
        _ch = R.Backend("ch", "http://127.0.0.1:1", cfg={})
        _ca2 = R.Backend("ca2", "http://127.0.0.1:2", cfg={})
        _ca3 = R.Backend("ca3", "http://127.0.0.1:3", cfg={})
        _cl = R.Backend("cl", "http://127.0.0.1:4", cfg={})
        _cp = R.Pool([_ch, _ca2, _ca3, _cl], {})
        _cp._overflow_pending[11] = ("meta:m1/lane:m1", "ch", "ca2")
        _cp._overflow_pending[12] = ("meta:m1/lane:m1", "ch", "ca3")
        _ca2.inflight = _ca3.inflight = 1
        _co = _cp.overflow_rollback("meta:m1/lane:m1", 12, "ca3")     # the SIBLING's alt died
        check("a sibling overflow's rollback releases only its OWN reservation and leaves the lane's other pending intact",
              _co is not None and _co[0] is _ch and _co[1] == "sticky" and _co[2] is True
              and _ca3.inflight == 0 and _ca2.inflight == 1
              and list(_cp._overflow_pending) == [11],
              "out=%s ca3=%s ca2=%s pend=%s" % (_co and (_co[0].id, _co[1]), _ca3.inflight, _ca2.inflight,
                                                list(_cp._overflow_pending)))
        _co and _ch.end()                                              # the request's finally, once
        _cp._overflow_pending[13] = ("meta:m1/lane:m1", "ch", "ca3")
        _ca3.inflight = 2                                              # a live lane ALSO rides ca3
        _ch.state = R.DOWN                                             # home died inside the same request
        _co2 = _cp.overflow_rollback("meta:m1/lane:m1", 13, "ca3")
        check("a rollback whose home died mid-request releases the alt EXACTLY once and migrates -- no None, no 502",
              _co2 is not None and _co2[0] is _cl and _co2[1] == "migrated"
              and _ca3.inflight == 1 and _cl.inflight == (1 if _co2[2] else 0),
              "out=%s ca3=%s cl_inflight=%s" % (_co2 and (_co2[0].id, _co2[1]), _ca3.inflight, _cl.inflight))
        # Review L1-3/L1: _affinity_drop_backend deletes pending entries whose
        # home (or alt) just died -- the third uncounted bucket the closed
        # identity promised not to have. Those drops must tick fizzles, or a
        # home migration silently swallows requests from the ledger.
        _fz_before = _cp.metrics["overflow_fizzles"]
        _cp._overflow_pending[97] = ("meta:x/lane:x", "ca9", "cl")
        _pend_before = len(_cp._overflow_pending)
        _cp._affinity_drop_backend("ca9")
        check("dropping a dead backend's pending re-homes books each one as a fizzle (identity stays closed)",
              list(_cp._overflow_pending) == [11]          # sibling's entry survives, 97 is gone
              and _cp.metrics["overflow_fizzles"] == _fz_before + 1,
              "pend %s->%s fizzles %s->%s" % (_pend_before, len(_cp._overflow_pending),
                                              _fz_before, _cp.metrics["overflow_fizzles"]))

        print("")
        print("5c) the probe answers BUSY boxes honestly (v1.2.9, review L1-3/S2)")
        _pf = FakeStrata(P_PROBE_PORT, "probebox")
        _pf.start()
        try:
            # hang-stream parks like a box whose slot is taken: 200 + SSE
            # headers already out, keep-alive beats for up to 10 s. The old
            # non-streaming fill-read blocked on it (on a real box: for the
            # whole queue wait, budget 60 s) and printed "unreachable" for a
            # HEALTHY box. Streaming probe + verdict-at-headers answers now.
            _pbe = R.Backend("pb", "http://127.0.0.1:%d" % P_PROBE_PORT,
                             cfg={"probe_model": "hang-stream"})
            _pt0 = time.monotonic()
            _pc, _ = R._probe_messages(_pbe, "/v1/messages")
            _pdt = time.monotonic() - _pt0
            check("a parked stream gets its verdict at the headers (pre-fix this blocked ~10 s / budget 60 s)",
                  _pc == 200 and _pdt < 2.0, "code=%s in %.2fs" % (_pc, _pdt))
            _pc2, _ = R._probe_messages(
                R.Backend("pb2", "http://127.0.0.1:%d" % P_PROBE_PORT, cfg={}), "/v1/messages")
            check("an idle box still answers OK over the streaming probe (no false negatives)",
                  _pc2 == 200, "code=%s" % _pc2)
            _pc3, _ = R._probe_messages(R.Backend("pb3", "http://127.0.0.1:9", cfg={}), "/v1/messages")
            check("a truly dead port still returns None -- honest 'unreachable' for cold/dead boxes survives",
                  _pc3 is None, "code=%s" % _pc3)
        finally:
            _pf.kill()

        print("")
        print("5d) adversarial edges -- hostile framing, control trust, rewrite (v1.2.10, review L2-2)")

        def _raw(port, blob, host="127.0.0.1", read=4.0):
            try:
                _s = socket.create_connection((host, port), 5)
            except OSError:
                # boot races (wait_for loops) and server-side resets: a raw
                # probe sees "nothing", it never crashes the suite
                return b""
            _s.settimeout(read)
            try:
                try:
                    _s.sendall(blob)
                except OSError:
                    pass        # server may answer and close before the junk lands
                _d = b""
                try:
                    while len(_d) < 65536:
                        _g = _s.recv(4096)
                        if not _g:
                            break
                        _d += _g
                        # the headers alone don't carry the named error --
                        # read through to the body, or until the server closes
                except (socket.timeout, OSError):
                    pass
                return _d
            finally:
                _s.close()

        # M1: int(x,16) accepted "-1" (read(-1) = read to EOF, walking past
        # max_body_mb) and "-2" (ValueError inside read: handler died with
        # ZERO response bytes). Strict hex, or a named 400.
        _pre = (b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                b"content-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n") % ROUTER_PORT
        _codes = [_raw(ROUTER_PORT, _pre + _f + b"XX junk XX\r\n0\r\n\r\n")
                  for _f in (b"-2\r\n", b"-1\r\n", b"0x21\r\n", b"1_0\r\n")]
        check("hostile chunk sizes (-2, -1, 0x21, 1_0) all get a named 400 -- never silent death, never an unbounded read",
              all(b"400" in c and b"bad chunk framing" in c for c in _codes), repr(_codes)[:180])
        _st, _h, _b, _w = call(ROUTER_PORT, "/v1/messages", conv("chunk-liveness"))
        check("main router answers normally after the hostile framing", _st == 200, "status=%s" % _st)

        # L2: OPTIONS was aliased onto do_POST -- a preflight-style OPTIONS
        # would EXECUTE the destructive clear.
        _aff0 = stats(ROUTER_PORT)["router"]["affinity_keys"]
        _o = _raw(ROUTER_PORT, b"OPTIONS /__router/sticky/clear HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % ROUTER_PORT)
        _aff1 = stats(ROUTER_PORT)["router"]["affinity_keys"]
        check("OPTIONS /__router/sticky/clear is 405, not a destructive clear (and lanes survive)",
              b"405" in _o and _aff1 == _aff0 and _aff0 > 0, "code=%s aff %s->%s" % (_o.split(b" ")[1] if b" " in _o else b"?", _aff0, _aff1))

        _rwf = FakeStrata(RW_FAKE, "rwbox")
        _rwf.start()
        proc6 = None
        try:
            # M3: the ONE sanctioned body edit ran after the connection opened,
            # with an except-list missing TypeError (unhashable model ->
            # thread death) and an ensure_ascii=False re-encode (lone surrogate
            # -> UnicodeEncodeError CHARGED TO A HEALTHY BOX: connect_errors,
            # DOWN flaps, x-strata-pin choosing which box eats it).
            proc6 = subprocess.Popen(
                [sys.executable, ROUTER,
                 "--backend", '{"id":"t","url":"http://127.0.0.1:%d"}' % RW_FAKE,
                 "--listen", "127.0.0.1", "--port", str(RW_ROUTER),
                 "--rewrite-model", "in-model=out-model"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_for(lambda: get(RW_ROUTER, "/healthz")[0] == 200)
            _mb = {"model": ["x"], "max_tokens": 8, "messages": [{"role": "user", "content": "m-list"}]}
            _st, _h, _b, _w = call(RW_ROUTER, "/v1/messages", _mb)
            _surr = {"model": "in-model", "max_tokens": 8, "system": "pre\ud800post",
                     "messages": [{"role": "user", "content": "m-surr"}]}
            _st2, _h2, _b2, _w2 = call(RW_ROUTER, "/v1/messages", _surr)
            _rws = stats(RW_ROUTER)["backends"][0]
            check("unhashable model and a lone-surrogate body neither kill the relay nor bill the healthy box (v1.2.10)",
                  _st == 200 and _st2 == 200
                  and _rws["stats"]["connect_errors"] == 0 and _rws["state"] == "healthy",
                  "list=%s surr=%s errs=%s state=%s" % (_st, _st2, _rws["stats"]["connect_errors"], _rws["state"]))

            # control token: pin + sticky/clear gated when set (M2/L1 hardening)
            _tcfg = {"listen": "127.0.0.1", "port": TOK_ROUTER,
                     "backends": [{"id": "t", "url": "http://127.0.0.1:%d" % RW_FAKE}],
                     "control_token": "tok-smoke-9d41"}
            with open("smoke-tok.json", "w", encoding="utf-8") as _tf:
                json.dump(_tcfg, _tf)
            proc7 = subprocess.Popen([sys.executable, ROUTER, "--config", "smoke-tok.json"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                wait_for(lambda: get(TOK_ROUTER, "/healthz")[0] == 200)
                call(TOK_ROUTER, "/v1/messages", conv("tok-warm"))
                _s1, _h1, _b1, _w1 = call(TOK_ROUTER, "/v1/messages", conv("tok-pin"),
                                          extra={"x-strata-pin": "t"})
                _s2, _h2, _b2, _w2 = call(TOK_ROUTER, "/__router/sticky/clear", {})
                _aff2 = stats(TOK_ROUTER)["router"]["affinity_keys"]
                _s3, _h3, _b3, _w3 = call(TOK_ROUTER, "/v1/messages", conv("tok-pin2"),
                                          extra={"x-strata-pin": "t", "x-strata-control": "tok-smoke-9d41"})
                _s4, _h4, _b4, _w4 = call(TOK_ROUTER, "/__router/sticky/clear", {},
                                          extra={"x-strata-control": "tok-smoke-9d41"})
                check("with control_token set: pin and clear without x-strata-control are 403, lanes survive",
                      _s1 == 403 and _s2 == 403 and _aff2 > 0, "pin=%s clear=%s aff=%s" % (_s1, _s2, _aff2))
                check("...and with the token both work: the pin lands, the clear clears",
                      _s3 == 200 and _h3.get("x-strata-placement") == "pinned"
                      and _s4 == 200 and int(json.loads(_b4).get("cleared_affinity_keys", 0)) >= 1,
                      "pin=%s place=%s clear=%s" % (_s3, _h3.get("x-strata-placement"), _b4[:60]))
                # M1 (L2-3): the token gates the ROUTER -- it must never travel
                # on the forwarded turn to the box (mirror deploy would hand it
                # to the peer's machine on every pinned request).
                check("the control token never reaches the box (L2-3/M1): the fake saw no x-strata-control, "
                      "pinned turns included",
                      all(not c for c in _rwf.seen_controls),
                      "seen=%r" % ([c for c in _rwf.seen_controls if c],)[:140])
                # L1 (L2-3): compare_digest raises TypeError on non-ASCII --
                # must 403, not kill the handler with zero response bytes.
                _nasty = _raw(TOK_ROUTER, b"POST /__router/sticky/clear HTTP/1.1\r\n"
                              b"Host: 127.0.0.1:%d\r\ncontent-length: 2\r\n"
                              b"x-strata-control: caf\xc3\xa9\r\n\r\n{}" % TOK_ROUTER)
                check("a non-ASCII x-strata-control gets a named 403, not a dead connection (L2-3/L1)",
                      b"403" in _nasty and b"control token required" in _nasty, _nasty[:130])
            finally:
                proc7.kill()
                try:
                    proc7.wait(timeout=5)
                except Exception:
                    pass

            # M4: bound off-loopback -- Host: localhost must NOT pass anymore
            _lcfg = {"listen": "127.0.0.2", "port": LAN_ROUTER,
                     "backends": [{"id": "t", "url": "http://127.0.0.1:%d" % RW_FAKE}]}
            with open("smoke-lan.json", "w", encoding="utf-8") as _lf:
                json.dump(_lcfg, _lf)
            proc8 = subprocess.Popen([sys.executable, ROUTER, "--config", "smoke-lan.json"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                wait_for(lambda: _raw(LAN_ROUTER, b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.2:%d\r\n\r\n" % LAN_ROUTER,
                                      host="127.0.0.2").find(b"200") >= 0)
                _noHost = _raw(LAN_ROUTER, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n", host="127.0.0.2")
                check("a non-loopback bind refuses Host: localhost -- loopback NAMES are not a free pass off-loopback",
                      b"403" in _noHost, _noHost[:120])
            finally:
                proc8.kill()
                try:
                    proc8.wait(timeout=5)
                except Exception:
                    pass
        finally:
            if proc6:
                proc6.kill()
                try:
                    proc6.wait(timeout=5)
                except Exception:
                    pass
            _rwf.kill()

        print("")
        print("5e) ghosts, locks and the keys file (v1.2.11, review L2-3)")

        # M2 (L2-3): a request the ROUTER abandoned on read timeout (sent, no
        # first byte) must register ghost debt like a client abort does --
        # otherwise the box keeps counting our corpse, the courtesy gate reads
        # it as external load, and our own zombie closes our own home's gate
        # and exiles the lane to the borrowed box.
        _ghA, _ghB = FakeStrata(GH_A, "gh-a"), FakeStrata(GH_B, "gh-b")
        _ghA.start(), _ghB.start()
        _gcfg = {"listen": "127.0.0.1", "port": GH_ROUTER,
                 "status_interval": 0.4, "read_timeout": 1.5,
                 "backends": [
                     {"id": "ga", "url": "http://127.0.0.1:%d" % GH_A,
                      "require_idle": True, "max_inflight": 1, "priority": 0},
                     {"id": "gb", "url": "http://127.0.0.1:%d" % GH_B,
                      "require_idle": True, "max_inflight": 1, "priority": 1}]}
        with open("smoke-gh.json", "w", encoding="utf-8") as _gf:
            json.dump(_gcfg, _gf)
        procgh = subprocess.Popen([sys.executable, ROUTER, "--config", "smoke-gh.json"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for(lambda: get(GH_ROUTER, "/healthz")[0] == 200)
            wait_for(lambda: all(x["status_ok"] for x in stats(GH_ROUTER)["backends"]))
            _s0, _h0, _b0, _w0 = call(GH_ROUTER, "/v1/messages", conv("gh-lane"))
            check("guard setup: the ghost lane is homed on ga",
                  _s0 == 200 and _h0.get("x-strata-backend") == "ga",
                  "%s %s" % (_s0, _h0.get("x-strata-backend")))
            _ovf0 = stats(GH_ROUTER)["router"]["overflow_placements"]
            _sb = conv("gh-lane", 2)
            _sb["model"] = "stall"
            _stt, _htd, _bd, _wt = call(GH_ROUTER, "/v1/messages", _sb, timeout=10.0)
            check("guard setup: the stall turn dies as the documented backend_timeout 502",
                  _stt == 502 and "backend_timeout" in _bd, "%s %s" % (_stt, _bd[:80]))
            time.sleep(1.0)   # >=2 polls of ga while it still counts our corpse
            _s3g, _h3g, _b3g, _w3g = call(GH_ROUTER, "/v1/messages", conv("gh-lane", 3))
            _ovf1 = stats(GH_ROUTER)["router"]["overflow_placements"]
            check("a read-timeout corpse never closes its OWN home's gate: the lane stays home, "
                  "zero overflow (pre-fix: ext_streak saw our zombie, exiled the lane; L2-3/M2)",
                  _s3g == 200 and _h3g.get("x-strata-backend") == "ga" and _ovf1 == _ovf0,
                  "be=%s place=%s ovf %s->%s" % (_h3g.get("x-strata-backend"),
                                                 _h3g.get("x-strata-placement"), _ovf0, _ovf1))
        finally:
            procgh.kill()
            try:
                procgh.wait(timeout=5)
            except Exception:
                pass
            _ghA.kill(), _ghB.kill()

        # M3 (L2-3): the DOWN/HEALTHY log lines used to fire INSIDE the backend
        # lock -- one blocked log sink (piped stderr nobody reads, quick-edit
        # freeze) would then freeze every begin/end/pick touching that box.
        _m3 = R.Backend("m3x", "http://127.0.0.1:9")
        _m3res = {}
        _oW, _oI = R.LOG.warning, R.LOG.info

        def _probeW(*a):
            _m3res["down"] = _m3.lock.acquire(blocking=False)
            if _m3res["down"]:
                _m3.lock.release()

        def _probeI(*a):
            _m3res["heal"] = _m3.lock.acquire(blocking=False)
            if _m3res["heal"]:
                _m3.lock.release()

        R.LOG.warning, R.LOG.info = _probeW, _probeI
        try:
            _m3.note_connect_failure("probe", 1, 1.0)   # forces the DOWN transition
            _m3.note_success()                          # ...and the recovery
        finally:
            R.LOG.warning, R.LOG.info = _oW, _oI
        check("DOWN/HEALTHY transitions log OUTSIDE the backend lock -- a blocked log sink can "
              "no longer freeze the box's whole begin/end/pick path (L2-3/M3)",
              _m3res.get("down") is True and _m3res.get("heal") is True, str(_m3res))

        # L5 (L2-3): the 4096 cap must ACCOUNT for its evictions -- an
        # un-counted one is exactly the silent ledger hole the closed identity
        # exists to make impossible.
        with _cp.lock:
            _cp._overflow_pending.clear()
            for _i in range(4096):
                _cp._overflow_pending[_i] = ("meta:fill/lane:fill", "h", "a")
            _ev0 = _cp.metrics["overflow_evictions"]
            _cp._stash_pending(9999, ("meta:x/lane:x", "ca9", "cl"))
            _ev_ok = (_cp.metrics["overflow_evictions"] == _ev0 + 1
                      and 9999 in _cp._overflow_pending and 0 not in _cp._overflow_pending
                      and len(_cp._overflow_pending) == 4096)
            _cp._overflow_pending.clear()
        check("overflow-cap evictions get their own counter (the identity can self-verify; L2-3/L5)",
              _ev_ok, "evictions=%s" % _cp.metrics["overflow_evictions"])

        # L2 (L2-3): str(None) == "None" would become a usable key, and a
        # "control": null an illusory gate whose secret is the word "None".
        _nullkeys = os.path.join(os.getcwd(), "smoke-nullkeys.json")
        with open(_nullkeys, "w", encoding="utf-8") as _nk:
            json.dump({"local": None, "control": None}, _nk)
        try:
            R._read_keys_file(_nullkeys)
            _null_refused = False
        except SystemExit as _e2:
            _null_refused = "not a string" in str(_e2)
        check("a non-string keys-file value (null/true/...) is refused -- no gate whose secret "
              "is the word 'None' (L2-3/L2)", _null_refused)

        # L3+L4 (L2-3): --set-key must rewrite atomically (no O_TRUNC corpse)
        # and must not silently mutate the sibling entries it did not touch.
        _kdir2 = tempfile.mkdtemp(prefix="strata-keys2-")
        _kpath2 = os.path.join(_kdir2, "router.keys.json")
        with open(_kpath2, "w", encoding="utf-8") as _k2:
            json.dump({"local": "old-ka", "remote": "  padded-peer  "}, _k2)
        _ogp = R.getpass.getpass
        try:
            R.getpass.getpass = lambda prompt="": "new-ka"
            _rc2 = R.set_key({"backends": [{"id": "local", "url": "http://127.0.0.1:1"},
                                           {"id": "remote", "url": "http://127.0.0.1:1"}]},
                             "local", None, _kpath2)
        finally:
            R.getpass.getpass = _ogp
        _back2 = R._read_keys_file(_kpath2)          # decrypted view (v1.2.14)
        _raw2 = open(_kpath2, "rb").read()
        _sealed2 = (not R._dpapi_enabled()) or (b"new-ka" not in _raw2 and b"padded-peer" not in _raw2)
        check("--set-key rewrites atomically and leaves untouched siblings byte-faithful "
              "(no silent strip, no stale .new; L2-3/L3+L4); on Windows no key bytes survive in the raw file",
              _rc2 == 0 and _back2.get("local") == "new-ka"
              and _back2.get("remote") == "  padded-peer  "
              # the .lock sibling stays by design (deleting it would break a
              # waiting writer -- R4-B/F3); what must NOT survive is a .new temp
              and sorted(n for n in os.listdir(_kdir2) if not n.endswith(".lock")) == ["router.keys.json"]
              and _sealed2,
              "rc=%s entries=%s sealed=%s dir=%s" % (_rc2, sorted(_back2), _sealed2, sorted(os.listdir(_kdir2))))

        print("")
        print("5f) 2x2 stress guards -- protocol edges (P1) + scope/lane integrity & metric honesty (P2), v1.2.12")

        # F2: absolute-form request-target used to ride into the box's request
        # line verbatim. Origin-form only, refused by name.
        _ab = _raw(ROUTER_PORT, b"GET http://127.0.0.1:%d/v1/models HTTP/1.1\r\n"
                   b"Host: 127.0.0.1:%d\r\n\r\n" % (ROUTER_PORT, ROUTER_PORT))
        check("absolute-form request target gets a named 400 (never relayed into the box; stress P1/F2)",
              b"400" in _ab and b"origin-form" in _ab, repr(_ab[:90]))

        # F3: a >1 MB body on a refused route used to lose the refusal to a
        # Windows RST -- the caller learned nothing. The drain now finishes
        # politely, so the 403 SURVIVES a 2 MB sender.
        _s3 = socket.create_connection(("127.0.0.1", ROUTER_PORT), 5)
        _s3.settimeout(10.0)
        try:
            _s3.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: evil.test\r\n"
                        b"content-length: 2097152\r\ncontent-type: application/json\r\n\r\n"
                        + b"x" * (2 << 20))
            _s3.shutdown(socket.SHUT_WR)      # a finished sender DESERVES the refusal
            _d3 = b""
            try:
                while True:
                    _g = _s3.recv(4096)
                    if not _g:
                        break
                    _d3 += _g
            except OSError:
                pass
        finally:
            _s3.close()
        check("the rebinding 403 REACHES a 2 MB sender (timed graceful drain; stress P1/F3)",
              b"403" in _d3 and b"rebinding" in _d3, repr(_d3[:90]))

        # F4: the chunked reader no longer terminates early, forgives the CRLF,
        # or runs an unbounded trailer loop.
        _c4a = _raw(ROUTER_PORT, _pre + b"\r\n5\r\nhello\r\n0\r\n\r\n")
        check("empty line at chunk-size position = named 400, never a silent truncated body (stress P1/F4)",
              b"400" in _c4a and b"before the final chunk" in _c4a, repr(_c4a[:90]))
        _c4b = _raw(ROUTER_PORT, _pre + b"5\r\nhelloXY0\r\n0\r\n\r\n")
        check("chunk data not followed by CRLF = named 400 (strict terminator; stress P1/F4)",
              b"400" in _c4b and b"not terminated by CRLF" in _c4b, repr(_c4b[:90]))
        _c4c = _raw(ROUTER_PORT, _pre + b"0\r\n" + b"X-T: 1\r\n" * 65 + b"\r\n")
        check("trailer flood past 64 lines gets a named 400 (bounded read; stress P1/F4)",
              b"400" in _c4c and b"trailer" in _c4c, repr(_c4c[:90]))
        _c4d = b""
        _sh = socket.create_connection(("127.0.0.1", ROUTER_PORT), 5)
        _sh.settimeout(6.0)
        try:
            _sh.sendall(b"HEAD /v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                        b"transfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" % ROUTER_PORT)
            try:
                while b"\r\n\r\n" not in _c4d and len(_c4d) < 8192:
                    _g = _sh.recv(4096)
                    if not _g:
                        break
                    _c4d += _g
            except OSError:
                pass
            _after = b""
            try:      # a pipelined FOLLOW-UP must meet a dead socket: the chunked
                      # leftovers died with the connection, never a second request
                _sh.sendall(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % ROUTER_PORT)
                _after = _sh.recv(4096) or b""
            except OSError:
                _after = b""
        finally:
            _sh.close()
        _st, _h, _b, _w = call(ROUTER_PORT, "/v1/messages", conv("head-chunk-live"))
        check("chunked do_HEAD CLOSES the socket (a pipelined follow-up meets nothing) instead of "
              "letting the leftovers become a second request -- router stays healthy (stress P1/F4)",
              b"HTTP/1.1" in _c4d and not _after and _st == 200,
              "head=%s after=%r live=%s" % (repr(_c4d[:60]), _after[:60], _st))

        # F6: the IPv6 Host literal was chopped by rsplit(":",1) -- [::1] 403'd.
        _h6a = _raw(ROUTER_PORT, b"GET /healthz HTTP/1.1\r\nHost: [::1]\r\n\r\n")
        _h6b = _raw(ROUTER_PORT, b"GET /healthz HTTP/1.1\r\nHost: [::1]:%d\r\n\r\n" % ROUTER_PORT)
        check("Host: [::1] and [::1]:port both parse and pass the loopback guard (stress P1/F6)",
              b"200" in _h6a and b"200" in _h6b, repr(_h6a[:40]) + repr(_h6b[:40]))

        # F9: HTTP/1.0 has no chunked coding -- the framing MUST adapt.
        _r10 = _raw(ROUTER_PORT, b"GET /v1/models HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        _body10 = _r10.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in _r10 else b""
        check("HTTP/1.0 caller gets close-delimited framing, not chunked: no TE header, no "
              "chunk framing in the body, no 0-chunk (stress P1/F9)",
              b"200" in _r10 and b"transfer-encoding" not in _r10.lower()
              and _body10.startswith(b"{") and b"0\r\n\r\n" not in _r10, repr(_r10[:90]))
        _st, _h, _b, _w = call(ROUTER_PORT, "/v1/messages", conv("http10-live"))
        check("the main router answers 1.1 callers normally after the HTTP/1.0 probe", _st == 200, "status=%s" % _st)

        # F1: a LYING box answers with raw framing -- bare-CR split headers and
        # an access-control-allow-origin. http.client rebuilds the split pair
        # clean (trust model), but the CORS relay is the one shape a browser
        # could read through -- stripped by name.
        _lie = FakeStrata(LIE_FAKE, "liebox")
        _lie.lie = True
        _lie.start()
        _proc_lie = subprocess.Popen(
            [sys.executable, ROUTER,
             "--backend", '{"id":"lie","url":"http://127.0.0.1:%d"}' % LIE_FAKE,
             "--listen", "127.0.0.1", "--port", str(LIE_ROUTER), "--log-level", "WARNING"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for(lambda: get(LIE_ROUTER, "/healthz")[0] == 200)
            _lc = http.client.HTTPConnection("127.0.0.1", LIE_ROUTER, timeout=10)
            _lc.request("GET", "/v1/lie")
            _lr = _lc.getresponse()
            _ls, _lao, _lbody = _lr.status, _lr.getheader("access-control-allow-origin"), _lr.read()
            _lc.close()
            check("access-control-* from a lying box NEVER rides the passthrough (browser-read "
                  "channel closed); status+body relay intact (stress P1/F1)",
                  _ls == 200 and _lao is None and _lbody == b"{}",
                  "status=%s ao=%r body=%r" % (_ls, _lao, _lbody[:40]))
        finally:
            _proc_lie.kill()
            try:
                _proc_lie.wait(timeout=5)
            except Exception:
                pass
            _lie.kill()

        # F8: the keys file refuses non-string values since v1.2.11 -- the
        # INLINE config door gets the same doctrine.
        _t8 = dict(R.DEFAULTS)
        _t8["backends"] = [{"id": "t", "url": "http://127.0.0.1:9", "backend_api_key": True}]
        _t8["backend_api_key"] = 12345
        _t8["control_token"] = True
        _t8["rewrite_model"] = {"in": {"bad": "shape"}, "ok": "fine"}
        _p8 = R.validate_cfg(_t8, R.make_pool(_t8), strict=False)
        _k8 = " ".join(k for k, _w in _p8)
        check("inline typed junk (true/123 as key/token, dict as rewrite value) refuses boot -- "
              "keys-file doctrine at the inline door (stress P1/F8)",
              "t.backend_api_key" in _k8 and _k8.count("backend_api_key") >= 2
              and "control_token" in _k8 and "rewrite_model" in _k8, _k8[:200])

        # P2(a/b): the scope must survive type flattening, anon must see everything.
        def _ak(body):
            return R.affinity_key_of("/v1/messages", body, {})
        _msgs = [{"role": "user", "content": "identical first turn"}]
        _u1 = json.dumps({"metadata": {"user_id": 1}, "messages": _msgs}).encode()
        _u2 = json.dumps({"metadata": {"user_id": 2}, "messages": _msgs}).encode()
        _us = json.dumps({"metadata": {"user_id": "1"}, "messages": _msgs}).encode()
        check("non-string metadata.user_id still SCOPES: sessions 1, 2 and \"1\" with an identical "
              "first turn get three distinct lanes (stress P2a)",
              len({_ak(_u1), _ak(_u2), _ak(_us)}) == 3 and all(_ak(_u1).startswith("meta:") for _ in [0]),
              "%s %s %s" % (_ak(_u1)[:14], _ak(_u2)[:14], _ak(_us)[:14]))
        _c1 = json.dumps({"prompt_cache_key": 12345, "messages": _msgs}).encode()
        _c2 = json.dumps({"prompt_cache_key": "12345", "messages": _msgs}).encode()
        check("prompt_cache_key 12345 and \"12345\" are no longer the same session "
              "(type aliasing dead; stress P2a)", _ak(_c1) != _ak(_c2), "%s == %s?" % (_ak(_c1)[:14], _ak(_c2)[:14]))
        _pfx = b"NOTJSON" + b"p" * 70000
        _a1, _a2 = _pfx + b"-one", _pfx + b"-two"
        check("anon lanes hash the FULL body: two malformed bodies past 64 KB with an identical "
              "prefix part ways (stress P2b)", _ak(_a1) != _ak(_a2) and _ak(_a1).startswith("anon:"),
              "%s %s" % (_ak(_a1)[:16], _ak(_a2)[:16]))

        # P2(C4): the last-resort counter is honest in BOTH directions.
        _lcfg = dict(R.DEFAULTS)
        _lcfg["backends"] = [{"id": "t", "url": "http://127.0.0.1:9", "require_idle": True}]
        _lcfg["status_interval"] = 3600
        _lp = R.make_pool(_lcfg)
        _lb = _lp.backends[0]           # gate CLOSED (never reported): unknown != idle
        _bg0, _nc = _lb.begin, [0]

        def _race_begin():
            _nc[0] += 1                 # first reservation loses the race (trial),
            return False if _nc[0] == 1 else _bg0()   # the fallback one wins

        _lb.begin = _race_begin
        _m0 = {k: _lp.metrics[k] for k in ("new_placements", "last_resort", "gate_bypass_borrow")}
        _lbe, _lreason, _lres, _ltok = _lp.pick("meta:r/lane:race")
        check("a reservation race at a LIVE box books as placed + borrow, never as last_resort "
              "(metric honesty; stress P2/C4)",
              _lreason == "placed" and _lres
              and _lp.metrics["new_placements"] == _m0["new_placements"] + 1
              and _lp.metrics["last_resort"] == _m0["last_resort"]
              and _lp.metrics["gate_bypass_borrow"] == _m0["gate_bypass_borrow"] + 1,
              "reason=%s %s" % (_lreason, _lp.metrics["last_resort"]))
        _lp2 = R.make_pool(_lcfg)
        _lb2 = _lp2.backends[0]
        _lb2.state = R.DOWN
        _lb2.down_until = time.monotonic() + 60
        _lr0 = _lp2.metrics["last_resort"]
        _lbe2, _lreason2, _lres2, _ltok2 = _lp2.pick("meta:r/lane:down")
        check("all boxes in down-cooldown still forward (never reject) and book the HONEST "
              "last_resort (stress P2/C4)",
              _lreason2 == "last_resort" and not _lres2
              and _lp2.metrics["last_resort"] == _lr0 + 1,
              "reason=%s res=%s" % (_lreason2, _lres2))

        print("")
        print("5g) stress-Q guards (v1.2.13) -- status-line smuggling, honest error taxonomy, counters")

        # Q2A-1 / Q2A-7 / Q2-F1 / Q2A-3 all need the lying box: one rig.
        _qlie = FakeStrata(LIE_FAKE, "liebox")
        _qlie.lie = True
        _qlie.start()
        _qproc = subprocess.Popen(
            [sys.executable, ROUTER,
             "--backend", '{"id":"lie","url":"http://127.0.0.1:%d"}' % LIE_FAKE,
             "--listen", "127.0.0.1", "--port", str(LIE_ROUTER), "--log-level", "WARNING"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for(lambda: get(LIE_ROUTER, "/healthz")[0] == 200)

            # Q2A-1: CR inside the reason phrase rides the WIRE STATUS LINE
            # verbatim (send_response does not escape it), and a lone CR ends
            # the line for WHATWG-fetch parsers -- a forged header above every
            # header-side filter. The sanitizer must relay the standard phrase.
            _ql = _raw(LIE_ROUTER, b"GET /v1/lieline HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                       b"Connection: close\r\n\r\n" % LIE_ROUTER, read=6.0)
            _qfirst = _ql.split(b"\r\n", 1)[0]      # an INTERNAL CR is the smuggling
            check("CR-injected reason phrase NEVER reaches the caller's status line: the forged "
                  "header dies, standard phrase + real status + body survive (stress Q1/Q2A-1)",
                  _ql.startswith(b"HTTP/1.1 200 OK") and b"\r" not in _qfirst
                  and b"access" not in _ql.lower()
                  and b"2\r\n{}" in _ql and _ql.endswith(b"0\r\n\r\n"),
                  "first=%r total=%s" % (_qfirst[:80], len(_ql)))

            # Q2A-7: a box that ANSWERS with an over-long header line raises
            # LineTooLong in the router's own parser. That is NOT the "did not
            # start answering, may still complete" timeout story -- nothing is
            # in flight. Honest 502, box keeps its health (it did answer).
            _qs, _qh, _qb, _qw = call(LIE_ROUTER, "/v1/big",
                                      {"model": "test-model", "messages": [{"role": "user", "content": "q2a7"}]})
            _qafter = stats(LIE_ROUTER)
            check("unparseable box response answers as backend_protocol_error, never the 'may still "
                  "complete' timeout lie; a box that answered keeps its health (stress Q1/Q2A-7)",
                  _qs == 502 and "backend_protocol_error" in _qb
                  and _qafter["backends"][0]["state"] == "healthy",
                  "status=%s body=%r" % (_qs, _qb[:110]))

            # Q2-F1: the window between the box's first byte and headers_out
            # used to book EVERY caller-side write failure as "no first byte
            # after send" (stream error + ghost debt + timeout 502) -- against
            # a box that had ANSWERED. 25 RST-during-relay probes; the storm
            # must move NOT ONE stream_error (the old code's own probes landed
            # in that branch; the new code can only land in the two abort
            # branches, neither of which charges the box).
            # The probe rides "slow-stream" and waits for the first RELAYED
            # byte before RST-ing (open-source fix batch): firing the RST
            # right after sendall left "mid-relay" to the race, and a piped
            # stdout (run_all_tests captures) shifts that race -- the storm
            # then completed relays instead of aborting them and booked zero
            # aborts. First byte in hand = the box answered AND the relay is
            # live; the router's next write to the dead socket then fails by
            # construction, in console AND pipe modes alike.
            _qb0 = stats(LIE_ROUTER)["backends"][0]["stats"]
            for _qi in range(25):
                try:
                    _qc = socket.create_connection(("127.0.0.1", LIE_ROUTER), 5)
                    _qc.settimeout(10)
                    _qjb = json.dumps({"model": "slow-stream",
                                       "messages": [{"role": "user", "content": "q2f1-%d" % _qi}]}).encode()
                    _qc.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                                b"content-type: application/json\r\ncontent-length: %d\r\n\r\n"
                                % (LIE_ROUTER, len(_qjb)) + _qjb)
                    _qc.recv(1)          # blocks till the relay is verifiably live
                    _qc.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    _qc.close()          # RST while the answer is mid-relay
                except OSError:
                    pass
            time.sleep(1.2)              # let every handler thread reach its except
            _qb1 = stats(LIE_ROUTER)["backends"][0]["stats"]
            check("caller RST during relay of an ALREADY-ANSWERED request books as an abort, never "
                  "as a backend stall: zero stream_errors across a 25-shot RST storm (stress Q2/F1)",
                  _qb1["stream_errors"] == _qb0["stream_errors"]
                  and _qb1["aborted_by_client"] > _qb0["aborted_by_client"],
                  "stream %s->%s aborted %s->%s" % (_qb0["stream_errors"], _qb1["stream_errors"],
                                                    _qb0["aborted_by_client"], _qb1["aborted_by_client"]))

            # Q2A-3: OPTIONS must answer 405 on EVERY path (the README always
            # said so) -- it used to alias into do_POST, so a preflight-shaped
            # probe either EXECUTED a real inference or left a chunked body
            # unread on the socket.
            _qr0 = stats(LIE_ROUTER)["router"]["requests"]
            _qo1 = _raw(LIE_ROUTER, b"OPTIONS /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                        b"Connection: close\r\n\r\n" % LIE_ROUTER)
            _qo2 = _raw(LIE_ROUTER, b"OPTIONS /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                        b"transfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" % LIE_ROUTER, read=8.0)
            _qr1 = stats(LIE_ROUTER)["router"]["requests"]
            check("OPTIONS answers a named 405 on EVERY path (no silent do_POST proxy), even with a "
                  "chunked body -- eaten politely, requests stays flat (stress Q1/Q2A-3)",
                  b"405" in _qo1 and b"405" in _qo2 and b"OPTIONS" in _qo2 and _qr1 == _qr0,
                  "o1=%r o2=%r requests %s->%s" % (_qo1[:30], _qo2[:30], _qr0, _qr1))

            # Q2A-2 + Q2-F6 (in-process): the control gate's two wiring holes.
            _t9 = dict(R.DEFAULTS)
            _t9["backends"] = [{"id": "t", "url": "http://127.0.0.1:9"}]
            _t9["control_token"] = "NEVER\r\nX-Injected: 1"      # ASCII, but carries CR/LF
            _p9 = [k for k, _w in R.validate_cfg(_t9, R.make_pool(_t9), strict=False)]
            check("a control_token carrying control bytes (ASCII CR/LF sneaks past isascii) refuses "
                  "boot -- its gate could never open for its owner (stress Q1/Q2A-2)",
                  "control_token" in " ".join(_p9), " ".join(_p9)[:160])

            class _GateA:
                cfg = {"control_token": "inline-only"}           # inline set, apply_keys skipped
                headers = {}
            class _GateB:
                cfg = {"control_token": "inline-only"}
                headers = {"x-strata-control": "inline-only"}
            class _GateC:
                cfg = {"_control_token": ""}                     # the normal no-token boot
                headers = {}
            check("an embedded boot that skipped apply_keys still HONORS its inline control_token "
                  "(fails closed without the header, opens with it; the real no-token boot stays "
                  "open -- stress Q2/F6)",
                  not R.Handler._control_ok(_GateA()) and R.Handler._control_ok(_GateB())
                  and R.Handler._control_ok(_GateC()),
                  "A=%s B=%s C=%s" % (R.Handler._control_ok(_GateA()),
                                      R.Handler._control_ok(_GateB()),
                                      R.Handler._control_ok(_GateC())))
        finally:
            _qproc.kill()
            try:
                _qproc.wait(timeout=5)
            except Exception:
                pass
            _qlie.kill()

        # Q2A-4 = Q2/F5: the rebinding guard must RECOGNIZE IPv6 literals in
        # Origin/Referer -- it used to parse "[::1]" down to "[" and 403 its
        # own owner (fail-closed, but closed on the wrong side).
        _g1 = _raw(ROUTER_PORT, b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                   b"Origin: http://[::1]:9999\r\nConnection: close\r\n\r\n" % ROUTER_PORT)
        _g2 = _raw(ROUTER_PORT, b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                   b"Origin: http://[::2]:9999\r\nConnection: close\r\n\r\n" % ROUTER_PORT)
        check("Origin: http://[::1] is admitted as the local caller it is, while http://[::2] "
              "still gets the named 403 (stress Q1/Q2A-4 = Q2/F5)",
              _g1.startswith(b"HTTP/1.1 200") and b"403" in _g2 and b"cross-origin" in _g2,
              "g1=%r g2=%r" % (_g1[:34], _g2[:34]))

        # Q2A-5: a door-refusal against a CHUNKED body (TE outranks any
        # content-length -- nothing to count down) must still reach its
        # sender: eat the body under the quiet deadline, THEN answer+close.
        _qcs = socket.create_connection(("127.0.0.1", ROUTER_PORT), 5)
        _qcs.settimeout(8.0)
        try:
            _qhead = (b"POST http://evil.test/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                      b"transfer-encoding: chunked\r\n\r\n" % ROUTER_PORT)
            _qcs.sendall(_qhead + (b"1000\r\n" + b"z" * 4096 + b"\r\n") * 50 + b"0\r\n\r\n")
            _qcs.shutdown(socket.SHUT_WR)          # honest FIN: the drain ends at EOF
            _qcd = b""
            try:
                while len(_qcd) < 65536:
                    _qcg = _qcs.recv(4096)
                    if not _qcg:
                        break
                    _qcd += _qcg
            except OSError:
                pass
        finally:
            _qcs.close()
        check("absolute-form + chunked: the 400 reaches the sender over a live socket instead of "
              "being RST-flushed away (stress Q1/Q2A-5)",
              _qcd.startswith(b"HTTP/1.1 400") and b"origin-form" in _qcd,
              "%r" % _qcd[:60])

        # Q2/F4: junk header NAMES (non-token) used to ride the request path
        # into the box verbatim -- betting the box's parser on shapes ours
        # rejects. They must be dropped on the way out; good headers unaffected.
        _hn0 = (len(a.seen_hdr_names), len(b.seen_hdr_names))
        _qhs = socket.create_connection(("127.0.0.1", ROUTER_PORT), 5)
        _qhs.settimeout(8.0)
        try:
            _qhb = json.dumps({"model": "test-model",
                               "messages": [{"role": "user", "content": "q2f4-name"}]}).encode()
            _qhs.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                         b"content-type: application/json\r\n"
                         b"x(bad: smuggled\r\nx-good-marker: keep\r\n"
                         b"content-length: %d\r\nConnection: close\r\n\r\n" % (ROUTER_PORT, len(_qhb)) + _qhb)
            _qhd = b""
            try:
                while len(_qhd) < 65536:
                    _qhg = _qhs.recv(4096)
                    if not _qhg:
                        break
                    _qhd += _qhg
            except OSError:
                pass
        finally:
            _qhs.close()
        _qnames = [n for _lst in (a.seen_hdr_names[_hn0[0]:], b.seen_hdr_names[_hn0[1]:])
                   for _seen in _lst for n in _seen]
        check("a junk header NAME never rides the request path into the box (token-only names); "
              "legitimate headers still forward (stress Q2/F4)",
              _qhd.startswith(b"HTTP/1.1 200") and "x-good-marker" in _qnames
              and not any("(" in n or " " in n or ":" in n for n in _qnames),
              "new names=%r" % (_qnames[:8],))

        # Q2/F3: the identity's LAST term must be observable -- a pin takeover
        # drops a lane's pending re-homes; those cancellations are counted now
        # (requests == placements + fizzles + evictions + operator_cancelled).
        _ocfg = dict(R.DEFAULTS)
        _ocfg["backends"] = [{"id": "a", "url": "http://127.0.0.1:9"},
                             {"id": "b", "url": "http://127.0.0.1:9"}]
        _ocfg["status_interval"] = 3600
        _op = R.make_pool(_ocfg)
        with _op.lock:
            _op._stash_pending("t1", ("laneQ", "a", "b"))
            _op._stash_pending("t2", ("laneQ", "a", "b"))
            _op._stash_pending("t3", ("laneR", "a", "b"))
        _op._overflow_drop_key("laneQ")
        check("operator-cancelled overflow re-homes are COUNTED (identity closeable from /stats "
              "alone after an operator touches the lane; stress Q2/F3)",
              _op.metrics["operator_cancelled"] == 2 and len(_op._overflow_pending) == 1
              and "operator_cancelled" in _op.status(),
              "cancelled=%s pending=%s" % (_op.metrics["operator_cancelled"], len(_op._overflow_pending)))

        # Q2/F2: with every tier refusing, the last-resort forward used to pick
        # its box by load_score's random tie-break and try begin() ONCE -- a
        # coin flip could book last_resort(reserved=False) while another box
        # had its half-open trial free for exactly this forward. The walk tries
        # each candidate in load order, so the trial actually gets taken.
        _owcfg = dict(R.DEFAULTS)
        _owcfg["backends"] = [{"id": "ob1", "url": "http://127.0.0.1:9", "require_idle": True},
                              {"id": "ob2", "url": "http://127.0.0.1:9", "require_idle": True}]
        _owcfg["status_interval"] = 3600          # never reported -> gate closed (unknown != idle)
        _owp = R.make_pool(_owcfg)
        _ob1, _ob2 = _owp.by_id["ob1"], _owp.by_id["ob2"]
        _ow_ok = True
        for _wi in range(6):
            _ob1.state = R.DOWN
            _ob1.down_until = time.monotonic() + 60      # mid-cooldown: no trial possible
            _ob1.trial_open = False
            _ob2.state = R.DOWN
            _ob2.down_until = time.monotonic() - 1       # cooldown over: trial IS possible
            _ob2.trial_open = False
            _obe, _oreason, _ores, _ = _owp.pick("meta:q/f2:lane")
            # begin() OPENS the half-open trial -- flipping the box DOWN ->
            # SUSPECT -- so the C4 branch may honestly book the forward as
            # "placed"; what Q2/F2 demanded is that the reserved forward LANDS
            # on the trial-free candidate EVERY round, never on a coin flip.
            if not (_oreason in ("placed", "last_resort") and _ores and _obe.id == "ob2"):
                _ow_ok = False
                break
            _ob2.trial_open = False                      # release the trial for the next round
        check("last-resort takes the candidate whose half-open trial is actually FREE (deterministic "
              "walk in load order, never the reserved-False coin flip; stress Q2/F2)", _ow_ok,
              "last try: reason=%s reserved=%s box=%s" % (_oreason, _ores, _obe.id))

        print("")
        print("6) per-backend keys -- each box authenticates with its own key")
        a.require_key, b.require_key = "smoke-ka-9d41", "smoke-kb-9d41"
        proc3 = subprocess.Popen(
            [sys.executable, ROUTER,
             "--backend", '{"id":"L","url":"http://127.0.0.1:%d","backend_api_key":"smoke-ka-9d41"}' % A_PORT,
             "--backend", '{"id":"R","url":"http://127.0.0.1:%d","backend_api_key":"smoke-kb-9d41"}' % B_PORT,
             "--listen", "127.0.0.1", "--port", str(ROUTER3_PORT),
             "--status-interval", "0.2", "--log-level", "WARNING"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            check("per-key router starts", wait_for(lambda: get(ROUTER3_PORT, "/healthz")[0] == 200, 20))

            def kstats():
                return {x["id"]: x for x in stats(ROUTER3_PORT)["backends"]}

            check("status polls authenticate with each box's own key",
                  wait_for(lambda: all(kstats()[i]["status_ok"] and (kstats()[i]["reported"] or {}).get("serving") is not None
                                       for i in ("L", "R")), 10))
            check("stats prove a key is configured per box, never expose the key",
                  all(kstats()[i]["has_api_key"] is True for i in ("L", "R")))
            _raws = get(ROUTER3_PORT, "/__router/stats")[1]
            check("the raw stats body contains NEITHER box key anywhere (T1)",
                  "smoke-ka-9d41" not in _raws and "smoke-kb-9d41" not in _raws, _raws[:80])
            st, h, _bb, _w = call(ROUTER3_PORT, "/v1/messages", conv("key-pin-L"),
                                  extra={"x-api-key": None, "x-strata-pin": "L"})
            check("client without a key -> router injects the LOCAL box's key",
                  st == 200 and h.get("x-strata-backend") == "L", "status=%s box=%s" % (st, h.get("x-strata-backend")))
            st, h, _bb, _w = call(ROUTER3_PORT, "/v1/messages", conv("key-pin-R"),
                                  extra={"x-api-key": None, "x-strata-pin": "R"})
            check("the borrowed box accepted a DIFFERENT key of its own",
                  st == 200 and h.get("x-strata-backend") == "R", "status=%s box=%s" % (st, h.get("x-strata-backend")))
            _s14 = stats(ROUTER3_PORT)
            _bL14 = next(b for b in _s14["backends"] if b["id"] == "L")
            check("v1.2.14: /stats carries started_at/uptime_s/status_interval facts and they are sane",
                  isinstance(_s14.get("started_at"), int) and 0 < _s14["started_at"] <= int(time.time()) + 2
                  and _s14.get("uptime_s", -1) >= 0
                  and isinstance(_s14.get("status_interval"), (int, float))
                  and 0 < _s14["status_interval"] <= 3600,
                  str({k: _s14.get(k) for k in ("started_at", "uptime_s", "status_interval")}))
            check("v1.2.14: finished requests feed the box's bytes_out counter and the rolling ttfb window",
                  _bL14["stats"].get("bytes_out", 0) > 0 and _bL14.get("recent_ttfb_n", 0) >= 1
                  and _bL14.get("recent_ttfb_avg_s") is not None,
                  "bytes=%s n=%s avg=%s" % (_bL14["stats"].get("bytes_out"),
                                            _bL14.get("recent_ttfb_n"), _bL14.get("recent_ttfb_avg_s")))
            st, h, _bb, _w = call(ROUTER3_PORT, "/v1/messages", conv("key-client-wins"),
                                  extra={"x-api-key": "wrong-on-purpose", "x-strata-pin": "R"})
            check("a caller's stale shim key is REPLACED by the configured box key (S2: shim bearer must not 401 the boxes)",
                  st == 200 and h.get("x-strata-backend") == "R",
                  "status=%s box=%s %s" % (st, h.get("x-strata-backend"), _bb[:60]))
            b.require_key = "smoke-kb-rotated-9d41"   # peer rotated their key; our borrower copy went stale

            def _keypin(cx, api):
                # The fake box occasionally accepts then dies pre-first-byte
                # under these back-to-back pairs (~1% reproduced in a focused
                # 300-iteration loop); the router's answer to that is PINNED
                # elsewhere (502, no retry on a POST, box stays healthy). So
                # the harness may re-ask a box that was never answered --
                # but ONLY that exact failure; any other 502 still fails.
                for _try in range(6):
                    _st, _h, _bb, _w = call(ROUTER3_PORT, "/v1/messages", conv(cx),
                                            extra={"x-api-key": api, "x-strata-pin": "R"})
                    if _st != 502 or "accepted the request but" not in _bb:
                        return _st, _bb
                    time.sleep(0.15)
                return _st, _bb
            st, _bb = _keypin("key-stale", None)
            st2, _bb2 = _keypin("key-nooverride", "smoke-kb-rotated-9d41")
            check("the caller CANNOT override the configured key -- even the RIGHT one sent by the client still 401s (the router's copy rules)",
                  st2 == 401, "status=%s" % st2)
            bx = kstats()
            check("stale borrower key: injected AS-IS, 401 relayed, box stays in the pool (rule 4)",
                  st == 401 and "wrong API key" in _bb and bx["R"]["state"] == "healthy",
                  "status=%s state=%s body=%s" % (st, bx["R"]["state"], _bb[:60]))
        finally:
            a.require_key = b.require_key = None
            check("stats expose gate_bypass_borrow -- the fail-open borrow is countable (B8)",
                  "gate_bypass_borrow" in stats(ROUTER_PORT)["router"])
            st, _h, _bb, _w = call(ROUTER_PORT, "/v1/messages", conv("key-passthru"),
                                   extra={"x-api-key": "caller-passthru-7f3"})
            check("backend WITHOUT a configured key still receives the caller's auth verbatim",
                  st == 200 and ("caller-passthru-7f3" in a.seen_auths or "caller-passthru-7f3" in b.seen_auths),
                  "status=%s" % st)
            _term(proc3)
            try:
                proc3.wait(timeout=5)
            except Exception:
                proc3.kill()

        print("")
        print("7) L2-review regressions -- refutation-tested defects must stay dead")

        # startup validation: typo'd / mistyped / placeholder knobs refuse to serve
        badcfg = dict(R.DEFAULTS)
        badcfg["max_body_mb"] = "big"
        badcfg["backends"] = [
            {"id": "x", "url": "http://127.0.0.1:1", "priority": "high", "require_idle": "false"},
            {"id": "y", "url": "http://127.0.0.1:2", "backend_api_key": "REPLACE-WITH-THIS-BOX-KEY"},
            {"id": "z", "url": "http://127.0.0.1:3", "backend_api_key": "密钥-cannot-be-a-header"},
        ]
        badpool = R.make_pool(badcfg)
        problems = R.validate_cfg(badcfg, badpool, strict=False)
        pkeys = " ".join(k for k, _w in problems)
        check("startup validation catches mistyped knobs, string booleans, placeholders and unsendable keys",
              "max_body_mb" in pkeys and "x.priority" in pkeys and "x.require_idle" in pkeys
              and "y.backend_api_key" in pkeys and "z.backend_api_key" in pkeys,
              "; ".join("%s: %s" % p for p in problems)[:220])
        try:
            R.validate_cfg(badcfg, badpool, strict=True)
            refused = False
        except SystemExit:
            refused = True
        check("a bad config refuses to serve instead of silently failing open", refused)

        # pre-v1.2.18 round-1 face M (P2 + narrow TPs): an empty listen "" booted
        # and bound EVERY interface (netstat-proven) while the rebinding guard
        # went on trusting Host: localhost -- a silent fail-open on a router that
        # injects keys; and a malformed-SHAPE inline key echoed its raw value
        # into every problems sink (both boot branches, sentinel-proven). Both
        # must die at the door: empty listen refused BY NAME, key values never
        # echoed -- only the type name is safe to print for key-shaped fields.
        _sent = "SENTINEL-KEY-SHAPE-9f13"
        _empty = dict(R.DEFAULTS)
        _empty["listen"] = ""
        _empty["backends"] = [{"id": "a", "url": "http://127.0.0.1:1", "priority": 0}]
        _eprob = " ".join("%s: %s" % pk for pk in R.validate_cfg(_empty, R.make_pool(_empty), strict=False))
        check("an empty listen is refused BY NAME (a bare '' would bind every interface "
              "behind a loopback-trusting guard)",
              "listen" in _eprob and "interface" in _eprob.lower(), _eprob[:160])
        try:
            R.validate_cfg(_empty, R.make_pool(_empty), strict=True)
            _refused_empty = False
        except SystemExit:
            _refused_empty = True
        check("an empty listen alone refuses to serve in strict boot (fail-open lock)", _refused_empty)
        _shape = dict(R.DEFAULTS)
        _shape["backends"] = [{"id": "a", "url": "http://127.0.0.1:1", "priority": 0,
                               "backend_api_key": [_sent]}]
        _shape["control_token"] = {"nested": _sent}
        _sj = " ".join("%s: %s" % pk for pk in R.validate_cfg(_shape, R.make_pool(_shape), strict=False))
        check("a malformed-shape inline backend_api_key/control_token is refused BY TYPE "
              "with the value never echoed",
              _sent not in _sj and _sj.count("must be a JSON string") >= 2, _sj[:200])

        # pre-1.2.18 round-2 (OS-O F-1 + adjudication reclass of F-3): a NON-STRING
        # listen died AFTER a lying "listening on http://None" INFO with a raw
        # gaierror traceback -- and int 0 collapses the rebinding guard's falsy
        # branch back to loopback-name trust while glibc parses "0" as INADDR_ANY:
        # the exact fail-open fix5 closed, re-opened on Linux via a JSON number.
        _tparts = []
        for _badln in (0, None, False):
            _t = dict(R.DEFAULTS)
            _t["listen"] = _badln
            _t["backends"] = [{"id": "a", "url": "http://127.0.0.1:1", "priority": 0}]
            _tparts += ["%s: %s" % pk for pk in R.validate_cfg(_t, R.make_pool(_t), strict=False)]
        _tprob = " ".join(_tparts)
        check("a non-string listen (0/null/false) is refused BY TYPE pre-bind -- no "
              "bind-time traceback, no lying 'listening' INFO (probe side)",
              _tprob.count("listen: must be a JSON string") >= 3, _tprob[:200])
        try:
            _t2 = dict(R.DEFAULTS)
            _t2["listen"] = 0
            _t2["backends"] = [{"id": "a", "url": "http://127.0.0.1:1", "priority": 0}]
            R.validate_cfg(_t2, R.make_pool(_t2), strict=True)
            _refused_t = False
        except SystemExit:
            _refused_t = True
        check("strict boot refuses a non-string listen too (guard-collapse fail-open lock)", _refused_t)

        # Open-source readiness L2 (OSB/P2-1): the stranger journey's FIRST
        # command is `--config router.json`, typed before step 0 ever created
        # that file. A raw FileNotFoundError wall must not be the project's
        # introduction -- boot names the file and points at the example.
        try:
            R.build_cfg(["--config", "no-such-router-box.json"])
            _cfgerr = ""
        except SystemExit as _exc_cfg:
            _cfgerr = str(_exc_cfg.code if _exc_cfg.code is not None else "")
        except FileNotFoundError as _exc_cfg:
            _cfgerr = "FileNotFoundError: %s" % _exc_cfg
        check("a missing --config dies with a named error and the example hint",
              "config file not found" in _cfgerr.lower()
              and "router.remote.example.json" in _cfgerr, _cfgerr[:200])

        # OS-C/C-5: the same door had wider frames -- a directory, an empty
        # file, or broken bytes died with a raw traceback (rc=1 but pre-bind,
        # so INFO-grade; still the first thing a stranger typos). Unreadable
        # must die BY NAME like the missing case: this check passes a
        # directory as --config and forbids any traceback in the death.
        try:
            R.build_cfg(["--config", os.path.dirname(os.path.abspath(__file__))])
            _cfgerr2 = ""
        except SystemExit as _exc_cfg:
            _cfgerr2 = str(_exc_cfg.code if _exc_cfg.code is not None else "")
        except OSError as _exc_cfg:
            _cfgerr2 = "OSError: %s" % _exc_cfg
        check("an unreadable --config (a directory here) dies with a named error, never a traceback",
              "config file not readable" in _cfgerr2.lower()
              and "traceback" not in _cfgerr2.lower(), _cfgerr2[:200])

        # Review L1-3/L2: a PRISTINE placeholder config (global placeholder,
        # no keys file) already refuses boot with the NAMED placeholder error
        # -- the shared-fallback warning then piled a false "wrong key for a
        # borrowed box" alarm on a config that holds no key at all.
        _vcfg = dict(R.DEFAULTS)
        _vcfg["backends"] = [{"id": "bx", "url": "http://127.0.0.1:8080", "require_idle": True}]
        _vcfg["backend_api_key"] = "REPLACE-WITH-THIS-BOX-KEY"
        _vsink = []

        class _VH(logging.Handler):
            def emit(self, record):
                _vsink.append(record.getMessage())

        _vh = _VH()
        R.LOG.addHandler(_vh)
        try:
            R.apply_keys(_vcfg, os.path.join(os.getcwd(), "smoke-vcfg.json"))
            _vprob = R.validate_cfg(_vcfg, R.make_pool(_vcfg), strict=False)
        finally:
            R.LOG.removeHandler(_vh)
        _vtxt = " | ".join(_vsink) + " || " + " | ".join("%s: %s" % pk for pk in _vprob)
        check("a placeholder config gets the named placeholder error WITHOUT a false shared-fallback-key warning",
              any("placeholder" in pk[1] for pk in _vprob) and not any("resolved from" in m for m in _vsink),
              _vtxt[:220])

        # DNS-rebinding guard: the router injects keys, so it must know its callers
        st, _h, _bb, _w = call(ROUTER_PORT, "/v1/messages", conv("guard-host"), extra={"Host": "attacker.example.com"})
        check("foreign Host refused (rebinding guard)", st == 403, "status=%s" % st)
        st, _h, _bb, _w = call(ROUTER_PORT, "/v1/messages", conv("guard-origin"), extra={"origin": "http://evil.example.com"})
        check("cross-origin browser caller refused", st == 403, "status=%s" % st)
        _conn = http.client.HTTPConnection("127.0.0.1", ROUTER_PORT, timeout=10)
        _conn.request("GET", "/healthz", headers={"referer": "http://evil.example.com/x"})
        st = _conn.getresponse().status
        _conn.close()
        check("admin routes guarded too (foreign Referer -> 403)", st == 403, "status=%s" % st)
        st, _h, _bb, _w = call(ROUTER_PORT, "/v1/messages", conv("guard-ok"))
        check("normal local caller unaffected by the guard", st == 200, "status=%s" % st)

        # control chars in the path die at the edge; they never become a fake outage
        bx0 = {x["id"]: x for x in stats(ROUTER_PORT)["backends"]}
        errs0 = sum(bx0[i]["stats"]["connect_errors"] for i in bx0)
        worst = b""
        for _i in range(3):
            _s = socket.create_connection(("127.0.0.1", ROUTER_PORT), timeout=5)
            _s.sendall(b"POST /a\x01b HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Length: 0\r\n\r\n" % ROUTER_PORT)
            worst = _s.recv(4096)
            _s.close()
        bx1 = {x["id"]: x for x in stats(ROUTER_PORT)["backends"]}
        errs1 = sum(bx1[i]["stats"]["connect_errors"] for i in bx1)
        check("control-char path -> 400 at the edge, never charged to a backend (rule 4 stays clean)",
              worst.startswith(b"HTTP/1.1 400")
              and errs1 == errs0
              and all(bx1[i]["state"] == "healthy" for i in bx1),
              "resp=%r errs %s->%s" % (worst[:16], errs0, errs1))

        # non-ASCII in the request line: http.client sends the line as ASCII,
        # so a high-bit byte must die at the edge, never mid-relay (A2)
        _s = socket.create_connection(("127.0.0.1", ROUTER_PORT), timeout=5)
        _s.sendall(b"GET /caf\xe9 HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % ROUTER_PORT)
        _resp = _s.recv(4096)
        _s.close()
        check("non-ASCII request path -> 400 at the edge (no handler death)",
              _resp.startswith(b"HTTP/1.1 400"), repr(_resp[:40]))

        # S1 regression: bytes must CROSS the relay while the stream is still
        # open. The fake sends a keep-alive comment then sits silent 0.5 s --
        # exactly what Strata does every 10 s for a parked stream. A relay
        # using read(n) buffers it to EOF; read1 delivers it now.
        _lbody = conv("live-stream")
        _lbody["model"] = "slow-stream"
        _lraw = json.dumps(_lbody).encode()
        _s = socket.create_connection(("127.0.0.1", ROUTER_PORT), timeout=10)
        _s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\ncontent-type: application/json\r\n"
                   b"content-length: %d\r\n\r\n" % (ROUTER_PORT, len(_lraw)) + _lraw)
        _s.settimeout(5)
        _t0 = time.monotonic()
        _data = b""
        _early = False
        while time.monotonic() - _t0 < 3.0:
            try:
                _got = _s.recv(65536)
            except (socket.timeout, OSError):
                break
            if not _got:
                break
            _data += _got
            if b": keep-alive" in _data:
                _early = (time.monotonic() - _t0) < 0.45
                break
        _rest = b""
        while b"message_stop" not in _rest:
            try:
                _g2 = _s.recv(65536)
            except (socket.timeout, OSError):
                break
            if not _g2:
                break
            _rest += _g2
        _s.close()
        check("SSE relays LIVE: keep-alive crosses mid-stream (<0.45 s while the fake sits silent 0.5 s)",
              _early, "keep-alive at %.2fs" % (time.monotonic() - _t0))
        check("the same live stream still arrives whole (terminator intact)",
              b"message_stop" in (_data + _rest), repr((_data + _rest)[-60:]))

        # v1.2.4: a KILLED caller must release the box in ~1 s even while the
        # stream is silent. Writes to a dead localhost socket keep "succeeding"
        # (OS send buffers), so without the router's MSG_PEEK watchdog a killed
        # agent burns its full FIFO+prefill time for a corpse and starves
        # everyone queued behind it (observed in production).
        _bx = {x["id"]: x for x in stats(ROUTER_PORT)["backends"]}
        errs0_h = sum(x["stats"]["stream_errors"] for x in _bx.values())
        ab0_h = sum(x["stats"]["aborted_by_client"] for x in _bx.values())
        a.hang_seen_at = None
        b.hang_seen_at = None
        _hbody = conv("hang-1")
        _hbody["model"] = "hang-stream"
        _hraw = json.dumps(_hbody).encode()
        _s = socket.create_connection(("127.0.0.1", ROUTER_PORT), timeout=10)
        _s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\ncontent-type: application/json\r\n"
                   b"content-length: %d\r\n\r\n" % (ROUTER_PORT, len(_hraw)) + _hraw)
        _s.settimeout(8)
        _hd = b""
        while b": keep-alive" not in _hd:
            _g = _s.recv(65536)
            if not _g:
                break
            _hd += _g
        _hbox = "a" if b"x-strata-backend: a" in _hd.lower() else "b"
        _t0 = time.monotonic()
        _s.close()   # the caller hangs up mid-stream while the fake still "thinks"
        _rel = wait_for(lambda: getattr({"a": a, "b": b}[_hbox], "hang_seen_at") is not None, 3.0)
        _seen = getattr({"a": a, "b": b}[_hbox], "hang_seen_at")
        check("caller hangup releases the BACKEND in ~1 s (watchdog, not a lucky write)",
              _rel and (_seen - _t0) < 2.5, "box=%s dt=%s" % (_hbox, "n/a" if _seen is None else round(_seen - _t0, 2)))
        time.sleep(0.8)   # let the relay thread land its attribution
        _bx = {x["id"]: x for x in stats(ROUTER_PORT)["backends"]}
        errs1_h = sum(x["stats"]["stream_errors"] for x in _bx.values())
        ab1_h = sum(x["stats"]["aborted_by_client"] for x in _bx.values())
        check("the hangup counts as a client abort, NOT as stream errors or a box failure",
              ab1_h > ab0_h and errs1_h == errs0_h and all(x["state"] == "healthy" for x in _bx.values()),
              "aborted %s->%s stream_err %s->%s" % (ab0_h, ab1_h, errs0_h, errs1_h))
        check("router answers normally right after a watchdog release", get(ROUTER_PORT, "/healthz")[0] == 200)

        # ...and the watchdog must NOT fire on a pipelined client: readable
        # DATA is the next request, not a hangup (Strata's rule, kept verbatim).
        _pbody = conv("pipe-1")
        _pbody["model"] = "hang-stream"
        _praw = json.dumps(_pbody).encode()
        _s = socket.create_connection(("127.0.0.1", ROUTER_PORT), timeout=10)
        _s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\ncontent-type: application/json\r\n"
                   b"content-length: %d\r\n\r\n" % (ROUTER_PORT, len(_praw)) + _praw)
        _s.sendall(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n" % ROUTER_PORT)
        _s.settimeout(12)
        _acc = b""
        while b'"ok"' not in _acc:
            try:
                _g = _s.recv(65536)
            except (socket.timeout, OSError):
                break
            if not _g:
                break
            _acc += _g
        _s.close()
        check("pipelined bytes mid-stream mean NEXT REQUEST, not hangup (data != death)",
              _acc.count(b"HTTP/1.1 200") >= 2 and b'"ok"' in _acc and b"0\r\n\r\n" in _acc,
              "200s=%d head=%r" % (_acc.count(b"HTTP/1.1 200"), _acc[:40]))

        # HEAD: header-only framing, or the terminator desyncs the next response
        _conn = http.client.HTTPConnection("127.0.0.1", ROUTER_PORT, timeout=10)
        _conn.request("HEAD", "/v1/messages")
        _r = _conn.getresponse()
        hd = {k.lower(): v for k, v in _r.getheaders()}
        _conn.close()
        check("HEAD response carries no chunk framing", "transfer-encoding" not in hd and hd.get("content-length") == "0", str(hd)[:160])

        # admin POST with a body must drain it before answering (keep-alive framing)
        _conn = http.client.HTTPConnection("127.0.0.1", ROUTER_PORT, timeout=10)
        _conn.request("POST", "/__router/sticky/clear", body=b"x", headers={"content-type": "text/plain"})
        _conn.getresponse().read()
        _conn.request("POST", "/__router/sticky/clear")
        st = _conn.getresponse().status
        _conn.close()
        check("keep-alive stays framed after a body-carrying admin POST", st == 200, "status=%s" % st)

        # A5: read-timeout on a QUEUED request -- honest 502, box stays healthy.
        # A2: half-open trial admits exactly one; everyone else migrates.
        c = FakeStrata(C_PORT, "c", hold=0.3, serial=True)    # 0.3 < read-timeout 0.5: the head of the queue succeeds,
        d = FakeStrata(D_PORT, "d", hold=0.02, serial=True)   # anything parked behind it times out honestly
        c.start()
        d.start()
        proc4 = subprocess.Popen(
            [sys.executable, ROUTER,
             "--backend", "c=http://127.0.0.1:%d" % C_PORT,
             "--backend", "d=http://127.0.0.1:%d" % D_PORT,
             "--listen", "127.0.0.1", "--port", str(ROUTER4_PORT),
             "--max-connect-failures", "2", "--down-backoff", "2",
             "--status-interval", "0.2", "--read-timeout", "0.5", "--log-level", "WARNING"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            check("regression router starts", wait_for(lambda: get(ROUTER4_PORT, "/healthz")[0] == 200, 20))

            def ccall(tag, turns=1, extra=None):
                return call(ROUTER4_PORT, "/v1/messages", conv(tag, turns), extra=extra)

            def bx4():
                return {x["id"]: x for x in stats(ROUTER4_PORT)["backends"]}

            parked4 = []

            def park4(i):
                parked4.append(ccall("to-q-%d" % i, 1, {"x-strata-pin": "c"}))

            ts4 = [threading.Thread(target=park4, args=(i,), daemon=True) for i in range(3)]
            for t in ts4:
                t.start()
            for t in ts4:
                t.join(30)
            timed_out = [x for x in parked4 if x[0] == 502 and "backend_timeout" in x[2]]
            ok4 = [x for x in parked4 if x[0] == 200]
            check("queued requests past the read timeout get an honest backend_timeout (no retry bait)",
                  len(timed_out) >= 1 and len(ok4) >= 1 and "may still complete" in timed_out[0][2],
                  str([(x[0], x[2][:50]) for x in parked4])[:200])
            check("a slow-but-connected box stays healthy -- busy is not dead (rule 4)",
                  bx4()["c"]["state"] == "healthy" and bx4()["c"]["stats"]["connect_errors"] == 0,
                  "state=%s errs=%s" % (bx4()["c"]["state"], bx4()["c"]["stats"]["connect_errors"]))

            ccall("trial-conv", 1, {"x-strata-pin": "c"})     # home = c
            c.kill()
            check("dead home box detected", wait_for(lambda: bx4()["c"]["state"] == "down", 20))
            res5 = []

            def burst5():
                # /v1/responses answers instantly on the fake (no SSE event loop),
                # and the body's metadata.user_id keeps the SAME affinity key, so
                # the burst cannot be mistaken for read-timeouts queued on d
                res5.append(call(ROUTER4_PORT, "/v1/responses", conv("trial-conv", turns=4)))

            th5 = [threading.Thread(target=burst5, daemon=True) for _ in range(5)]
            for t in th5:
                t.start()
            for t in th5:
                t.join(30)
            on_d = [x for x in res5 if x[0] == 200 and x[1].get("x-strata-backend") == "d"]
            migrated_any = [x for x in res5 if x[1].get("x-strata-placement") == "migrated"]
            dead502 = [x for x in res5 if x[0] == 502]
            check("sticky traffic on a dead home converges on the survivor -- at most one eats the trial",
                  len(res5) == 5 and len(on_d) >= 4 and len(dead502) <= 1 and len(migrated_any) >= 1,
                  str([(x[0], x[1].get("x-strata-placement"), x[1].get("x-strata-backend")) for x in res5])[:220])

            # the begin() contract directly, no servers involved: a DOWN box past
            # its cooldown admits ONE half-open trial; everyone else gets False
            bu = R.Backend("u", "http://127.0.0.1:1", cfg={})
            bu.state, bu.down_until, bu.trial_open = R.DOWN, 0.0, False
            admits = (bu.begin(), bu.begin(), bu.begin())
            check("begin(): the half-open slot admits exactly one, then blocks until note_* clears it",
                  admits == (True, False, False) and bu.inflight == 1 and bu.trial_open is True,
                  "admits=%s inflight=%s" % (admits, bu.inflight))

            # ---- v1.2.2: status parsing against Strata's REAL schemas -------
            # (the fakes above already serve the real schema with decoys, so a
            # regression that re-promotes a capacity field breaks the tier
            # tests too; these pin the extractor itself, no servers involved)
            ps = R.parse_status
            st_idle = ps(json.dumps({"concurrency": {"serving": 1, "requested": 1},
                                     "activity": {"requests": 0, "in_flight": 0, "last_request_at": None},
                                     "vram": {"reserve_mib": 700, "expert_slots": 1200, "elastic": True}}))
            check("/v1/status idle: load is activity.in_flight=0 -- not capacity, not VRAM MiB",
                  st_idle == {"serving": 0.0, "queued": None}, str(st_idle))
            st_load = ps(json.dumps({"concurrency": {"serving": 4},
                                     "activity": {"requests": 9, "in_flight": 3, "last_request_at": 1},
                                     "last_timings": {"prompt_n": 100, "predicted_ms": 50.2},
                                     "vram": {"reserve_mib": 700, "expert_slots": 1200, "vram_free_mib": 91}}))
            check("/v1/status loaded: serving=3 (requests running + waiting), capacity and MiB ignored",
                  st_load == {"serving": 3.0, "queued": None}, str(st_load))
            st_m = ps(json.dumps({"engine": {"expert_slots": 1200, "max_context": 131072,
                                             "vram": {"reserve_mib": 700}},
                                  "live": {"state": "generating", "queued": 2},
                                  "conversation_cache": {"slots": 8}, "totals": {"requests": 9}}))
            check("/metrics solo: serving from live.state, queued from live.queued (engine section ignored)",
                  st_m == {"serving": 1.0, "queued": 2.0}, str(st_m))
            st_mp = ps(json.dumps({"live": {"state": "generating", "queued": 1, "running": 2,
                                            "parallel": 4, "waiting": 1, "admitting": 1}}))
            check("/metrics parallel: running wins over live.state",
                  st_mp == {"serving": 2.0, "queued": 1.0}, str(st_mp))
            st_cap = ps(json.dumps({"vram": {"reserve_mib": 700, "expert_slots": 1200}}))
            check("a pure-capacity payload parses to nothing, never to 700 \"serving\"",
                  st_cap is None, str(st_cap))
            st_gen = ps(json.dumps({"serving": 1, "queued": 2}))
            check("generic {serving, queued} schemas still work (regex fallback intact)",
                  st_gen == {"serving": 1.0, "queued": 2.0}, str(st_gen))
            st_pr = ps("llamacpp:requests_processing 1\nllamacpp:requests_deferred 2\nllamacpp:model_loaded 1\n")
            check("Prometheus text (llama.cpp names): processing=running, deferred=waiting",
                  st_pr == {"serving": 1.0, "queued": 2.0}, str(st_pr))

            # ---- v1.2.2: the standard key input port (--set-key) ------------
            kdir = tempfile.mkdtemp(prefix="strata-keys-")
            kpath = os.path.join(kdir, "router.keys.json")
            old_gp = R.getpass.getpass
            try:
                R.getpass.getpass = lambda prompt="": "sekret-ka"
                rc = R.set_key({"backends": [{"id": "local", "url": "http://127.0.0.1:1"}]}, "local", None, kpath)
                stored = R._read_keys_file(kpath)    # decrypted view (v1.2.14)
                _rawk = open(kpath, "rb").read()
                _sealed = (not R._dpapi_enabled()) or (b"sekret-ka" not in _rawk and b"dpapi_v1" in _rawk)
                check("--set-key stores the typed key in the keys file, exit 0, key out of the config; "
                      "on Windows the raw file is DPAPI ciphertext with no key bytes in it",
                      rc == 0 and stored.get("local") == "sekret-ka" and _sealed,
                      "rc=%s entries=%s sealed=%s" % (rc, sorted(stored), _sealed))
                cfgk = {"backends": [{"id": "local", "url": "http://127.0.0.1:1",
                                      "backend_api_key": "REPLACE-WITH-THIS-BOX-KEY"}], "keys_file": kpath}
                R.apply_keys(cfgk, None)
                check("a keys-file entry overrides a leftover placeholder (in memory, config never rewritten)",
                      cfgk["backends"][0]["backend_api_key"] == "sekret-ka",
                      cfgk["backends"][0]["backend_api_key"])
                os.environ["STRATA_SMOKE_KEY_ENV"] = "env-kb"
                cfge = {"backends": [{"id": "other", "url": "http://127.0.0.1:1",
                                      "backend_api_key_env": "STRATA_SMOKE_KEY_ENV"}]}
                R.apply_keys(cfge, None)
                check("backend_api_key_env pulls the key from the named variable",
                      cfge["backends"][0]["backend_api_key"] == "env-kb", cfge["backends"][0]["backend_api_key"])

                # v1.2.6 L6 guard: a control-byte key would make http.client
                # raise mid-request with the FULL header value (the key) in the
                # message -- straight into the 502 body, the log and stats.
                # Both input ports must refuse it.
                R.getpass.getpass = lambda prompt="": "bad\nkey"
                rc_ctl = R.set_key({"backends": [{"id": "local", "url": "http://127.0.0.1:1"}]}, "local", None, kpath)
                check("--set-key refuses a key with control bytes (nothing stored)",
                      rc_ctl == 2 and R._read_keys_file(kpath).get("local") == "sekret-ka",
                      "rc=%s" % rc_ctl)
                with open(kpath, "w", encoding="utf-8") as _kf:
                    json.dump({"poison": "bad\r\nkey"}, _kf)
                try:
                    R.apply_keys({"backends": [{"id": "local", "url": "http://127.0.0.1:1"}],
                                  "keys_file": kpath}, None)
                    _refused = False
                except SystemExit as _se:
                    _refused = "control bytes" in str(_se)
                check("a keys-file key with control bytes refuses boot (key would leak into error messages)",
                      _refused)
            finally:
                R.getpass.getpass = old_gp
                os.environ.pop("STRATA_SMOKE_KEY_ENV", None)
                try:
                    os.remove(kpath)
                    os.rmdir(kdir)
                except OSError:
                    pass

            # ---- v1.2.14: DPAPI at rest + presence-gated box extras --------------
            _k14 = tempfile.mkdtemp(prefix="strata-keys14-")
            _p14 = os.path.join(_k14, "router.keys.json")
            with open(_p14, "w", encoding="utf-8") as _f14:
                json.dump({"local": "plain-k14"}, _f14)
            _cfg14 = {"backends": [{"id": "local", "url": "http://127.0.0.1:1"}], "keys_file": _p14}
            R.apply_keys(_cfg14, None)               # boot path: validate, then migrate
            _raw14 = open(_p14, "rb").read()
            _mig14 = ((not R._dpapi_enabled())
                      or (b"dpapi_v1" in _raw14 and b"plain-k14" not in _raw14))
            check("v1.2.14: a validated PLAINTEXT keys file migrates to DPAPI ciphertext at boot "
                  "(same resolved key; no key bytes left in the raw file on Windows)",
                  _cfg14["backends"][0].get("backend_api_key") == "plain-k14" and _mig14,
                  "resolved=%s migrated=%s" % (bool(_cfg14["backends"][0].get("backend_api_key")), _mig14))
            if R._dpapi_enabled():
                _bad14 = os.path.join(_k14, "router.badkeys.json")
                with open(_bad14, "w", encoding="utf-8") as _f14b:
                    json.dump({"dpapi_v1": "AAAA"}, _f14b)
                try:
                    R._read_keys_file(_bad14)
                    _b14 = False
                except SystemExit as _e14:
                    _b14 = "never travel" in str(_e14)
                check("v1.2.14: an unopenable DPAPI blob is fatal and names the copied-file "
                      "failure mode (blobs never travel between users/machines)", _b14)
            _ex14 = R.parse_status(json.dumps({
                "activity": {"in_flight": 2, "requests": 5, "last_request_at": 1700000000},
                "last_timings": {"predicted_per_second": 38.42},
                "uptime_s": 3601,
                "machine": {"gpu": {"name": "X", "util_pct": 74.6}}}))
            check("v1.2.14: Strata /v1/status extras ride along when published (decode tok/s, "
                  "box uptime, gpu util) -- the serving verdict itself is untouched",
                  _ex14 == {"serving": 2, "queued": None, "decode_tok_s": 38.4,
                            "box_uptime_s": 3601, "gpu_util_pct": 75}, str(_ex14))
            _ex14b = R.parse_status(json.dumps({"live": {"queued": 0, "running": 1, "tok_s": 31.7}}))
            check("v1.2.14: the /metrics shape contributes its instant live.tok_s when present",
                  _ex14b == {"serving": 1, "queued": 0, "decode_tok_s": 31.7}, str(_ex14b))
            _ex14c = R.parse_status(json.dumps({"activity": {"in_flight": 1}}))
            check("v1.2.14: extras are PRESENCE-gated -- a box that publishes nothing changes "
                  "nothing (no fabricated zeros, old output shape)",
                  _ex14c == {"serving": 1, "queued": None}, str(_ex14c))
        finally:
            _term(proc4)
            try:
                proc4.wait(timeout=5)
            except Exception:
                proc4.kill()
            c.kill()
            d.kill()

        # atomic placement: a burst of new conversations cannot breach the capped peer
        c2 = FakeStrata(C_PORT, "c", hold=1.2, serial=True)
        d2 = FakeStrata(D_PORT, "d", hold=1.2, serial=True)
        c2.start()
        d2.start()
        proc5 = subprocess.Popen(
            [sys.executable, ROUTER,
             "--backend", '{"id":"E","url":"http://127.0.0.1:%d","priority":0,"max_inflight":1,"require_idle":true}' % C_PORT,
             "--backend", '{"id":"F","url":"http://127.0.0.1:%d","priority":1,"max_inflight":1,"require_idle":true}' % D_PORT,
             "--listen", "127.0.0.1", "--port", str(ROUTER4_PORT),
             "--status-interval", "0.2", "--log-level", "WARNING"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            check("capped-tier router starts", wait_for(lambda: get(ROUTER4_PORT, "/healthz")[0] == 200, 20))

            def tiers5():
                return {x["id"]: x for x in stats(ROUTER4_PORT)["backends"]}

            check("both capped boxes are reporting and accepting",
                  wait_for(lambda: all(tiers5()[i]["accepting"] for i in ("E", "F")), 12))
            bres = []

            def fire_burst(i):
                bres.append(call(ROUTER4_PORT, "/v1/messages", conv("burst-%d" % i)))

            thb = []
            for i in range(6):
                t = threading.Thread(target=fire_burst, args=(i,), daemon=True)
                t.start()
                thb.append(t)
            fmax = 0
            tend = time.monotonic() + 2.5
            while time.monotonic() < tend:
                fmax = max(fmax, tiers5()["F"]["inflight"])
                time.sleep(0.05)
            for t in thb:
                t.join(40)
            check("concurrent first turns cannot breach the capped peer -- gate+reserve are one step",
                  fmax <= 1, "max F inflight observed = %s" % fmax)
            check("the overflow queued instead of failing -- all six conversations completed",
                  len(bres) == 6 and all(x[0] == 200 for x in bres), str([x[0] for x in bres])[:120])
        finally:
            _term(proc5)
            try:
                proc5.wait(timeout=5)
            except Exception:
                proc5.kill()
            c2.kill()
            d2.kill()

        # require_idle with a status endpoint that NEVER answered (wrong borrower
        # key from minute one): the box must fail CLOSED -- unknown is not idle
        b.require_key = "kb"
        a.hold = b.hold = 1.2
        proc6 = subprocess.Popen(
            [sys.executable, ROUTER,
             "--backend", '{"id":"L","url":"http://127.0.0.1:%d","priority":0,"max_inflight":1}' % A_PORT,
             "--backend", '{"id":"R","url":"http://127.0.0.1:%d","priority":1,"max_inflight":1,"require_idle":true,"backend_api_key":"stale-borrower-key"}' % B_PORT,
             "--listen", "127.0.0.1", "--port", str(ROUTER3_PORT),
             "--status-interval", "0.2", "--log-level", "WARNING"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            check("never-reported router starts", wait_for(lambda: get(ROUTER3_PORT, "/healthz")[0] == 200, 20))

            def ks6():
                return {x["id"]: x for x in stats(ROUTER3_PORT)["backends"]}

            t6, r6 = spawn(call, ROUTER3_PORT, "/v1/messages", conv("nr-first"))
            check("primary occupancy visible", wait_for(lambda: ks6()["L"]["inflight"] >= 1, 8))
            st6, h6, _bb6, w6 = call(ROUTER3_PORT, "/v1/messages", conv("nr-second"))
            t6.join(30)
            check("a peer whose status NEVER answered is not borrowed -- queues at home (fail closed)",
                  st6 == 200 and h6.get("x-strata-backend") == "L" and w6 >= 1.2,
                  "status=%s box=%s wall=%s" % (st6, h6.get("x-strata-backend"), w6))
            rr = ks6()["R"]
            check("stats evidence: R never reported, is refusing placements, and stays healthy (rule 4)",
                  rr["reported_age_s"] is None and rr["accepting"] is False
                  and "401" in (rr["status_error"] or "") and rr["state"] == "healthy",
                  json.dumps({k: rr.get(k) for k in ("reported_age_s", "accepting", "status_error", "state")})[:200])
        finally:
            _term(proc6)
            try:
                proc6.wait(timeout=5)
            except Exception:
                proc6.kill()
            a.hold = b.hold = 0.55
            b.require_key = None

        # A1: a status endpoint that CONNECTS then answers LATER than
        # status_timeout is a busy box, not a dead one. It must not count
        # toward DOWN, and later good reports must still land -- the
        # refutation-confirmed top defect (healthy box ejected mid-decode and
        # its warm conversations migrated was the rule-4 breach).
        slow_n = [0]

        class _SlowHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a2):
                pass

            def do_GET(self):
                slow_n[0] += 1
                if slow_n[0] <= 3:
                    time.sleep(0.45)          # > status_timeout below
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"activity": {"requests": 0, "in_flight": 0}}')

        _srv = ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
        _srv.daemon_threads = True
        _srv.handle_error = lambda *x: None
        threading.Thread(target=_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        _pcfg = {"status_paths": ["/v1/status", "/metrics"], "status_timeout": 0.2,
                 "status_interval": 0.1, "max_connect_failures": 2, "down_backoff": 5.0}
        _be = R.Backend("slowbox", "http://127.0.0.1:%d" % _srv.server_address[1], "", cfg=dict(_pcfg))
        _poller = R.StatusPoller(R.Pool([_be], dict(_pcfg)), dict(_pcfg))
        _poller.start()
        check("A1: connect-then-silent status NEVER counts toward DOWN (rule 4: busy is not dead)",
              wait_for(lambda: slow_n[0] >= 4, 10) and _be.state != R.DOWN and _be.connect_failures == 0,
              "state=%s fails=%s hits=%s err=%s" % (_be.state, _be.connect_failures, slow_n[0], _be.status_error))
        check("A1: the box earns full credit as soon as it answers again (ever_reported)",
              wait_for(lambda: _be.ever_reported, 10), str(_be.status_error))
        _poller.stop_evt.set()
        _srv.shutdown()
        _srv.server_close()

        # O3 (Windows): SO_REUSEADDR lets a SECOND process co-bind a port
        # another is still listening on -- two routers would split traffic
        # silently. With SO_EXCLUSIVEADDRUSE the double start must fail loudly.
        if os.name == "nt":
            _r1 = R.Router(("127.0.0.1", 0), R.Handler)
            _p2 = _r1.server_address[1]
            _second = None
            try:
                try:
                    _second = R.Router(("127.0.0.1", _p2), R.Handler)
                except OSError:
                    _second = False
                check("Windows: a second router cannot silently co-bind the port (SO_EXCLUSIVEADDRUSE)",
                      _second is False, "second bind -> %r" % (_second,))
            finally:
                if _second not in (False, None):
                    _second.server_close()
                _r1.server_close()

        # ================= v1.2.16 -- R4 review fix regressions =================
        # (round-1 findings R4-A/F1 F3 F4 F5 F6 F7, R4-B/F1 F2 F3 F4)
        _mm = stats(ROUTER_PORT)["router"]
        check("v1.2.16: passthrough_gets exists as a ledger terminal",
              "passthrough_gets" in _mm, json.dumps(_mm)[:200])

        _rq0 = _mm["requests"]; _np0 = _mm["new_placements"]; _pg0 = _mm["passthrough_gets"]
        _gm = get(ROUTER_PORT, "/v1/models")[0]      # box may 404; the proxy still ran
        _mm = stats(ROUTER_PORT)["router"]
        check("v1.2.16: keyless GET books passthrough_gets, never new_placements (R4-A/F4)",
              _mm["requests"] == _rq0 + 1 and _mm["passthrough_gets"] == _pg0 + 1
              and _mm["new_placements"] == _np0,
              "GET->%s requests %s->%s new_pl %s->%s passthru %s->%s"
              % (_gm, _rq0, _mm["requests"], _np0, _mm["new_placements"], _pg0, _mm["passthrough_gets"]))
        _tt = sum(_mm.get(k, 0) for k in ("sticky_hits", "new_placements", "migrations",
                                          "pinned", "last_resort", "overflow_placements",
                                          "overflow_rollbacks", "overflow_fizzles",
                                          "overflow_evictions", "operator_cancelled",
                                          "passthrough_gets", "preview_passes"))
        check("v1.2.16: the closed identity holds over all 12 terminals (requests == SUM; preview_passes is 0 with the flag off)",
              _tt == _mm["requests"], "requests=%s terminals=%s" % (_mm["requests"], _tt))

        _pc = {"model": "test-model", "max_tokens": 16,
               "prompt": "R4-A/F3 stable completions prefix " + "filler " * 40,
               "metadata": {"user_id": "r4f3-probe"}}
        _c1 = call(ROUTER_PORT, "/v1/completions", _pc)
        _c2 = call(ROUTER_PORT, "/v1/completions", _pc)
        check("v1.2.16: /v1/completions has affinity -- same prompt homes once then sticks (R4-A/F3)",
              _c1[0] == 200 and _c1[1].get("x-strata-backend") in ("a", "b")
              and _c2[1].get("x-strata-backend") == _c1[1].get("x-strata-backend")
              and _c2[1].get("x-strata-placement") == "sticky",
              "%s/%s then %s/%s" % (_c1[1].get("x-strata-backend"), _c1[1].get("x-strata-placement"),
                                    _c2[1].get("x-strata-backend"), _c2[1].get("x-strata-placement")))

        _lb = R.Backend("unitbox", "http://127.0.0.1:9", "", cfg={})
        _lb.ever_reported = True
        _lb.reported = {"queued": 10.0}
        _lb.status_ts = time.monotonic()
        _sf = _lb.load_score()
        _lb.status_ts = time.monotonic() - 3600.0
        _ss = _lb.load_score()
        _lb.reported = {"queued": -1000000.0}
        _lb.status_ts = time.monotonic()
        _sn = _lb.load_score()
        check("v1.2.16: stale reported load ages out; a lying negative queued cannot buy the pool"
              " (R4-A/F5 + R4-B/F1 clamp)",
              _sf > 500.0 and _ss < 2.0 and _sn < 2.0,
              "fresh=%s stale=%s negative=%s" % (round(_sf, 1), round(_ss, 3), round(_sn, 3)))

        _lb.state = R.HEALTHY
        _ak_ok = _lb.snapshot().get("accepting")
        _lb.state = R.DOWN
        _ak_down = _lb.snapshot().get("accepting")
        check("v1.2.16: a DOWN box no longer claims accepting=true to the monitor (R4-A/F1)",
              _ak_ok is True and _ak_down is False, "healthy=%s down=%s" % (_ak_ok, _ak_down))

        _w = []
        R.walk_ints({"live": {"queued": float("nan"), "running": 1.0}}, (), _w)
        _psn = R.parse_status(b'{"live": {"queued": NaN, "serving": Infinity}}')
        check("v1.2.16: non-finite numbers never walk the tree nor pass the JSON door (R4-B/F1)",
              len(_w) == 1 and not _psn, "walk=%s parse=%r" % (_w, _psn))

        check("v1.2.16: response header values relay C0/DEL-stripped; tab survives (R4-B/F2)",
              R._HDR_VAL_CTL_RE.sub("", "a\x00b\x7fc\td") == "abc\td")

        _p4 = R.Pool([R.Backend("u1", "http://127.0.0.1:9", "", cfg={})], {"sticky_max": 4})
        for _i in range(7):
            _p4._affinity_put("k%d" % _i, "u1", "sticky")
        check("v1.2.16: sticky_max is honored literally -- 4 means 4, oldest evicted first (R4-A/F7)",
              len(_p4.affinity) == 4 and list(_p4.affinity) == ["k3", "k4", "k5", "k6"],
              str(list(_p4.affinity)))

        def _vsm(v):
            c = {"backends": [{"id": "u1", "url": "http://127.0.0.1:9"}]}
            if v is not None:
                c["sticky_max"] = v
            try:
                R.validate_cfg(c, R.make_pool(c), strict=True)
                return True
            except SystemExit:
                return False
        check("v1.2.16: sticky_max < 1 refused at boot; absent or >=1 passes (R4-A/F7)",
              _vsm(None) and _vsm(4) and not _vsm(0) and not _vsm(-5) and not _vsm(0.5),
              "none=%s 4=%s 0=%s -5=%s 0.5=%s" % (_vsm(None), _vsm(4), _vsm(0), _vsm(-5), _vsm(0.5)))

        class _StormCap(logging.Handler):
            def __init__(self):
                logging.Handler.__init__(self, level=logging.DEBUG)
                self.recs = []

            def emit(self, rec):
                self.recs.append(rec)
        _sc = _StormCap()
        R.LOG.addHandler(_sc)
        try:
            _sb = R.Backend("stormbox", "http://127.0.0.1:9", "", cfg={})
            _sb.note_connect_failure("boom", 1, 5.0)      # transition -> WARNING
            _sb.note_connect_failure("boom", 1, 5.0)      # repeats -> debug only
            _sb.note_connect_failure("boom", 1, 5.0)
            _dw = [r.getMessage() for r in _sc.recs if r.levelno >= logging.WARNING
                   and "DOWN" in r.getMessage()]
        finally:
            R.LOG.removeHandler(_sc)
        check("v1.2.16: a dead box logs the DOWN transition once, repeats stay debug (R4-A/F6)",
              len(_dw) == 1, "%d warnings: %s" % (len(_dw), _dw[:2]))

        _kd = tempfile.mkdtemp(prefix="r4keys_")
        try:
            _kp = os.path.join(_kd, "router.keys.json")
            _l1 = R._keys_lock(_kp, timeout=0.4)
            _lkerr = None
            try:
                R._keys_lock(_kp, timeout=0.4)
            except BaseException as _e:
                _lkerr = _e
            R._keys_unlock(_l1)
            _l2 = R._keys_lock(_kp, timeout=0.4)          # released -> re-acquirable
            R._keys_unlock(_l2)
            check("v1.2.16: keys writes hold an exclusive lock; second writer times out, then it frees"
                  " (R4-B/F3)", isinstance(_lkerr, TimeoutError) and _l2 is not None, repr(_lkerr))

            with open(os.path.join(_kd, "router.json"), "w", encoding="utf-8") as _fh:
                _fh.write("{}")
            with open(_kp, "w", encoding="utf-8") as _fh:
                json.dump({"u1": "sk-fake-r4sweep"}, _fh)
            for _stale in ("router.keys.json.new.4242", "router.keys.json.new.99"):
                with open(os.path.join(_kd, _stale), "w", encoding="utf-8") as _fh:
                    _fh.write('{"leftover": "stale temp"}')
            _acfg = {"backends": [{"id": "u1", "url": "http://127.0.0.1:9"}]}
            R.apply_keys(_acfg, os.path.join(_kd, "router.json"))
            check("v1.2.16: boot sweeps stale <keys>.json.new.* temps a hard crash left behind (R4-B/F4)",
                  not [n for n in os.listdir(_kd) if ".new." in n], str(os.listdir(_kd))[:200])
        finally:
            for _n in os.listdir(_kd):
                try:
                    os.unlink(os.path.join(_kd, _n))
                except OSError:
                    pass
            try:
                os.rmdir(_kd)
            except OSError:
                pass

        # ================= v1.2.17 -- R6 review fix regressions =================
        # (round-2 findings: R6-C/P3-1 P3-2 P3-3 + note-1, R6-D/P2)

        # R6-C/P3-1: lying box smuggles NUL inside content-type -- the skip-
        # and-reattach path must sanitize exactly like the relay loop does.
        _fk17 = (a.require_key, b.require_key, a.lie, b.lie)
        a.require_key = b.require_key = None
        a.lie = b.lie = True
        try:
            _c17 = http.client.HTTPConnection("127.0.0.1", ROUTER_PORT, timeout=15.0)
            _c17.request("GET", "/v1/liect")
            _r17 = _c17.getresponse()
            _ct17 = _r17.getheader("content-type")
            _xn17 = _r17.getheader("x-nul")
            _r17.read()
            _c17.close()
        finally:
            a.require_key, b.require_key, a.lie, b.lie = _fk17
        check("v1.2.17: the content-type reattach strips NUL/C0 like the relay loop (R6-C/P3-1)",
              _ct17 == "text/plain; qz=1" and _xn17 == "ab",
              "content-type=%r x-nul=%r" % (_ct17, _xn17))

        _sb2 = R.Backend("scorebox", "http://127.0.0.1:9", "", cfg={})
        _sb2.state = R.HEALTHY
        _sb2.ever_reported = True
        _sb2.reported = {"queued": -1000000.0}
        _sb2.status_ts = time.monotonic()
        _s17_lie = _sb2.snapshot()["score"]
        _sb2.reported = {"queued": 500.0}
        _s17_honest = _sb2.snapshot()["score"]
        _sb2.status_ts = time.monotonic() - 3600.0
        _s17_blind = _sb2.snapshot()["score"]
        check("v1.2.17: snapshot score IS the placement score -- clamp + freshness gate (R6-C/P3-2, R6-D/P3)",
              _s17_lie == 0.0 and _s17_honest == 30000.0 and _s17_blind == 0.0,
              "lie=%s honest=%s blind=%s" % (_s17_lie, _s17_honest, _s17_blind))

        _he_cls = next(_k for _k in R.Router.__mro__[1:] if "handle_error" in _k.__dict__)
        _he_orig = _he_cls.handle_error
        _he_hits = []

        def _he_spy(_self, _request, _client):
            _he_hits.append(type(sys.exc_info()[1]).__name__)
        _he_cls.handle_error = _he_spy
        try:
            _hr17 = R.Router.__new__(R.Router)   # handle_error touches no state
            for _exc17 in (ConnectionAbortedError(10053, "wsa abort"), BrokenPipeError(),
                           ConnectionResetError(), TimeoutError(), ValueError("real fault")):
                try:
                    raise _exc17
                except BaseException:
                    _hr17.handle_error(None, ("127.0.0.1", 1))
        finally:
            _he_cls.handle_error = _he_orig
        check("v1.2.17: WinError-10053 aborts are silenced with the other hang-ups; faults still print (R6-C/P3-3)",
              _he_hits == ["ValueError"], str(_he_hits))

        _f4home = R.Backend("f4home", "http://127.0.0.1:9", "", cfg={})
        _f4alt = R.Backend("f4alt", "http://127.0.0.1:9", "", cfg={})
        _f4pool = R.Pool([_f4home, _f4alt], {})
        _f4alt.begin()                                 # what pick booked on the overflow
        _f4ends = []
        _f4end_real = _f4alt.end
        _f4alt.end = lambda: (_f4ends.append(1), _f4end_real())[1]
        _f4pool._overflow_pending[555] = ("f4lane", "f4home", "f4alt")
        _f4home.state = R.DOWN                         # home died mid-request too
        _f4place_real = _f4pool._place
        _f4pool._place = lambda **_kw: (None, False)   # nowhere to migrate onward to
        try:
            _f4late = _f4pool.overflow_rollback("f4lane", 555, "f4alt")
        finally:
            _f4pool._place = _f4place_real
        _f4early = _f4pool.overflow_rollback("f4lane", 999, "f4alt")  # pop miss: plain None,
        # the reservation stays with the caller's finally -- unchanged semantics
        check("v1.2.17: released verdict stops a double end() when rollback finds no box; early-None stays plain None (R6-C note-1)",
              _f4late is not None and _f4late[0] is None and _f4late[2] is False
              and len(_f4ends) == 1 and _f4alt.inflight == 0
              and _f4early is None and len(_f4ends) == 1,
              "late=%r ends=%s inflight=%s early=%r" % (_f4late, len(_f4ends), _f4alt.inflight, _f4early))

        _r5dir = tempfile.mkdtemp(prefix="r6keys_")
        try:
            _r5p = os.path.join(_r5dir, "router.keys.json")
            if os.name == "nt":
                _rp_real = os.replace
                _r5tries = []

                def _flaky_replace(src, dst):
                    _r5tries.append(1)
                    if len(_r5tries) < 3:
                        _err17 = OSError(5, "Access is denied")
                        _err17.winerror = 5
                        raise _err17
                    return _rp_real(src, dst)

                os.replace = _flaky_replace
                try:
                    R._write_keys_file(_r5p, {"u1": "sk-fake-retry"})
                finally:
                    os.replace = _rp_real
                _r5rt, _ = R._read_keys_file2(_r5p)
                check("v1.2.17: keys replace waits out a concurrent reader's WinError-5 window (R6-D/P2)",
                      len(_r5tries) == 3 and _r5rt == {"u1": "sk-fake-retry"},
                      "tries=%s roundtrip=%s" % (len(_r5tries), _r5rt))
            else:
                R._write_keys_file(_r5p, {"u1": "sk-fake-retry"})
                _r5rt, _ = R._read_keys_file2(_r5p)
                check("v1.2.17: keys write path intact off Windows (retry gate is nt-only) (R6-D/P2)",
                      _r5rt == {"u1": "sk-fake-retry"}, str(_r5rt))
        finally:
            for _n in os.listdir(_r5dir):
                try:
                    os.unlink(os.path.join(_r5dir, _n))
                except OSError:
                    pass
            try:
                os.rmdir(_r5dir)
            except OSError:
                pass
        # ---- smart placement C1: scaffold + L0 observation (design v4.1 §2/§9/§13) ----
        print("")
        print("S1) smart scaffold -- config, accumulator, OBS (design v4.1)")
        _sp_be = R.Backend("sp1", "http://127.0.0.1:9", cfg={"max_inflight": 4})
        _sp_be2 = R.Backend("sp2", "http://127.0.0.1:9", cfg={"max_inflight": 4})
        _sp_pool = R.Pool([_sp_be, _sp_be2], {"smart": {"smart_obs": True, "window_n": 1}})
        _sp_off = R.Pool([R.Backend("sp3", "http://127.0.0.1:9", cfg={})], {})
        check("S1: smart counters exist on the ledger, zero at birth (moves are diagnostics only)",
              all(_sp_pool.metrics[k] == 0 for k in
                  ("moves", "homecomings", "preview_passes", "move_gate_locked",
                   "shadow_would_moves", "shadow_loss_moves", "shadow_unresolved")),
              str({k: _sp_pool.metrics.get(k, "ABSENT") for k in ("moves", "preview_passes")}))
        check("S1: flags default ALL off -- a plain cfg runs the estimator nowhere (§9)",
              _sp_off.smart_any is False and _sp_pool.smart_any is True,
              "off=%s on=%s" % (_sp_off.smart_any, _sp_pool.smart_any))
        for _sp_m, _sp_p in (("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens"),
                             ("GET", "/v1/messages"), ("POST", "/v1/responses")):
            _sp_pool.note_completion(_sp_be, _sp_m, _sp_p, 5.0, None, 200)
        check("S1: class-filtered accumulator counts ONLY POST /v1/messages (§13-14)",
              _sp_be.sm["streams_s"] == 1 and abs(_sp_be.sm["dur_sum_s"] - 5.0) < 1e-9,
              "streams_s=%s dur=%.1f" % (_sp_be.sm.get("streams_s"), _sp_be.sm.get("dur_sum_s", -1)))
        _sp_off.note_completion(_sp_be2, "POST", "/v1/messages", 5.0, None, 200)
        check("S1: all flags OFF -- the accumulator never ticks (byte-silent scaffold)",
              _sp_be2.sm["streams_s"] == 0, "streams_s=%s" % _sp_be2.sm.get("streams_s"))
        _sp_be.ever_reported = True
        _sp_be.reported = {"serving": 0.0, "queued": 0.0}
        _sp_t = time.monotonic() + 100.0
        _sp_be.status_ts = _sp_t - 0.1
        for _i in range(20):
            _sp_be.sm["streams_s"] += 1
            _sp_be.sm["dur_sum_s"] += 300.0
        _sp_be._smart_tick_locked(_sp_pool.sm_cfg, _sp_t)
        check("S1: window T-bar = counter difference; n_min counts FILTERED completions (V3-09①②)",
              _sp_be.sm["t_bar_window"] is not None
              and abs(_sp_be.sm["t_bar_window"] - (5.0 + 20 * 300.0) / 21.0) < 1e-9
              and _sp_be.sm["degraded"] is False,
              "w=%s deg=%s" % (_sp_be.sm["t_bar_window"], _sp_be.sm["degraded"]))
        for _i in range(20):
            _sp_be.sm["streams_s"] += 1
            _sp_be.sm["dur_sum_s"] += 10.0
        _sp_be._smart_tick_locked(_sp_pool.sm_cfg, _sp_t + 1.0)
        for _i in range(20):
            _sp_be.sm["streams_s"] += 1
            _sp_be.sm["dur_sum_s"] += 300.0
        _sp_be.status_ts = _sp_t + 0.9
        _sp_be._smart_tick_locked(_sp_pool.sm_cfg, _sp_t + 1.0)
        check("S1: T̄_used = min(window, 3 x 24h rolling-min base) binds on a spike (V3-05/E3)",
              _sp_be.sm["t_bar_window"] is not None and abs(_sp_be.sm["t_bar_window"] - 300.0) < 1e-6
              and abs(_sp_be.sm["t_bar_used"] - 30.0) < 1e-6 and abs(_sp_be.sm["t_bar_base"] - 10.0) < 1e-6,
              "w=%s used=%s base=%s" % (_sp_be.sm["t_bar_window"], _sp_be.sm["t_bar_used"], _sp_be.sm["t_bar_base"]))
        _sp_be._smart_tick_locked(_sp_pool.sm_cfg, _sp_t + 2.0)
        check("S1: streams_s < n_min -- window None + degraded, T_bar_used = named DEFAULT_T̄ (F4; clamp-exempt E6③)",
              _sp_be.sm["t_bar_window"] is None and _sp_be.sm["degraded"] is True
              and _sp_be.sm["t_bar_used"] == 120.0,
              "w=%s deg=%s used=%s" % (_sp_be.sm["t_bar_window"], _sp_be.sm["degraded"], _sp_be.sm["t_bar_used"]))
        _sp_be.reported = {"serving": 4.0, "queued": 0.0}
        _sp_be.status_ts = _sp_t + 2.9
        _sp_be._smart_tick_locked(_sp_pool.sm_cfg, _sp_t + 3.0)
        _sp_c1 = _sp_be.sm["cong_streak"]
        _sp_be.status_ts = _sp_t + 3.9
        _sp_be._smart_tick_locked(_sp_pool.sm_cfg, _sp_t + 4.0)
        _sp_c2 = _sp_be.sm["cong_streak"]
        _sp_be.status_ts = _sp_t - 2.0          # 6.0s behind the tick clock: stale
        _sp_be._smart_tick_locked(_sp_pool.sm_cfg, _sp_t + 4.0)
        _sp_c3 = _sp_be.sm["cong_streak"]
        _sp_be.reported = {"serving": 0.0, "queued": 0.0}
        _sp_be.status_ts = _sp_t + 3.9
        _sp_be._smart_tick_locked(_sp_pool.sm_cfg, _sp_t + 4.0)
        _sp_c4 = _sp_be.sm["cong_streak"]
        check("S1: cong_streak counts fresh congested polls, FREEZES while stale, resets on idle (V3-09③)",
              (_sp_c1, _sp_c2, _sp_c3, _sp_c4) == (1, 2, 2, 0),
              "steps=%s" % (( _sp_c1, _sp_c2, _sp_c3, _sp_c4),))
        _sp_inf, _sp_req = _sp_be.inflight, _sp_be.stats["requests"]
        _sp_be.ever_reported = True
        _sp_be.status_ts = time.monotonic()
        _sp_be.accepts_placement()
        check("S1: accepts_placement is an un-ticked read -- no inflight++, no request tick (§13-17)",
              _sp_be.inflight == _sp_inf and _sp_be.stats["requests"] == _sp_req,
              "inflight %s->%s requests %s->%s" % (_sp_inf, _sp_be.inflight, _sp_req, _sp_be.stats["requests"]))
        _sp_snap = _sp_be.snapshot()
        check("S1: /stats carries the additive OBS panel incl. F13 failure_pressure proxy",
              all(_sp_snap.get(k, "ABSENT") != "ABSENT" or k == "cap_slots"
                  for k in ("t_bar_window_s", "t_bar_base_s", "t_bar_used_s", "t_bar_degraded",
                            "cong_streak", "failure_pressure"))
              and "cap_slots" in _sp_snap and isinstance(_sp_snap["failure_pressure"], float),
              str({k: _sp_snap.get(k, "ABSENT") for k in ("t_bar_window_s", "cong_streak", "failure_pressure")}))
        _sp_thr = threading.active_count()
        _sp_pool.note_completion(_sp_be, "POST", "/v1/messages", 1.0, None, 200)
        _sp_be._smart_tick_locked(_sp_pool.sm_cfg, time.monotonic())
        check("S1: the scaffold starts ZERO resident threads (S-2)",
              threading.active_count() == _sp_thr,
              "%d -> %d" % (_sp_thr, threading.active_count()))
        _sp_pay = [None] * 10
        _sp_be.sm["tick_n"] = 0                 # cadence is per-backend: count from here
        _sp_be.status_ts = _sp_t + 19.9
        for _i in range(10):
            _sp_pay[_i] = _sp_be._smart_tick_locked(_sp_pool.sm_cfg, _sp_t + 20.0 + _i * 0.001)
        check("S1: an OBS line is prepared exactly once per obs_every_polls tick, never otherwise",
              sum(1 for _p in _sp_pay if _p) == 1 and _sp_pay[-1],
              "emitted at %s" % [i for i, p in enumerate(_sp_pay) if p])
        _sp_pay_off = []
        for _i in range(10):
            _sp_pay_off.append(_sp_be._smart_tick_locked(_sp_off.sm_cfg, time.monotonic()))
        check("S1: smart_obs OFF -- no OBS line is ever prepared (default-off L0 with no exception, §1)",
              not any(_sp_pay_off), str([bool(p) for p in _sp_pay_off].count(True)))
        _sp_pA = R.Pool([R.Backend("mx1", "http://127.0.0.1:9", cfg={})], {"smart": {"smart_place": True}})
        _sp_pbA = R.validate_cfg({"smart": {"smart_place": True}}, _sp_pA, strict=False)
        check("S1: S-1 -- smart_place ON without a declared max_inflight is a named boot refusal",
              any("S-1" in _w for _k, _w in _sp_pbA),
              str(["%s: %s" % (k, w) for k, w in _sp_pbA])[:220])
        _sp_pB = R.Pool([R.Backend("mx2", "http://127.0.0.1:9", cfg={"max_inflight": 2})], {"smart": {}})
        _sp_pbB = R.validate_cfg({"smart": {"smart_obs": True}}, _sp_pB, strict=False)
        check("S1: S-1 does NOT demand mi for obs/shadow/preview -- only place/move do",
              not any("S-1" in _w for _k, _w in _sp_pbB), str(_sp_pbB)[:200])
        _sp_pC = R.Pool([R.Backend("mx3", "http://127.0.0.1:9", cfg={})], {"smart": {"smart_obs": "false"}})
        _sp_pbC = R.validate_cfg({"smart": {"smart_obs": "false"}}, _sp_pC, strict=False)
        check("S1: a string \"false\" flag is refused BY NAME -- the truthy-string trap stays closed",
              any(_k == "smart.smart_obs" for _k, _w in _sp_pbC), str(_sp_pbC)[:200])
        _sp_pD = R.Pool([R.Backend("mx4", "http://127.0.0.1:9", cfg={})], {"smart": {"k_gainn": 3}})
        _sp_pbD = R.validate_cfg({"smart": {"k_gainn": 3}}, _sp_pD, strict=False)
        check("S1: an unknown smart.* knob is not a problem (warn+ignore doctrine) -- never silently trusted",
              not any(_k.startswith("smart") for _k, _w in _sp_pbD), str(_sp_pbD)[:200])
        # ---- smart placement C2: L1 cap_read (design §8 whitelist) ----
        print("")
        print("S2) smart L1 -- cap_slots: one whitelisted key, never a walk (design S8)")
        _cap_ok = '{"activity":{"in_flight":3},"concurrency":{"serving":8}}'
        _cap_junk = [
            ("string digits", '{"concurrency":{"serving":"8"}}'),
            ("bool true -- the truthy family", '{"concurrency":{"serving":true}}'),
            ("zero slots", '{"concurrency":{"serving":0}}'),
            ("negative", '{"concurrency":{"serving":-2}}'),
            ("fractional", '{"concurrency":{"serving":2.5}}'),
            ("NaN literal", '{"concurrency":{"serving":NaN}}'),
            ("Infinity literal", '{"concurrency":{"serving":Infinity}}'),
            ("null", '{"concurrency":{"serving":null}}'),
            ("wrong parent", '{"pools":{"serving":8}}'),
            ("wrong child", '{"concurrency":{"max":8}}'),
            ("flat dotted key is not the path", '{"concurrency.serving":8}'),
            ("body is a list", '[{"concurrency":{"serving":8}}]'),
            ("body not JSON", 'concurrency_serving 8\n'),
            ("serving is an object", '{"concurrency":{"serving":{"now":8}}}'),
            ("past the sane ceiling", '{"concurrency":{"serving":1000001}}'),
        ]
        check("S2: the whitelist key reads to a slot count, integral float included (isolation 2: exact path)",
              R._read_cap_slots(_cap_ok) == 8
              and R._read_cap_slots('{"concurrency":{"serving":8.0}}') == 8,
              str(R._read_cap_slots(_cap_ok)))
        check("S2: no near-miss shape ever reads -- the reader NEVER walks, one path only (§8)",
              all(R._read_cap_slots(_b) is None for _n, _b in _cap_junk),
              str([_n for _n, _b in _cap_junk if R._read_cap_slots(_b) is not None]))
        _cap_pool_off, _cap_be_off = R.Pool([], {}), R.Backend("capoff", "http://127.0.0.1:9", cfg={})
        _cap_pool_on = R.Pool([], {"smart": {"smart_cap_read": True}})
        _cap_be_on = R.Backend("capon", "http://127.0.0.1:9", cfg={})
        check("S2: the cap flag alone arms the scaffold (smart_any True, no behavior layer)",
              _cap_pool_off.smart_any is False and _cap_pool_on.smart_any is True)
        _cap_calls = []
        _cap_real = R._read_cap_slots
        R._read_cap_slots = lambda _b: (_cap_calls.append(1), _cap_real(_b))[1]
        try:
            _cap_pol_off = R.StatusPoller(_cap_pool_off, {})
            _cap_pol_off._get = lambda be, path: (200, _cap_ok)
            _cap_pol_off._poll(_cap_be_off)
            check("S2: flag OFF -- the reader is never invoked and cap_slots stays None (isolation 1)",
                  not _cap_calls and _cap_be_off.cap_slots is None,
                  "calls=%d cap=%s" % (len(_cap_calls), _cap_be_off.cap_slots))
            _cap_pol_on = R.StatusPoller(_cap_pool_on, {})
            _cap_pol_on._get = lambda be, path: (200, _cap_ok)
            _cap_pol_on._poll(_cap_be_on)
            check("S2: flag ON fresh poll -- cap lands AND the load numbers are untouched by the decoy "
                  "(isolation 3: cap feeds ONLY cap_slots)",
                  len(_cap_calls) > 0 and _cap_be_on.cap_slots == 8
                  and _cap_be_on.snapshot()["reported"]["serving"] == 3.0,
                  "cap=%s serving=%s" % (_cap_be_on.cap_slots, _cap_be_on.snapshot()["reported"]["serving"]))
            _cap_pol_on._get = lambda be, path: (None, "refused")
            _cap_pol_on._poll(_cap_be_on)
            check("S2: an unreachable box FREEZES cap_slots -- only fresh commits write it",
                  _cap_be_on.cap_slots == 8, "cap=%s" % _cap_be_on.cap_slots)
            _cap_junk_hits = []
            for _n, _b in _cap_junk:
                _bj = R.Backend("capj", "http://127.0.0.1:9", cfg={})
                _cap_pol_j = R.StatusPoller(_cap_pool_on, {})
                _cap_pol_j._get = lambda be, path, _body=_b: (200, _body)
                _cap_pol_j._poll(_bj)
                if _bj.cap_slots is not None:
                    _cap_junk_hits.append(_n)
            check("S2: a junk-shaped capacity is refused at the write point -- cap_slots stays None",
                  not _cap_junk_hits, str(_cap_junk_hits))
            _bt = R.Backend("capk", "http://127.0.0.1:9", cfg={"max_inflight": 4})
            _bt.cap_slots = 2
            _bt.ever_reported = True
            _bt.reported = {"serving": 2.0, "queued": 0.0}
            _bt.status_ts = time.monotonic()
            _bt._smart_tick_locked(_cap_pool_on.sm_cfg, time.monotonic())
            check("S2: k_b = min(max_inflight, cap_slots) -- the declared cap tightens congestion",
                  _bt.sm["cong_streak"] == 1, "streak=%s" % _bt.sm["cong_streak"])
        finally:
            R._read_cap_slots = _cap_real
        # ---- smart placement C3: affinity origin field (design S13-20) ----
        print("")
        print("S3) affinity origin -- who seated this lane, and does it survive a restamp (S13-20)")
        _ob1 = R.Backend("ob1", "http://127.0.0.1:9", cfg={})
        _ob2 = R.Backend("ob2", "http://127.0.0.1:9", cfg={})
        _opool = R.Pool([_ob1, _ob2], {})
        _opool.affinity["legacy"] = ("ob1", time.monotonic())   # pre-origin 2-form
        check("S3: readers tolerate the legacy 2-form -- _affinity_get reads it and RESTAMPS to 3-form",
              _opool._affinity_get("legacy") == "ob1"
              and len(_opool.affinity["legacy"]) == 3 and _opool.affinity["legacy"][2] == "sticky",
              str(_opool.affinity.get("legacy")))
        check("S3: status() counts in v[0]-form -- a wider value never breaks the monitor feed",
              _opool.status()["affinity_by_backend"].get("ob1") == 1)
        _loud = False
        try:
            _opool._affinity_put("noorigin", "ob1")
        except TypeError:
            _loud = True
        check("S3: _affinity_put has NO origin default -- a missed call site dies LOUD, never defaults",
              _loud and "noorigin" not in _opool.affinity)
        _opool._affinity_put("tr1", "ob2", "transient")
        _opool._affinity_get("tr1")
        check("S3: restamp preserves ANY origin -- transient survives a sticky hit intact",
              _opool.affinity["tr1"][2] == "transient" and _opool.affinity["tr1"][0] == "ob2",
              str(_opool.affinity.get("tr1")))
        _r1 = _opool.pick("lane1", pin="ob1")
        check("S3: the pin seat writes origin=pin",
              _r1[1] == "pinned" and _opool.affinity["lane1"][2] == "pin",
              "%s / %s" % (_r1[1], _opool.affinity["lane1"][2] if len(_opool.affinity["lane1"]) > 2 else "2-FORM"))
        _r2 = _opool.pick("lane1")
        _r3 = _opool.pick("lane1")
        check("S3: two sticky hits restamp the row -- origin STAYS pin (§13-20: hits must not launder an operator pin)",
              _r2[1] == "sticky" and _r3[1] == "sticky" and _opool.affinity["lane1"][2] == "pin",
              "reasons=%s,%s origin=%s" % (_r2[1], _r3[1], _opool.affinity["lane1"][2]))
        _r4 = _opool.pick("lane2")
        check("S3: fresh placement seats origin=sticky",
              _r4[1] == "placed" and _opool.affinity["lane2"][2] == "sticky")
        _od = _opool.status().get("affinity_origin", "ABSENT")
        check("S3: /stats publishes the origin distribution (who owns the table, right now)",
              _od != "ABSENT" and _od.get("pin") == 1 and _od.get("sticky") == 2
              and _od.get("transient") == 1, str(_od))
        # ---- smart placement C4: J engine + window discipline + shadow ledger + release gate ----
        print("")
        print("S4) smart L2 -- J engine + would-move ledger + release gate (design S2/S3/S9/E5/D9/D14)")

        def _jbox(jid, mi=4, tbar=100.0, serving=0.0, cap=None):
            b = R.Backend(jid, "http://127.0.0.1:9", cfg={"max_inflight": mi})
            if cap is not None:
                b.cap_slots = cap
            b.ever_reported = True
            b.reported = {"serving": serving, "queued": 0.0}
            b.status_ts = time.monotonic()
            b.sm["t_bar_used"] = tbar
            b.sm["t_bar_window"] = tbar
            return b

        class _LSpy(R.Backend):
            def load_score(self):
                return _LSpy.scores.get(self.id, 0.0)

        _LSpy.scores = {}
        _jcfg = {"smart": {"smart_shadow": True, "window_n": 1, "kappa_hat": 0.01,
                           "w_cour": 1.0, "k_gain": 2.0, "shadow_cycle_s": 60.0}}
        _jp = R.Pool([], _jcfg)
        check("S4: k_b = min(mi, cap_slots) with honest None when nothing is declared (S2)",
              R._k_b_of(_jbox("jb")) == 4 and R._k_b_of(_jbox("jc", mi=9, cap=2)) == 2
              and R._k_b_of(R.Backend("jx", "http://127.0.0.1:9", cfg={})) is None)
        _pw0 = _jp._j_parts(_jbox("w0", serving=0.0), time.monotonic(), 0, 4.0)
        _pw1 = _jp._j_parts(_jbox("w1", serving=4.0), time.monotonic(), 0, 4.0)
        _pw2 = _jp._j_parts(_jbox("w2", serving=8.0), time.monotonic(), 0, 4.0)
        check("S4: Ŵ = max(0, L-k+[L>=k])/max(1,k) x T̄ -- zero under k_b, +1 entry AT the boundary (S2)",
              _pw0["W"] == 0.0 and abs(_pw1["W"] - 0.25 * 100.0) < 1e-9
              and abs(_pw2["W"] - 1.25 * 100.0) < 1e-9,
              "W=%s/%s/%s" % (_pw0["W"], _pw1["W"], _pw2["W"]))
        _jw = _jbox("jw", serving=2.0)
        _pjw = _jp._j_parts(_jw, time.monotonic(), 8000, 4.0)
        check("S4: J = R̂xŴ + Ĉ + X exactly -- Ĉ=len(body)/4 x κ̂, X = external load x T̄/k (one currency, S2)",
              abs(_pjw["C"] - 20.0) < 1e-9 and abs(_pjw["X"] - 50.0) < 1e-9
              and abs(_pjw["J"] - (4.0 * _pjw["W"] + 20.0 + 50.0)) < 1e-9, str(_pjw))
        _jstale = R.Backend("jstale", "http://127.0.0.1:9", cfg={"max_inflight": 4})
        _jstale.ever_reported = True
        _jstale.reported = {"serving": 2.0, "queued": 0.0}
        _jstale.status_ts = time.monotonic() - 999.0
        _jstale.sm["t_bar_used"] = 50.0
        check("S4: stale feed / no k_b / no T̄ are MISSING inputs -- J says None, never guesses (F1/F5)",
              _jp._j_parts(_jstale, time.monotonic(), 0, 4.0) is None
              and _jp._j_parts(_jbox("jmi", mi=None), time.monotonic(), 0, 4.0) is None)
        _jtie_a, _jtie_b = _jbox("ta"), _jbox("tb", serving=2.0)   # J=20 vs J=70
        _jtie_a.status_ts = _jtie_b.status_ts = time.monotonic()
        _jp0k = R.Pool([], {"smart": {"smart_place": True, "kappa_hat": 0.01, "w_cour": 1.0}})
        _LSpy.scores = {"A": 99.0, "B": 1.0}
        _a = _LSpy("A", "http://127.0.0.1:9", cfg={"max_inflight": 4})
        _a.ever_reported = True; _a.reported = {"serving": 0.0, "queued": 0.0}
        _a.status_ts = time.monotonic(); _a.sm["t_bar_used"] = 100.0; _a.sm["t_bar_window"] = 100.0
        _b = _LSpy("B", "http://127.0.0.1:9", cfg={"max_inflight": 4})
        _b.ever_reported = True; _b.reported = {"serving": 2.0, "queued": 0.0}
        _b.status_ts = time.monotonic(); _b.sm["t_bar_used"] = 100.0; _b.sm["t_bar_window"] = 100.0
        _ord_default = _jp0k._smart_order([_b, _a], time.monotonic(), 8000, 4.0)
        check("S4: k_eps=0 (default) -- J orders outright; only EXACT ties fall to load_score (S3 band head)",
              _ord_default and [x.id for x in _ord_default] == ["A", "B"],
              str([x.id for x in _ord_default] if _ord_default else _ord_default))
        _jp3k = R.Pool([], {"smart": {"smart_place": True, "k_eps": 3.0, "kappa_hat": 0.01, "w_cour": 1.0}})
        _ord_band = _jp3k._smart_order([_a, _b], time.monotonic(), 8000, 4.0)
        check("S4: k_eps relative band -- inside the band load_score orders, NOT raw J and NOT a draw (E6①)",
              _ord_band and [x.id for x in _ord_band] == ["B", "A"],
              str([x.id for x in _ord_band] if _ord_band else _ord_band))
        _ord_degraded = _jp0k._smart_order([_a, _b, _jstale], time.monotonic(), 8000, 4.0)
        check("S4: ONE candidate with missing inputs degrades the WHOLE round to today's order (E6② round-level)",
              _ord_degraded is None)
        _jsu = _LSpy("S", "http://127.0.0.1:9", cfg={"max_inflight": 4})
        _jsu.ever_reported = True; _jsu.reported = {"serving": 0.0, "queued": 0.0}
        _jsu.status_ts = time.monotonic(); _jsu.sm["t_bar_used"] = 1.0; _jsu.sm["t_bar_window"] = 1.0
        _jsu.state = R.SUSPECT
        _ord_susp = _jp3k._smart_order([_a, _b, _jsu], time.monotonic(), 8000, 4.0)
        check("S4: SUSPECT leaves the J candidate face while a HEALTHY remains; all-SUSPECT = today (F11)",
              _ord_susp is not None and all(x.id != "S" for x in _ord_susp)
              and _jp3k._smart_order([_jsu], time.monotonic(), 8000, 4.0) is None,
              str([x.id for x in _ord_susp] if _ord_susp is not None else None))
        # -- window discipline: N ticks per window, the window HOLDS in between (S2/V3-09①) --
        _wp = R.Pool([], {"smart": {"smart_obs": True}})
        _wb = R.Backend("wb", "http://127.0.0.1:9", cfg={})
        _wb.ever_reported = True
        _wb.reported = {"serving": 0.0, "queued": 0.0}
        _wt = time.monotonic() + 5000.0
        _wb.status_ts = _wt
        _wb.sm["streams_s"] = 25
        _wb.sm["dur_sum_s"] = 250.0
        for _i in range(9):
            _wb._smart_tick_locked(_wp.sm_cfg, _wt + 0.001 * _i)
        check("S4: 25 samples but the window diffs on N=10 boundaries only -- before the first boundary "
              "T̄ is None (no opinion yet), so J stays silent and the round falls back honestly",
              _wb.sm["t_bar_window"] is None and _wb.sm["t_bar_used"] is None,
              str((_wb.sm["t_bar_window"], _wb.sm["t_bar_used"])))
        _wb._smart_tick_locked(_wp.sm_cfg, _wt + 0.0095)
        check("S4: tick #10 opens the window -- mean over FILTERED completions",
              _wb.sm["t_bar_window"] is not None and abs(_wb.sm["t_bar_window"] - 10.0) < 1e-9
              and _wb.sm["degraded"] is False and _wb.sm["t_bar_used"] == 10.0,
              str((_wb.sm["t_bar_window"], _wb.sm["t_bar_used"])))
        _wb.sm["streams_s"] += 5
        _wb.sm["dur_sum_s"] += 450.0
        for _i in range(11, 20):
            _wb._smart_tick_locked(_wp.sm_cfg, _wt + 0.001 * _i)
        check("S4: between windows the window HOLDS -- no half-window mean, no flapping (S2)",
              abs(_wb.sm["t_bar_window"] - 10.0) < 1e-9, str(_wb.sm["t_bar_window"]))
        _wb._smart_tick_locked(_wp.sm_cfg, _wt + 0.0195)
        check("S4: next window had only 5 FILTERED samples -- back to DEFAULT_T̄=120 + degraded (F4)",
              _wb.sm["t_bar_window"] is None and _wb.sm["degraded"] is True
              and _wb.sm["t_bar_used"] == 120.0, str((_wb.sm["t_bar_window"], _wb.sm["t_bar_used"])))
        # -- shadow ledger: the mover's WOULD-BE measured on observations only (E5) --
        _sh_home = _jbox("sh", serving=8.0)
        _sh_home.sm["t_bar_used"] = 300.0
        _sh_home.sm["t_bar_window"] = 300.0
        _sh_home.sm["cong_streak"] = 2
        _sh_tgt = _jbox("st", serving=0.0)
        _sh_tgt.sm["t_bar_used"] = 30.0
        _sh_tgt.sm["t_bar_window"] = 30.0
        _shp = R.Pool([_sh_home, _sh_tgt], _jcfg)
        _shp._affinity_put("sl", "sh", "sticky")
        _rs = _shp.pick("sl", body_len=8000)
        check("S4: congested home + idle target + net inequality -- a would-move SAMPLE opens; the lane does NOT move (L2)",
              _rs[1] == "sticky" and _rs[0].id == "sh"
              and _shp.metrics["shadow_would_moves"] == 1 and "sl" in _shp._shadow_open,
              "%s wm=%s open=%s" % (_rs[1], _shp.metrics["shadow_would_moves"], list(_shp._shadow_open)))
        _shp.note_completion(_sh_home, "POST", "/v1/messages", 50.0, "sl", 200)
        _shp.note_completion(_sh_home, "POST", "/v1/messages", 70.0, "sl", 200)
        _shp.note_completion(_sh_home, "POST", "/v1/messages", 9.0, "other-lane", 200)
        _cyc0 = _shp._shadow_bucket
        _shp._shadow_roll((_cyc0 + 1) * 60.0 + 1.0)
        _c = _shp._shadow_cyc[_cyc0]
        check("S4: cycle close settles the sample -- MEDIAN of the lane's real home durations vs raw target window + Ĉ (D14/E5)",
              _c["samples"] == 1 and _c["resolved"] == 1 and _c["loss"] == 0
              and _shp.metrics["shadow_loss_moves"] == 0 and _c["unresolved"] == 0,
              str(_c))
        _sh_home.sm["cong_streak"] = 2
        _sh_home.inflight = 0
        _shp.pick("sl", body_len=8000)
        _shp.note_completion(_sh_home, "POST", "/v1/messages", 10.0, "sl", 200)
        _shp.note_completion(_sh_home, "POST", "/v1/messages", 14.0, "sl", 200)
        _cyc1 = _shp._shadow_bucket
        _shp._shadow_roll((_cyc1 + 1) * 60.0 + 1.0)
        _c2 = _shp._shadow_cyc[_cyc1]
        check("S4: home median 12 < target 30 + Ĉ 20 -- that would-move counts as a LOSS (the gate's currency)",
              _c2["resolved"] == 1 and _c2["loss"] == 1 and _shp.metrics["shadow_loss_moves"] == 1,
              str(_c2))
        _shp._affinity_put("orphan", "sh", "sticky")
        _shp.pick("orphan", body_len=8000)
        _cyc2 = _shp._shadow_bucket
        _shp._shadow_roll((_cyc2 + 1) * 60.0 + 1.0)
        check("S4: a would-move with NO post-decision turn resolves UNRESOLVED -- honest count, never silently dropped (D13)",
              _shp._shadow_cyc[_cyc2]["unresolved"] == 1
              and _shp.metrics["shadow_unresolved"] == 1 and "orphan" not in _shp._shadow_open,
              str(_shp._shadow_cyc[_cyc2]))
        _sh_tgt.sm["t_bar_window"] = None
        _before_wm = _shp.metrics["shadow_would_moves"]
        _sh_home.sm["cong_streak"] = 2
        _sh_home.inflight = 0
        _shp._affinity_put("deg", "sh", "sticky")
        _shp.pick("deg", body_len=8000)
        check("S4: target window below n_min (degraded) -- the sample is EXCLUDED, not guessed around (D9①)",
              _shp.metrics["shadow_would_moves"] == _before_wm and "deg" not in _shp._shadow_open)
        _off_home = _jbox("oh", serving=8.0)
        _off_home.sm["cong_streak"] = 2
        _offp = R.Pool([_off_home, _jbox("ot")], {})
        _offp._affinity_put("ol", "oh", "sticky")
        _offp.pick("ol", body_len=8000)
        check("S4: shadow OFF -- no lane state, no sample, no decision: the ledger stays byte-silent (§9)",
              not _offp._shadow_open and not _offp._lane
              and _offp.metrics["shadow_would_moves"] == 0)
        _st = {"k": None}
        for _i in range(70):
            _st["k"] = _shp._lane_touch("rlane")
        check("S4: R̂ rolls with observed turns, clamped [1,64] with init 4 for unseen lanes (O3 honest)",
              _shp._lane_touch("fresh")["R_hat"] == 4.0 and _st["k"]["turns"] == 70
              and _st["k"]["R_hat"] == 64.0, str(_st["k"]))
        _gp = R.Pool([], {"smart": {"smart_shadow": True, "release_gate_shadow_cycles": 2,
                                    "release_gate_min_would_moves": 20}})
        check("S4: release gate starts CLOSED -- zero completed cycles means zero evidence, and zero samples never ships (E5)",
              _gp._release_gate_open() is False)
        _gp._shadow_done = [{"cycle": 1, "samples": 5, "resolved": 5, "loss": 0, "unresolved": 0},
                            {"cycle": 2, "samples": 12, "resolved": 12, "loss": 0, "unresolved": 0}]
        check("S4: 17 resolved < min_would_moves=20 -- gate STAYS locked (禁空轉)", _gp._release_gate_open() is False)
        _gp._shadow_done[1]["samples"] = _gp._shadow_done[1]["resolved"] = 16
        check("S4: two loss-free cycles and 21 resolved -- gate OPEN (§9 data gate)",
              _gp._release_gate_open() is True)
        _gp._shadow_done[-1]["loss"] = 1
        check("S4: one loss in the last two cycles -- gate closed again (虧搬率 must be ZERO, not low)",
              _gp._release_gate_open() is False)
        del _gp._shadow_done[-1]
        check("S4: fewer than release_gate_shadow_cycles completed cycles -- closed regardless of pool size",
              _gp._release_gate_open() is False)
        _gst = _gp.status()
        check("S4: OBS exposes the gate and the cycle panel to /stats (S11)",
              _gst["release_gate_open"] is False and _gst["shadow_cycles"][-1]["samples"] == 5,
              str(_gst.get("shadow_cycles")))
        # ---- smart placement C5: L3 smart_place -- the placement face walks J ----
        print("")
        print("S5) smart L3 -- placement walks J inside the tier; ties keep today's floor (S3)")

        def _ube(bid, serving=0.0, tbar=100.0, mi=8, cap=None, debt=0, ri=False):
            b = R.Backend(bid, "http://127.0.0.1:9",
                          cfg={"max_inflight": mi, "require_idle": ri})
            b.ever_reported = True
            b.reported = {"serving": serving, "queued": 0.0}
            b.status_ts = time.monotonic()
            b.cap_slots = cap
            b.sm["t_bar_used"] = tbar
            b.sm["t_bar_window"] = tbar
            if debt:
                b._ghost_debt = [time.monotonic() + 60.0] * debt
            return b

        # Identical VISIBLE load on both boxes (reported 4.0, inflight 0) --
        # today's order sees a tie and spreads on the jitter floor. J sees the
        # difference: UA is an 8-slot promise over a 100s window (X=4x100/8=50,
        # J=70); UB declared 4 slots, rides exactly its boundary (W entry term
        # x 1s window), and four ghost debts forgive its courtesy (X=0, J=21).
        _uA, _uB = _ube("UA", serving=4.0), _ube("UB", serving=4.0, tbar=1.0, cap=4, debt=4)
        _upool = R.Pool([_uA, _uB], {"smart": {"smart_place": True, "kappa_hat": 0.01, "w_cour": 1.0}})
        _oA, _oB = _ube("OA", serving=4.0), _ube("OB", serving=4.0, tbar=1.0, cap=4, debt=4)
        _uoff = R.Pool([_oA, _oB], {})
        _upicks, _opicks = [], []
        for _i in range(20):
            for _b in (_uA, _uB, _oA, _oB):
                _b.inflight = 0
            _upicks.append(_upool._place(body_len=8000)[0].id)
            _opicks.append(_uoff._place()[0].id)
        check("S5: smart_place ON -- J reads what load_score cannot see (declared cap, T̄, ghost debt): J=21 beats J=70 every single time",
              set(_upicks) == {"UB"}, str(sorted(set(_upicks))))
        check("S5: OFF, the same pair stays today's tie -- the fan-out floor still spreads on load_score's jitter (no regression)",
              {"OA", "OB"} == set(_opicks), str(sorted(set(_opicks))))
        _udown = _ube("UD", serving=0.0, tbar=1.0)
        _udown.state = R.DOWN
        _ord_down = _upool._smart_order([_udown, _ube("UB2", serving=0.0)], time.monotonic(), 0, 4.0)
        check("S5: a DOWN box sorts LAST in a J round whatever its J says -- the trial stays behind the living",
              [x.id for x in _ord_down] == ["UB2", "UD"], str([x.id for x in _ord_down]))
        _uqA, _uqB = _ube("QA", serving=10.0, mi=2), _ube("QB", serving=2.0, mi=2)
        _uqA.inflight = _uqB.inflight = 2
        _uqp = R.Pool([_uqA, _uqB], {"smart": {"smart_place": True, "kappa_hat": 0.01, "w_cour": 1.0}})
        _q_be, _q_res = _uqp._place(body_len=8000)
        check("S5: queue-anyway fallback queues at the J-cheapest box, not the load_score-earliest (drain face)",
              _q_res is False and _q_be.id == "QB", "%s res=%s" % (_q_be.id, _q_res))
        # -- HTTP: one real boot with the flag ON: spread floor under the J-tie form + S-1's real door --
        _sp_a = FakeStrata(9175, "sa", hold=0.15)
        _sp_b = FakeStrata(9174, "sb", hold=0.15)
        _sp_a.start()
        _sp_b.start()
        with open("smart_place_probe.json", "w") as _ff:
            json.dump({"listen": "127.0.0.1", "port": 9176, "status_interval": 0.2,
                       "backends": [{"id": "sa", "url": "http://127.0.0.1:9175", "max_inflight": 8,
                                     "require_idle": True},
                                    {"id": "sb", "url": "http://127.0.0.1:9174", "max_inflight": 8,
                                     "require_idle": True}],
                       "smart": {"smart_obs": True, "smart_place": True, "n_min": 1}}, _ff)
        with open("smart_s1_probe.json", "w") as _ff:
            json.dump({"listen": "127.0.0.1", "port": 9173,
                       "backends": [{"id": "sa", "url": "http://127.0.0.1:9175", "max_inflight": 8},
                                    {"id": "sb", "url": "http://127.0.0.1:9174"}],
                       "smart": {"smart_place": True}}, _ff)
        _proc_sp = subprocess.Popen([sys.executable, ROUTER, "--config", "smart_place_probe.json",
                                     "--log-level", "WARNING"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _proc_s1 = subprocess.Popen([sys.executable, ROUTER, "--config", "smart_s1_probe.json"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            check("S5: S-1's real door -- smart_place ON with an undeclared max_inflight dies at boot, non-zero (§13-9)",
                  wait_for(lambda: _proc_s1.poll() is not None, 15)
                  and _proc_s1.returncode not in (0, None),
                  "rc=%s" % _proc_s1.returncode)
            check("S5: a legal smart boot comes up green",
                  wait_for(lambda: get(9176, "/healthz")[0] == 200, 25))
            # warm the boxes so a real T-bar window opens somewhere: sequential
            # lanes on require_idle ties spread by jitter, windows open on the
            # next 10-tick boundary (and honestly decay -- S4 pinned that, the
            # live panel must show the OPENING, racing the decay is the flake)
            for _i in range(4):
                call(9176, "/v1/messages", conv("warm%d" % _i), timeout=30)
            check("S5: the OBS panel is ALIVE on a smart boot -- a real T-bar window opens under traffic (S11)",
                  wait_for(lambda: any(
                      stats(9176)["backends"][i]["t_bar_window_s"] is not None
                      for i in range(2)), 30))
            _sp_codes = []
            for _i in range(8):
                st, _h, _bd, _w = call(9176, "/v1/messages", conv("spread%d" % _i), timeout=60)
                _sp_codes.append(st)
            _st2 = stats(9176)
            _od2 = _st2["router"].get("affinity_origin", {})
            check("S5: fan-out floor under the J-tie form -- 8 same-shape lanes all placed, all homed sticky (§13-15)",
                  all(_c == 200 for _c in _sp_codes) and _od2.get("sticky", 0) >= 8,
                  "codes=%s origins=%s" % (sorted(set(_sp_codes)), _od2))
            check("S5: ON boot reports estimator_mode=J in every box's OBS row",
                  all(b["estimator_mode"] == "J" for b in _st2["backends"]),
                  str([b["estimator_mode"] for b in _st2["backends"]]))
        finally:
            _term(_proc_sp)
            if _proc_s1.poll() is None:
                _term(_proc_s1)
            _sp_a.kill()
            _sp_b.kill()
        # ---- smart placement C6: L4 smart_preview -- a preview passes, it never homes ----
        print("")
        print("S6) smart L4 -- the preview ledger tells the truth (preview_passes, §7)")
        _pvA, _pvB = _ube("VA"), _ube("VB")
        _pvp = R.Pool([_pvA, _pvB], {"smart": {"smart_preview": True}})
        _pvp._affinity_put("lane-a", "VA", "sticky")
        _b, _rs, _res, _tk = _pvp.pick("lane-a", preview=True)
        check("S6: preview at a homed lane routes home, ticks ZERO sticky_hits -- preview_passes pays instead (§7)",
              _rs == "sticky" and _b.id == "VA" and _pvp.metrics["sticky_hits"] == 0
              and _pvp.metrics["preview_passes"] == 1, "%s pv=%s" % (_rs, _pvp.metrics["preview_passes"]))
        _b2, _rs2, _res2, _ = _pvp.pick("lane-fresh", preview=True)
        check("S6: preview finds a box but writes NO home and ticks no new_placements -- 跳寫家",
              _res2 and _pvp._affinity_get("lane-fresh") is None
              and _pvp.metrics["new_placements"] == 0 and _pvp.metrics["preview_passes"] == 2,
              "%s res=%s row=%s" % (_rs2, _res2, _pvp._affinity_get("lane-fresh")))
        _pvA.state = R.DOWN
        _b3, _rs3, _, _ = _pvp.pick("lane-a", preview=True)
        check("S6: preview at a DEAD home exiles nothing -- the lane keeps its row, no drop, no migrations tick",
              _pvA.state == R.DOWN and _pvp._affinity_get("lane-a") == "VA"
              and _pvp.metrics["migrations"] == 0 and _pvp.metrics["preview_passes"] == 3,
              "row=%s mig=%s" % (_pvp._affinity_get("lane-a"), _pvp.metrics["migrations"]))
        _pvo = R.Pool([_ube("HO", serving=1.0, ri=True), _ube("HO2")], {"smart": {"smart_preview": True}})
        _pvo._affinity_put("lane-o", "HO", "sticky")
        _b4, _rs4, _, _tk4 = _pvo.pick("lane-o", preview=True)
        check("S6: a preview NEVER overflows a lane -- no provisional re-home stashed, a token count exiles nobody",
              _tk4 is None and len(_pvo._overflow_pending) == 0 and _pvo._affinity_get("lane-o") == "HO",
              "tk=%s pend=%s" % (_tk4, len(_pvo._overflow_pending)))
        _pvs = R.Pool([_pvsh := _ube("SH", serving=8.0, cap=8), _ube("ST")],
                      {"smart": {"smart_shadow": True, "smart_preview": True, "kappa_hat": 0.01}})
        _pvsh.sm["cong_streak"] = 2
        _pvs._affinity_put("lane-s", "SH", "sticky")
        _pvs.pick("lane-s", preview=True)
        check("S6: a preview is not a conversation turn -- no lane state, no shadow sample on a congested home",
              "lane-s" not in _pvs._lane and not _pvs._shadow_open, str(list(_pvs._lane)))
        _ofo = R.Pool([_ube("OC"), _ube("OD")], {})
        _ofo.pick("off-lane", preview=True)
        check("S6: OFF -- preview is byte-for-byte today's request: home written, new_placements ticked, preview_passes untouched (§13-8)",
              _ofo._affinity_get("off-lane") is not None and _ofo.metrics["new_placements"] == 1
              and _ofo.metrics["preview_passes"] == 0)
        _pv_a = FakeStrata(9171, "pa", hold=0.1)
        _pv_b = FakeStrata(9170, "pb", hold=0.1)
        _pv_a.start()
        _pv_b.start()
        with open("smart_preview_probe.json", "w") as _ff:
            json.dump({"listen": "127.0.0.1", "port": 9172, "status_interval": 0.5,
                       "backends": [{"id": "pa", "url": "http://127.0.0.1:9171"},
                                    {"id": "pb", "url": "http://127.0.0.1:9170"}],
                       "smart": {"smart_preview": True}}, _ff)
        _proc_pv = subprocess.Popen([sys.executable, ROUTER, "--config", "smart_preview_probe.json",
                                     "--log-level", "WARNING"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            check("S6: a legal preview boot comes up green",
                  wait_for(lambda: get(9172, "/healthz")[0] == 200, 25))
            _hm = call(9172, "/v1/messages", conv("pvhome"), timeout=30)
            _hp = call(9172, "/v1/messages/count_tokens", conv("pvhome"), timeout=30)
            check("S6: live preview answers from HOME with byte-identical placement headers (placed/sticky words, no new header)",
                  _hm[0] == 200 and _hp[0] == 200
                  and _hm[1].get("x-strata-placement") == "placed"
                  and _hp[1].get("x-strata-placement") == "sticky"
                  and _hp[1].get("x-strata-backend") == _hm[1].get("x-strata-backend"),
                  "%s/%s @%s/%s" % (_hm[1].get("x-strata-placement"), _hp[1].get("x-strata-placement"),
                                    _hm[1].get("x-strata-backend"), _hp[1].get("x-strata-backend")))
            _f1 = call(9172, "/v1/messages/count_tokens", conv("pvfresh"), timeout=30)
            _f2 = call(9172, "/v1/messages", conv("pvfresh"), timeout=30)
            check("S6: live fresh preview places but homes nothing -- the conversation still PLACES when it arrives",
                  _f1[0] == 200 and _f1[1].get("x-strata-placement") == "placed"
                  and _f2[1].get("x-strata-placement") == "placed",
                  "%s/%s" % (_f1[1].get("x-strata-placement"), _f2[1].get("x-strata-placement")))
            _pr = stats(9172)["router"]
            _psum = sum(_pr.get(k, 0) for k in
                        ("sticky_hits", "new_placements", "migrations", "pinned", "last_resort",
                         "overflow_placements", "overflow_rollbacks", "overflow_fizzles",
                         "overflow_evictions", "operator_cancelled", "passthrough_gets",
                         "preview_passes"))
            check("S6: the closed identity RE-DERIVES with preview_passes as terminal #12 (requests == SUM)",
                  _psum == _pr["requests"] and _pr.get("preview_passes", 0) >= 2,
                  "requests=%s sum=%s pv=%s" % (_pr["requests"], _psum, _pr.get("preview_passes")))
        finally:
            _term(_proc_pv)
            _pv_a.kill()
            _pv_b.kill()
        # ---- smart placement C7: L5 smart_move + smart_transient + the shipping gate ----
        print("")
        print("S7) smart L5 -- the mover exists, but only on evidence (§4/§6/S9)")

        def _mrig(mv=True, **extra):
            cfg = {"smart": dict({"kappa_hat": 0.01, "w_cour": 1.0}, **({"smart_move": True} if mv else {}), **extra)}
            _h = _ube("MH", serving=8.0, cap=8)
            _h.sm["cong_streak"] = 2
            _t = _ube("MT", serving=0.0)
            _p = R.Pool([_h, _t], cfg)
            _p._affinity_put("mk", "MH", "sticky")
            return _p, _h, _t

        def _gate(p):
            for _c in (1, 2):
                p._shadow_done.append({"cycle": _c, "samples": 11, "resolved": 11, "loss": 0, "unresolved": 0})
            return p
        _mp, _mh, _mt = _mrig()
        _st = {"turns": 3, "last_move": 0.0, "R_hat": 4.0}
        _mp._smart_move("mk", _mh, 8000, _st)
        check("S7: predicate fires but the shipping gate is CLOSED -- zero evidence, zero moves, and the lock is COUNTED (S9)",
              _mp.metrics["moves"] == 0 and _mp.metrics["move_gate_locked"] == 1
              and _mp._affinity_get("mk") == "MH", "mv=%s lock=%s" % (_mp.metrics["moves"], _mp.metrics["move_gate_locked"]))
        _gate(_mp)
        _mp._smart_move("mk", _mh, 8000, _st)
        _row = _mp.affinity.get("mk")
        check("S7: gate open + all four conditions -- the lane MOVES: origin=smart (auditable), moves booked as diagnostics",
              _mp.metrics["moves"] == 1 and _row[0] == "MT" and _row[2] == "smart",
              str(_row))
        _mp._smart_move("mk", _mh, 8000, _st)
        check("S7: tau_pp_move cooldown (900s) -- a just-moved lane does not ping-pong on the very next turn",
              _mp.metrics["moves"] == 1, "mv=%s" % _mp.metrics["moves"])
        _pp, _ph, _pt = _mrig()
        _pp._affinity_put("mk", "MH", "pin")
        _gate(_pp)
        _pp._smart_move("mk", _ph, 8000, {"turns": 3, "last_move": 0.0, "R_hat": 4.0})
        check("S7: an origin=pin lane is UNTOUCHABLE by smart_move -- the exemption column does real work (V3-07)",
              _pp.metrics["moves"] == 0 and _pp.affinity.get("mk")[2] == "pin", str(_pp.affinity.get("mk")))
        _tp, _th2, _tt2 = _mrig(mv=True, tau_pp_move=0.001, tau_pp_transient=600.0)
        _tp._affinity_put("mk", "MH", "transient")
        _gate(_tp)
        _tp._smart_move("mk", _th2, 8000, {"turns": 3, "last_move": time.monotonic() - 30, "R_hat": 4.0})
        check("S7: a transient home cools on tau_pp_transient, NOT the move key -- three keys stay independent (§4.3)",
              _tp.metrics["moves"] == 0, "mv=%s" % _tp.metrics["moves"])
        _op = R.Pool([_ube("XA"), _ube("XB")], {"smart": {"smart_transient": True}})
        _op._affinity_put("tk", "XA", "sticky")
        _op._stash_pending(7, ("tk", "XA", "XB"))
        _op.overflow_commit("tk", token=7)
        _trow = _op.affinity.get("tk")
        check("S6/§13-13: transient ON -- the overflow commit homes the lane with origin=transient (commit-then-migrate)",
              _trow[0] == "XB" and _trow[2] == "transient", str(_trow))
        _oq = R.Pool([_ube("YA"), _ube("YB")], {})
        _oq._affinity_put("tk", "YA", "sticky")
        _oq._stash_pending(7, ("tk", "YA", "YB"))
        _oq.overflow_commit("tk", token=7)
        check("S7: OFF -- overflow commit stays today's sticky re-home, origins and terminals byte-unchanged (§13-8)",
              _oq.affinity.get("tk")[2] == "sticky" and _oq.metrics["overflow_placements"] == 1)
        _fp, _fh, _ft = _mrig(mv=False)
        _stf = {"turns": 1, "last_move": 0.0, "R_hat": 4.0}
        _fp.pick("mk")
        check("S7: move OFF -- a sticky hit changes nothing the mover would touch: no locks, no moves, lane untouched",
              _fp.metrics["moves"] == 0 and _fp.metrics["move_gate_locked"] == 0
              and "mk" not in _fp._lane and _fp.affinity.get("mk")[2] == "sticky")
        # -- live: gate enforcement and the transient origin, both on a real boot --
        _mv_a, _mv_b = FakeStrata(9157, "ma", hold=0.1), FakeStrata(9156, "mb", hold=0.1)
        _mv_a.start(); _mv_b.start()
        with open("smart_move_probe.json", "w") as _ff:
            json.dump({"listen": "127.0.0.1", "port": 9158, "status_interval": 0.2,
                       "backends": [{"id": "ma", "url": "http://127.0.0.1:9157", "max_inflight": 8},
                                    {"id": "mb", "url": "http://127.0.0.1:9156", "max_inflight": 8}],
                       "smart": {"smart_move": True, "smart_shadow": True}}, _ff)
        _proc_mv = subprocess.Popen([sys.executable, ROUTER, "--config", "smart_move_probe.json",
                                     "--log-level", "WARNING"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            check("S7: a legal move boot comes up green",
                  wait_for(lambda: get(9158, "/healthz")[0] == 200, 25))
            for _i in range(3):
                check("S7: live turn %d answers" % _i, call(9158, "/v1/messages", conv("mlane"), timeout=30)[0] == 200)
            _mr = stats(9158)["router"]
            check("S7: live with the flag ON -- no evidence yet means ZERO moves, the lane never moved, gate reads closed",
                  _mr["moves"] == 0 and _mr["release_gate_open"] is False
                  and _mr["affinity_origin"].get("sticky", 0) >= 1,
                  "mv=%s gate=%s" % (_mr["moves"], _mr["release_gate_open"]))
        finally:
            _term(_proc_mv)
            _mv_a.kill(); _mv_b.kill()
        _t_a, _t_b = FakeStrata(9160, "ta", hold=2.0), FakeStrata(9159, "tb", hold=0.1)
        _t_a.start(); _t_b.start()
        with open("smart_transient_probe.json", "w") as _ff:
            json.dump({"listen": "127.0.0.1", "port": 9161, "status_interval": 0.2,
                       "backends": [{"id": "ta", "url": "http://127.0.0.1:9160", "max_inflight": 1},
                                    {"id": "tb", "url": "http://127.0.0.1:9159", "max_inflight": 8}],
                       "smart": {"smart_transient": True}, "control_token": "s7ctl"}, _ff)
        _proc_tv = subprocess.Popen([sys.executable, ROUTER, "--config", "smart_transient_probe.json",
                                     "--log-level", "WARNING"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            check("S7: a legal transient boot comes up green",
                  wait_for(lambda: get(9161, "/healthz")[0] == 200, 25))
            # determinism without coin flips: an operator pin puts turn 1 on
            # the one-slot slow box (pin is also the honest stress of §6's
            # claim -- the transient put must be able to RE-HOME a lane that
            # the pin seated, because pin governs placement, not fate). Turn
            # 2 finds the slot held by its own lane -- the cap branches it.
            _ctl = {"x-strata-pin": "ta", "x-strata-control": "s7ctl"}
            _w1 = threading.Thread(target=lambda: call(9161, "/v1/messages", conv("tlane"),
                                                        extra=_ctl, timeout=40))
            _w1.start()
            time.sleep(0.5)              # turn 1 holds ta's only slot
            _t_b.blind = False
            time.sleep(0.4)              # poller sees tb healthy again
            _t2s, _t2h = call(9161, "/v1/messages", conv("tlane"), timeout=40)[:2]
            _w1.join()
            check("S7: second turn OVERFLOWED the capped home and answered from the peer (§6 commit-then-migrate)",
                  _t2s == 200 and _t2h.get("x-strata-placement") == "overflow"
                  and _t2h.get("x-strata-backend") == "tb",
                  "%s @%s" % (_t2h.get("x-strata-placement"), _t2h.get("x-strata-backend")))
            _tr = stats(9161)["router"]
            check("S7: LIVE origin=transient -- the answered overflow homed the lane and the origin column says so (§13-13)",
                  _tr["affinity_origin"].get("transient", 0) >= 1, str(_tr["affinity_origin"]))
        finally:
            _term(_proc_tv)
            _t_a.kill(); _t_b.kill()
        # ---- smart placement C8: L6 smart_homecoming -- exile is not fate, but proof is the gate ----
        print("")
        print("S8) smart L6 -- the lane walks home only on a two-poll proof (§5)")
        _ho, _hw = _ube("GA"), _ube("GB")
        _hp = R.Pool([_ho, _hw], {"smart": {"smart_homecoming": True}})
        _hp._affinity_put("hk", "GB", "sticky")
        _hp._exiled["hk"] = "GA"
        _ho.sm["empty_streak"] = 2
        _ho.sm["feed_blind"] = False           # a never-polled box is born blind (router :268) -- and a blind feed is exactly what D4' refuses
        _hp._homecoming("hk", _hw, {"turns": 2, "last_move": 0.0, "R_hat": 4.0})
        check("S8: exiled lane comes home on the two-poll verifiably-empty proof -- origin=smart, homecomings booked",
              _hp.affinity.get("hk")[0] == "GA" and _hp.affinity.get("hk")[2] == "smart"
              and _hp.metrics["homecomings"] == 1, str(_hp.affinity.get("hk")))
        _hp._affinity_put("hk2", "GB", "sticky")
        _hp._exiled["hk2"] = "GA"
        _hp._homecoming("hk2", _hw, {"turns": 2, "last_move": 0.0, "R_hat": 4.0})
        check("S8: the per-box 120s throttle holds -- a freed box drains ONE lane, not its queue (§13-5)",
              _hp.metrics["homecomings"] == 1 and _hp.affinity.get("hk2")[0] == "GB")
        _hp2 = R.Pool([_ho2 := _ube("HA"), _ube("HB")], {"smart": {"smart_homecoming": True}})
        _hp2._affinity_put("k1", "HB", "sticky")
        _hp2._exiled["k1"] = "HA"
        _ho2.sm["empty_streak"] = 1
        _ho2.sm["feed_blind"] = False          # unblind so the streak is the ONLY refusing item
        _hp2._homecoming("k1", _hp2.backends[1], {"turns": 2, "last_move": 0.0, "R_hat": 4.0})
        check("S8: one empty report is not a proof -- streak<2 keeps the lane put (D4' x2 consecutive)",
              _hp2.metrics["homecomings"] == 0 and _hp2.affinity.get("k1")[0] == "HB")
        _hp3 = R.Pool([_ho3 := _ube("IA"), _ube("IB")], {"smart": {"smart_homecoming": True}})
        _hp3._affinity_put("k2", "IB", "transient")
        _hp3._exiled["k2"] = "IA"
        _ho3.sm["empty_streak"] = 5
        _ho3.sm["feed_blind"] = False          # box fully proven -- only the transient origin may refuse
        _hp3._homecoming("k2", _hp3.backends[1], {"turns": 2, "last_move": 0.0, "R_hat": 4.0})
        check("S8: transient homes belong to the MOVER -- homecoming skips them (§5 scope, two mechanisms never stack)",
              _hp3.metrics["homecomings"] == 0 and _hp3.affinity.get("k2")[0] == "IB")
        _hp4 = R.Pool([_ho4 := _ube("JA"), _ube("JB")], {"smart": {"smart_homecoming": True}})
        _hp4._affinity_put("k3", "JB", "sticky")
        _hp4._exiled["k3"] = "JA"
        _ho4.sm["empty_streak"] = 5
        _ho4.sm["feed_blind"] = False          # box fully proven -- only the lane's own cooldown may refuse
        _hp4._homecoming("k3", _hp4.backends[1], {"turns": 2, "last_move": time.monotonic() - 30, "R_hat": 4.0})
        check("S8: a just-moved lane waits out tau_pp_homecoming (900s) even beside a fully proven empty box",
              _hp4.metrics["homecomings"] == 0)
        _of = R.Pool([_ube("KA"), _ube("KB")], {})
        _of._affinity_put("ok", "KB", "sticky")
        _of._exile_note("ok", "KA")
        _of.pick("ok")
        check("S8: OFF -- the machinery is inert: no memory recorded, no decision read, counters byte-silent (§13-8)",
              _of.metrics["homecomings"] == 0 and "ok" not in _of._exiled
              and _of.affinity.get("ok")[0] == "KB")
        # -- live: the whole arc on one real boot -- exiled by cap, home empties, lane walks back
        _hc_a, _hc_b = FakeStrata(9155, "ha", hold=2.0), FakeStrata(9154, "hb", hold=0.1)
        _hc_a.start(); _hc_b.start()
        with open("smart_homecoming_probe.json", "w") as _ff:
            json.dump({"listen": "127.0.0.1", "port": 9153, "status_interval": 0.2,
                       "backends": [{"id": "ha", "url": "http://127.0.0.1:9155", "max_inflight": 1},
                                    {"id": "hb", "url": "http://127.0.0.1:9154", "max_inflight": 8}],
                       "smart": {"smart_homecoming": True}, "control_token": "s8ctl"}, _ff)
        _proc_hc = subprocess.Popen([sys.executable, ROUTER, "--config", "smart_homecoming_probe.json",
                                     "--log-level", "WARNING"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            check("S8: a legal homecoming boot comes up green",
                  wait_for(lambda: get(9153, "/healthz")[0] == 200, 25))
            _hc_ctl = {"x-strata-pin": "ha", "x-strata-control": "s8ctl"}
            _w = threading.Thread(target=lambda: call(9153, "/v1/messages", conv("hclane"),
                                                       extra=_hc_ctl, timeout=40))
            _w.start()
            time.sleep(0.5)
            call(9153, "/v1/messages", conv("hclane"), timeout=40)     # cap-refused: overflow -> hb
            _w.join()                                                  # ha's slot frees here
            time.sleep(2.0)                                            # ha verifiably empty, x2 fresh
            call(9153, "/v1/messages", conv("hclane"), timeout=40)     # the turn the proof fires on
            _t4 = call(9153, "/v1/messages", conv("hclane"), timeout=40)  # the next turn walks home
            _hr = stats(9153)["router"]
            check("S8: LIVE arc -- exiled by cap, home proved empty x2, lane walked home: sticky@ha, counters agree",
                  _t4[0] == 200 and _t4[1].get("x-strata-backend") == "ha"
                  and _hr["homecomings"] >= 1 and _hr["affinity_origin"].get("smart", 0) >= 1,
                  "b4=%s hc=%s o=%s" % (_t4[1].get("x-strata-backend"), _hr["homecomings"],
                                        _hr["affinity_origin"]))
        finally:
            _term(_proc_hc)
            _hc_a.kill(); _hc_b.kill()

        print("")
        print("S9) smart L9 -- the whole-ladder matrix: 64 flag combos close the identity; no dead knobs")
        # Docs-as-code: a knob registered in SMART_NUMS that NO read site ever
        # reads is worse than an unknown knob (unknown ones at least
        # warn-and-ignore). homecoming_lane_s was such a corpse -- the per-lane
        # homecoming ceiling is tau_pp_homecoming, and the table must say so.
        check("S9: no knob is registered that the code never reads (homecoming_lane_s is dead)",
              "homecoming_lane_s" not in R.SMART_NUMS, str(R.SMART_NUMS))
        _ver = subprocess.run([sys.executable, ROUTER, "--version"], capture_output=True,
                              text=True, timeout=30).stdout.strip()
        check("S9: --version speaks the shipped release (the bump is the release note's first line)",
              _ver == "1.2.18", _ver)
        _TERMS = ("sticky_hits", "new_placements", "migrations", "pinned", "last_resort",
                  "overflow_placements", "overflow_rollbacks", "overflow_fizzles",
                  "overflow_evictions", "operator_cancelled", "passthrough_gets",
                  "preview_passes")
        _FL6 = ("smart_cap_read", "smart_shadow", "smart_place",
                "smart_preview", "smart_move", "smart_transient")
        # 64 combinations of every action flag, each pool fed the SAME traffic:
        # 3 lanes placed then re-visited (sticky), 2 previews (one fat), 1 pin,
        # 1 passthrough. The closed identity is not allowed to care which rungs
        # of the ladder are lit -- requests == SUM(12 terminals) in every combo.
        _bad = None
        for _mask in range(64):
            _combo = {f: bool(_mask & (1 << _i)) for _i, f in enumerate(_FL6)}
            _combo["smart_homecoming"] = bool(_mask & 32)
            _bp = R.Pool([_ube("MA", mi=64), _ube("MB", mi=64)], {"smart": _combo})
            for _r in range(2):
                for _k in ("m0", "m1", "m2"):
                    _bp.pick(_k, body_len=200)
            _bp.pick("m0", preview=True)
            _bp.pick("m1", preview=True, body_len=4096)
            _bp.pick("m2", pin="MA")
            _bp.pick("", passthrough=True)
            _m = _bp.metrics
            _why = None
            if _m["requests"] != sum(_m.get(t, 0) for t in _TERMS):
                _why = "identity: requests=%s sum=%s" % (_m["requests"], sum(_m.get(t, 0) for t in _TERMS))
            elif any(len(v) != 3 or v[2] not in ("pin", "sticky", "smart", "transient")
                     for v in _bp.affinity.values()):
                _why = "affinity rows must be (id, ts, origin) from the named set"
            elif _m["moves"] != 0 or _m["homecomings"] != 0:
                _why = "no combo of this traffic may move or bring home a lane"
            elif not any(_combo[f] for f in ("smart_shadow", "smart_move", "smart_homecoming")) and _bp._lane:
                _why = "lane state was created with no flag that reads lanes lit"
            if _why and _bad is None:
                _bad = "%s: %s" % (_combo, _why)
        check("S9: all 64 flag combinations boot, serve, close the identity and create no rogue state (D9/§13-8)",
              _bad is None, str(_bad))
        # targeted cross-flag pins: a rung must never SILENTLY depend on another
        _lp = R.Pool([_ube("NA", mi=64), _ube("NB", mi=64)], {"smart": {"smart_place": True}})
        _lp.pick("p0", body_len=200); _lp.pick("p0", body_len=200)
        check("S9: place-alone speaks J on the FLOOR R-hat -- no lane state is born for a currency nobody measures",
              _lp.metrics["new_placements"] >= 1 and len(_lp._lane) == 0,
              "%s lanes=%s" % (_lp.metrics["new_placements"], len(_lp._lane)))
        _lm = R.Pool([_ube("OA", mi=64), _ube("OB", mi=64)], {"smart": {"smart_move": True}})
        _lm.pick("q0", body_len=200); _lm.pick("q0", body_len=200)
        check("S9: move-alone without shadow data never moves and never even reaches the gate (predicate first, gate last)",
              _lm.metrics["moves"] == 0 and _lm.metrics["move_gate_locked"] == 0,
              "mv=%s lock=%s" % (_lm.metrics["moves"], _lm.metrics["move_gate_locked"]))
        # shipping shape: every rung lit at once, one real boot
        _la, _lb = FakeStrata(9145, "la", hold=0.1), FakeStrata(9147, "lb", hold=0.1)
        _la.start(); _lb.start()
        with open("smart_allon_probe.json", "w") as _ff:
            json.dump({"listen": "127.0.0.1", "port": 9146, "status_interval": 0.2,
                       "backends": [{"id": "la", "url": "http://127.0.0.1:9145", "max_inflight": 8},
                                    {"id": "lb", "url": "http://127.0.0.1:9147", "max_inflight": 8}],
                       "smart": {f: True for f in
                                 ("smart_obs", "smart_cap_read", "smart_shadow", "smart_place",
                                  "smart_preview", "smart_move", "smart_transient", "smart_homecoming")}}, _ff)
        _proc_all = subprocess.Popen([sys.executable, ROUTER, "--config", "smart_allon_probe.json",
                                      "--log-level", "WARNING"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            check("S9: the all-on shipping boot comes up green",
                  wait_for(lambda: get(9146, "/healthz")[0] == 200, 25))
            _ar = call(9146, "/v1/messages", conv("allon"), timeout=40)
            _am = stats(9146)["router"]
            check("S9: LIVE all-on -- traffic served, every smart panel column present, identity closed",
                  _ar[0] == 200
                  and all(k in _am for k in ("shadow_cycles", "release_gate_open", "affinity_origin",
                                             "moves", "homecomings", "preview_passes", "move_gate_locked"))
                  and _am["requests"] == sum(_am.get(t, 0) for t in _TERMS),
                  "st=%s cols=%s rq=%s sum=%s" % (_ar[0],
                                                  [k for k in ("shadow_cycles", "release_gate_open", "affinity_origin") if k not in _am],
                                                  _am["requests"], sum(_am.get(t, 0) for t in _TERMS)))
        finally:
            _term(_proc_all)
            _la.kill(); _lb.kill()

        # ---- DV round-1 fix-locks: every check below pins ONE CONFIRMED fidelity-
        # audit finding (adjudication table in the notes dir). Authored against the
        # findings and run RED against the pre-fix router FIRST; crash-finders are
        # captured in a try so ONE run shows ALL the reds, not only the first.
        print("")
        print("S10) smart L10 -- the fix round: red locks on the fidelity audit's confirmed findings (DV round-1)")

        # F1 (P1): _shadow_note_turn unpacked (tgt, _ph, pt) but its log line
        # read ph -- NameError AFTER the booking and INSIDE the sticky branch's
        # try, i.e. it silently skipped homecoming AND the mover on every
        # would-move turn: shadow+move co-lit never moved (the shipping shape).
        _fp, _fh, _ft = _mrig(mv=False, smart_shadow=True)
        try:
            _fp._shadow_note_turn("mk", _fh, 8000, {"turns": 3, "last_move": 0.0, "R_hat": 4.0})
            _f1 = "ok"
        except Exception as _e1:
            _f1 = repr(_e1)
        check("S10/F1: the shadow note runs end to end -- ledger booked AND log line bound (no NameError tax on L5/L6 behind the sticky try)",
              _f1 == "ok" and _fp.metrics["shadow_would_moves"] == 1 and "mk" in _fp._shadow_open,
              "f1=%s wm=%s open=%s" % (_f1, _fp.metrics["shadow_would_moves"], list(_fp._shadow_open)))

        # F2 (P1): the OBS branch of _smart_tick_locked read w/base, bound ONLY
        # by the window-boundary branch -- obs_every_polls misaligned with
        # window_n made the first in-between OBS tick raise UnboundLocalError
        # OUTSIDE the poller's try: the poller thread DIED, taking every box's
        # feed with it. The defaults 10/10 are aligned by luck and hid it.
        _ob9 = _ube("OB1")
        _osc = {"smart_obs": True, "obs_every_polls": 5, "window_n": 10}
        _oline = "UNREACHED"
        try:
            for _i in range(5):
                _oline = _ob9._smart_tick_locked(_osc, time.monotonic())
        except Exception as _e2:
            _oline = repr(_e2)
        check("S10/F2: an OBS tick BETWEEN window boundaries speaks -- cadence and window need no common divisor",
              _oline != "UNREACHED" and "OBS box=OB1" in str(_oline) and "Error" not in str(_oline),
              repr(_oline))

        # F3 (P1): note_completion's own docstring promised "every failure
        # never count" -- nothing filtered status. A 500's seconds fed T-bar,
        # T-bar feeds every J and every W: an outage made HOME look expensive,
        # so placement grew FAILURE-ATTRACTING. The legacy stats beside it are
        # untouched (pre-existing production ledger); only the smart feed locks.
        _nb9 = _ube("NC")
        _np9 = R.Pool([_nb9], {"smart": {"smart_obs": True}})
        _t0 = (_nb9.sm["streams_s"], _nb9.sm["dur_sum_s"])
        _lg0 = dict(_nb9.stats)
        _f3 = "ok"
        try:
            _np9.note_completion(_nb9, "POST", "/v1/messages", 30.0, "", 500)
            _np9.note_completion(_nb9, "POST", "/v1/messages", 30.0, "", 503)
            _np9.note_completion(_nb9, "POST", "/v1/messages", 30.0, "", 200)
        except Exception as _e3:
            _f3 = repr(_e3)
        check("S10/F3: the docstring becomes the code -- >=400 feeds the smart T-bar NOTHING, 200 feeds exactly one; the legacy stats beside it untouched",
              _f3 == "ok" and _nb9.sm["streams_s"] == _t0[0] + 1
              and abs(_nb9.sm["dur_sum_s"] - (_t0[1] + 30.0)) < 1e-9 and dict(_nb9.stats) == _lg0,
              "f3=%s sm=%s legacy_moved=%s" % (_f3, (_nb9.sm["streams_s"], _nb9.sm["dur_sum_s"]),
                                               dict(_nb9.stats) != _lg0))

        # F4+F13 (P2): the D4' freshness proof lived only in feed_blind -- and
        # a frozen feed FREEZES the flag at its last value. A dead poller's
        # last word ("empty x2, fresh!") therefore latched forever: lanes would
        # walk home to a box nobody is watching anymore. The door must re-ask
        # the LIVE clock (F4) and the LIVE state table (F13), not the latch.
        _hp5 = R.Pool([_ho5 := _ube("QA"), _ube("QB")], {"smart": {"smart_homecoming": True}})
        _ho5.sm["feed_blind"] = False        # the frozen latch: last poll before the death said FRESH
        _ho5.sm["empty_streak"] = 2
        _hp5._exiled["kq5"] = "QA"
        _ho5.status_ts = time.monotonic() - 60.0   # ...but the clock says the feed died a minute ago
        check("S10/F4: a frozen feed_blind=False is no evidence forever -- the homecoming door re-asks the LIVE clock (a dead poller cannot send lanes home)",
              _hp5._homecoming("kq5", _hp5.by_id["QB"], {"turns": 1, "last_move": 0.0, "R_hat": 4.0}) is False)
        _hp6 = R.Pool([_ho6 := _ube("RA"), _ube("RB")], {"smart": {"smart_homecoming": True}})
        _ho6.sm["feed_blind"] = False
        _ho6.sm["empty_streak"] = 2
        _ho6.state = R.SUSPECT               # the poller is alive and says: NOT healthy
        _hp6._exiled["kq6"] = "RA"
        check("S10/F13: a SUSPECT home never receives a lane home -- D4' item one is re-verified live, not remembered",
              _hp6._homecoming("kq6", _hp6.by_id["RB"], {"turns": 1, "last_move": 0.0, "R_hat": 4.0}) is False)
        _hp7 = R.Pool([_ho7 := _ube("SA"), _ube("SB")], {"smart": {"smart_homecoming": True}})
        _ho7.sm["feed_blind"] = False        # fixtures unblinded: a polled box with a fresh feed (C8 lesson)
        _ho7.sm["empty_streak"] = 2
        _hp7._exiled["kq7"] = "SA"
        check("S10/F4: the fresh, HEALTHY, verifiably-empty home STILL welcomes the lane -- the new guards prove, they do not veto",
              _hp7._homecoming("kq7", _hp7.by_id["SB"], {"turns": 1, "last_move": 0.0, "R_hat": 4.0}) is True)

        # F6 (P2): _lane was capped FIFO, not LRU -- past 20000 lanes the
        # eviction killed the HOTTEST lane's row, voiding its tau cooldown and
        # R-hat history: a busy pool could move the same hot lane twice inside
        # one cooldown window. A lane that just spoke must outlive the cap.
        _lp2 = R.Pool([_ube("LZ")], {})
        for _i in range(19999):
            _lp2._lane_touch("lane%05d" % _i)
        _lp2._lane_touch("lane00000")                  # a TURN for the oldest lane: it is alive
        _lp2._lane_touch("lane20000"); _lp2._lane_touch("lane20001")
        check("S10/F6: a lane that just spoke survives the cap -- eviction is least-RECENTLY-used, not first-born",
              "lane00000" in _lp2._lane and "lane00001" not in _lp2._lane,
              "hot_survives=%s cold=%s len=%s" % ("lane00000" in _lp2._lane,
                                                  "lane00001" not in _lp2._lane, len(_lp2._lane)))

        # F7 (P2): overflow placement is tier-bound -- the step to the next
        # tier is the OPERATOR's priority ladder -- but the mover crossed
        # tiers, silently promoting a lane to a tier no operator priced for
        # it. Tier law: the mover moves WITHIN the home's tier; crossing
        # stays an operator decision (x-strata-pin, priority). Disclosed.
        _t7h = _ube("7H", serving=8.0, cap=8); _t7h.sm["cong_streak"] = 2
        _t7t = _ube("7T", serving=0.0); _t7t.priority = 1
        _t7p = R.Pool([_t7h, _t7t], {"smart": {"smart_move": True, "kappa_hat": 0.01, "w_cour": 1.0}})
        _t7p._affinity_put("mk7", "7H", "sticky")
        _gate(_t7p)                          # the data gate OPEN -- only the tier law may refuse
        _t7p._smart_move("mk7", _t7h, 8000, {"turns": 3, "last_move": 0.0, "R_hat": 4.0})
        check("S10/F7: the mover does not cross tiers -- all four conditions true and the gate open, a tier-1-only target still means stand down (predicate first, so the gate never even hears about it)",
              _t7p.metrics["moves"] == 0 and _t7p.metrics["move_gate_locked"] == 0
              and _t7p._affinity_get("mk7") == "7H",
              "mv=%s lock=%s aff=%s" % (_t7p.metrics["moves"], _t7p.metrics["move_gate_locked"],
                                        _t7p._affinity_get("mk7")))

        # F8 (P3): ghost debt was aged by TWO clocks -- J asked "debt newer
        # than THIS instant", the poller prunes "newer than the last status".
        # A debt that settled between polls kept hiding real load from J for a
        # full poll cycle. One clock: the status stamp (the poller's own line).
        _f8b = _ube("F8", serving=6.0, cap=4, tbar=50.0)
        _n8 = time.monotonic()
        _f8b.status_ts = _n8 - 0.2
        _f8b._ghost_debt = [_n8 - 0.1]      # born AFTER the last status: this box HAS been busier than it reports
        _p8 = R.Pool([_f8b], {"smart": {"w_cour": 1.0, "kappa_hat": 0.0}})
        _j8 = _p8._j_parts(_f8b, _n8, 0, 4.0)
        check("S10/F8: ghost debt ages on the STATUS clock -- a debt newer than the last poll still speaks (rep 6.0, one ghost: X=(6-0-1)*50/4=62.5, not the sighted 75)",
              _j8 is not None and abs(_j8["X"] - 62.5) < 1e-9, repr(_j8))

        # F15 (P3): every smart number was float-checked, but five are tick
        # counters and minimums -- the read sites int() them, so window_n=2.7
        # "worked" as 2 while the operator believed 2.7. Int-typed knobs
        # refuse a fraction at boot, BY NAME (the validator never truncates).
        _pr15 = R.validate_cfg({"smart": {"window_n": 2.7}}, R.Pool([], {}), strict=False)
        check("S10/F15: a tick-counter knob refuses a float at boot -- window_n=2.7 would silently run as 2; refuse by name, never truncate at the read site",
              any("window_n" in k for k, _w in _pr15), repr(_pr15))

        # F16 (P3): a sample whose cycle table was trimmed away vanished
        # mid-settle in total silence. 64 weekly buckets is a year -- the trim
        # is a bug path; if it ever bites, the ledger says so OUT LOUD.
        # (Fix is a warning line: nothing observable pre-fix but the silence.)
        _p16 = R.Pool([], {"smart": {"smart_shadow": True}})
        _f16 = "ok"
        try:
            _p16._shadow_settle({"key": "zz", "bucket": 999999, "home": "h", "target": "t",
                                 "c_hat": 0.0, "durs": [1.0]})
        except Exception as _e16:
            _f16 = repr(_e16)
        check("S10/F16: settling a sample whose cycle table is gone is a NAMED loss, never a crash",
              _f16 == "ok", _f16)

        # F5 (P2): the shadow tables were mutated UNLOCKED -- the poller's
        # _shadow_roll raced the request threads' _shadow_note_turn on
        # _shadow_open/_shadow_cyc/_shadow_done, and the poller's call sat
        # outside its try (a racing death was a DEAD POLLER). Discipline: one
        # dedicated shadow lock (pool.lock would deadlock status(), which
        # already holds it), table cores run under it, LOG outside it, the
        # poller's calls land INSIDE its try. A race is a race: pre-fix this
        # stress may or may not catch it (it also collects F1's NameError tax)
        # -- the lock is the fix, this is the regression net.
        import threading as _th
        _shh = _ube("SH1", serving=8.0, cap=8); _shh.sm["cong_streak"] = 2
        _sp5 = R.Pool([_shh, _sht := _ube("ST1")],
                      {"smart": {"kappa_hat": 0.001, "w_cour": 1.0, "shadow_cycle_s": 0.02}})
        _errs5 = []

        def _note5(_lo, _hi):
            for _k in range(_lo, _hi):
                try:
                    _sp5._shadow_note_turn("s5k%05d" % _k, _shh, 8000,
                                           {"turns": 3, "last_move": 0.0, "R_hat": 4.0})
                except Exception as _e:
                    _errs5.append(repr(_e))

        def _roll5(_n):
            for _i in range(_n):
                try:
                    _sp5._shadow_roll(time.monotonic())
                    _sp5._release_gate_open()
                except Exception as _e:
                    _errs5.append(repr(_e))
        _old_si = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            _ts5 = [_th.Thread(target=_note5, args=(0, 300)), _th.Thread(target=_note5, args=(300, 600)),
                    _th.Thread(target=_roll5, args=(1200,)), _th.Thread(target=_roll5, args=(1200,))]
            for _t5 in _ts5:
                _t5.start()
            for _t5 in _ts5:
                _t5.join(timeout=180)
        finally:
            sys.setswitchinterval(_old_si)
        check("S10/F5: note_turn x roll x gate under a 1us switch interval and a 20ms shadow cycle -- no thread dies and the ledger keeps no torn state",
              not _errs5, repr(_errs5[:4]))

        # B2 (behavioral face, adopted P3): the sticky-decision catch-all logged
        # swallowed failures at LOG.debug ONLY -- the exact invisibility that
        # hid F1 through three INFO-level rounds (diagnostics ticking while the
        # decision layer died behind the try). The swallow gets witnesses: a
        # NAMED panel counter (diagnostics -- never in the closed identity)
        # and a rate-limited WARNING; serving continues either way.
        _b2 = R.Pool([_b2h := _ube("BH", mi=64), _ube("BT", mi=64)],
                     {"smart": {"smart_shadow": True}})
        _b2._affinity_put("kb2", "BH", "sticky")

        def _b2boom(*a, **k):
            raise RuntimeError("poisoned decision (B2 lock)")
        _b2._shadow_note_turn = _b2boom           # an internal crash at the exact spot F1 died
        _b2.pick("kb2", body_len=200)
        check("S11/B2: a swallowed smart-decision failure books a NAMED counter and the request still serves at home -- the debug-only swallow that hid F1 never gets to be the only witness again",
              _b2.metrics.get("smart_decision_errors") == 1 and _b2.metrics["sticky_hits"] == 1
              and _b2.metrics["requests"] == sum(_b2.metrics.get(t, 0) for t in _TERMS),
              "err=%s sticky=%s rq=%s sum=%s" % (_b2.metrics.get("smart_decision_errors"),
                                                 _b2.metrics["sticky_hits"], _b2.metrics["requests"],
                                                 sum(_b2.metrics.get(t, 0) for t in _TERMS)))
    finally:
        _term(proc)
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except OSError:
                pass
        for bx2 in (a, b):
            try:
                bx2.kill()
            except Exception:
                pass

    print("")
    if FAKE_ERRORS:
        print("FakeStrata swallowed %d handler tracebacks (last few):" % len(FAKE_ERRORS))
        for _fe in FAKE_ERRORS[-3:]:
            print("---- FAKE ERROR ----")
            print(_fe)
    print("%d checks passed, %d failed" % (len(CHECKS), len(FAILS)))
    for f in FAILS:
        print("  FAILED: " + f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
