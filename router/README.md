# strata-router

Two identical boxes, one model, `parallel` off. Each box serves one request at a
time and parks the rest in its own FIFO. This sits in front of both so that:

* a task that cannot start yet **waits** instead of dying on a 429,
* the second box actually absorbs work rather than doubling prompt re-reads,
* `/v1/messages` (Anthropic) and `/v1/responses` (Codex) stay byte-compatible.

It is one stdlib-only Python file. No translation, no dependencies, no rate
limiter. Needs **Python 3.8+**; on a fresh Windows 11 the `python` command is
the Store stub that opens the Store -- install Python from python.org (tick
*Add to PATH*) or type every command below as `py -3 router.py ...`.

## Contents

- [The design, in four rules](#the-design-in-four-rules)
- [Start](#start)
- [Configuration reference](#configuration-reference)
- [Wire the clients](#wire-the-clients)
- [Read this before you debug "it stopped after N minutes"](#read-this-before-you-debug-it-stopped-after-n-minutes)
- [Ops](#ops)
- [Tiered placement: local first, the peer only when it is verifiably idle](#tiered-placement-local-first-the-peer-only-when-it-is-verifiably-idle)
- [Limits](#limits)
- [Tests](#tests)

## The design, in four rules

| # | Rule | Why |
|---|------|-----|
| 1 | **Passthrough only.** Nothing parses the body except an optional `model` rewrite. | Translation is where thinking-block signatures, `tool_use`, `stop_reason`, `cache_control` and SSE event names break. |
| 2 | **Never returns 429, never queues here.** Requests go straight into the backend FIFO. | The queue must live next to the real slots. A second admission queue in a proxy only invents 429s and hides backpressure. |
| 3 | **Affinity first, least-queued second.** Each conversation *lane* is pinned to one box; only brand-new lanes are placed, onto the shallowest queue. A pinned lane whose box is at capacity **overflows** to an open box and stays there. Optionally tiered (`priority` / `max_inflight` / `require_idle`): local first, a borrowed peer only while verifiably idle -- see *Tiered placement* below. | With `parallel` off, a box holds one conversation's cache. Round-robin makes every turn re-read its prompt on a cold box -- two boxes then become slower than one. |
| 4 | **Health = connection failure only.** 429 / `queue_wait_timeout` / slow first byte / 5xx never eject a box. | Busy is not dead. Ejecting a box because it is loaded halves your capacity exactly when you need it. |

## Start

```powershell
# 0. no router.json yet? copy the shipped template first -- the destination
#    router.json is the git-ignored one (the template itself is tracked), so
#    the copy stays local by construction; then edit it:
#    backends' ids/URLs, probe_model, prefixes -- real coordinates stay local
copy router.remote.example.json router.json      # PowerShell; `cp` on POSIX

# 1. on key-required boxes, fill the keys FIRST (hidden prompt, never echoed)
python router.py --set-key local  --config router.json
python router.py --set-key remote --config router.json   # the borrower key

# 2. verify each box: which paths it serves, which status field holds load
python router.py --probe --config router.json

# 3. run it
python router.py --config router.json
```

A `--config` file that does not exist yet refuses to boot with a named error
pointing back at this step -- and so does one that cannot be a config (a
directory, an empty or broken file, a JSON non-object): named error, no
traceback. Or skip the file entirely with `--backend id=http://host:port`
flags.

One flag note before you grep this README for them: `--listen` and `--port`
are `router.py`'s own bind overrides (config keys `listen`/`port`); `--host`
and `--queue-timeout` appear later only as **Strata box** flags --
`router.py` has neither (its closest knobs are `--read-timeout`, which never
cancels a queued request, and `--connect-timeout`).

Run `--probe` before trusting any config -- and after the keys: on keyed
boxes a keyless probe only proves the box can answer 401. The probe STREAMS,
and the response headers are its verdict: a healthy but BUSY box (your slot
taken, the request parked in the box's own FIFO) answers in seconds and is
cancelled by the box about 10 s after the probe exits -- a parked ping, never
a stolen turn. A healthy COLD box can still print `unreachable`: the first
request auto-loads the model and can outlast the probe's 60 s patience; run
it once warm. The two questions `--probe` actually answers: does the
Anthropic API live on `/v1/messages` or `/anthropic/v1/messages` (if the
latter, add `--path-prefix /anthropic`), and which status field exposes load.

Point the boxes at each other over the tailnet: Strata binds ONE address
(`--host`), and each side's own router reaches its local box on `127.0.0.1`,
so bind the box broadly (`--host 0.0.0.0`) and let the FIREWALL do the
scoping -- open the serving port only to the peer's Tailscale IP:
`New-NetFirewallRule -DisplayName "Strata peer" -Direction Inbound -Protocol TCP
-LocalPort 8081 -RemoteAddress <peer-tailnet-IP> -InterfaceAlias Tailscale
-Action Allow -Profile Any` (use your Strata's port). One port doctrine to
pin before you mirror files between boxes: each box's `local` entry
declares its own serving port, and the `remote` URL carries the PEER's
tailnet-serving port -- which need not equal yours, so your `remote` port
must equal the port the peer's `local` entry declares. The shipped
template deliberately assumes asymmetric boxes (local serves `8081`, the
peer serves `8080`), so each side's firewall `-LocalPort` must match the
port THAT box serves. Want a symmetric mirror (both boxes copy one file
verbatim)? Make all three spots agree on ONE serving port: both `local`
entries, both `remote` entries, and both firewall rules. When Strata first binds
`0.0.0.0` Windows raises its allow/deny popup -- press **Cancel**: the popup's
machine-wide allow rule is something a later scoped rule can never narrow (an
Allow never scopes another Allow), so one curious click silently leaves the
serving port open to the LAN. And check the adapter's real name before pasting
(`Get-NetAdapter | Select-Object Name`) -- it is `Tailscale` or
`vEthernet (Tailscale)` depending on install, and a wrong `-InterfaceAlias`
binds a rule that matches nothing. A tailnet-only bind
breaks that box's OWN router, which talks to it on loopback. Run the router
on the machine that runs Codex, so there is one endpoint to configure.
Restart only BETWEEN turns -- a stop closes every router-to-box connection,
exactly like closing the console window does, and the box's hang-up watcher
then cancels the in-slot turn within ~1 s and the parked one at its next beat
(<= ~10 s): whatever is in flight when you restart dies at the box and must be
re-asked (whether Claude Code retries a cut stream is its own retry policy --
do not count on it). Affinity also lives in memory, so roughly half the live
conversations re-read their prompt once on the new process.

## Configuration reference

Every knob exists as a CLI flag *and* as a `router.json` key (the flag wins;
`--config` takes any key below). Actions (`--set-key`, `--probe`,
`--version`) do their job and exit.

| Flag | Config key | Default | Meaning |
|------|-----------|---------|---------|
| `--config FILE` | — | — | JSON file with any keys below. |
| `--backend ID=URL[,/prefix]` | `backends` | `[]` | One entry per box, repeat per box. |
| `--listen ADDR` | `listen` | `127.0.0.1` | Bind address; a non-loopback bind tightens the Host guards. |
| `--port N` | `port` | `8088` | The router's own port. |
| `--path-prefix /P` | `path_prefix` | `""` | Prefix prepended to every backend path (e.g. `/anthropic`). |
| `--keys-file FILE` | `keys_file` | `""` | Backend-id→key sidecar; defaults to `router.keys.json` next to `--config` (git-ignored). |
| `--set-key ID` | — | — | Hidden prompt, DPAPI-stores that box's key, exits. |
| `--probe` | — | — | Verdict table per box, exits. |
| `--version` | — | — | Prints the version, exits. |
| `--sticky-ttl SEC` | `sticky_ttl` | `21600` | How long a lane's pin survives before re-placement. |
| `--connect-timeout SEC` | `connect_timeout` | `5.0` | Time to get a TCP connection to a box. |
| `--read-timeout SEC` | `read_timeout` | `3600.0` (`0` = never) | Cap on waiting for response bytes; `0` never times out a request parked in a queue. |
| `--max-connect-failures N` | `max_connect_failures` | `3` | Connect failures that park a box (busy never counts). |
| `--down-backoff SEC` | `down_backoff` | `20.0` | How long a parked box stays parked. |
| `--status-interval SEC` | `status_interval` | `1.0` | Queue-depth poll rate per box. |
| `--max-body-mb N` | `max_body_mb` | `512` | Request body cap. |
| `--rewrite-model FROM=TO` | `rewrite_model` | `{}` | The only body rewrite allowed; repeatable. |
| `--no-expose-affinity` | `expose_affinity` (inverted) | `true` | Keep lane pins out of the status views. |
| `--log-level LVL` | `log_level` | `INFO` | |

Config-only keys (no flag): `sticky_max` (`20000`, pin-table cap),
`status_timeout` (`3.0` s), `status_paths` (`["/v1/status", "/metrics"]`),
`backend_api_key` (`""` per backend -- prefer `--set-key` over a key in the
file), `control_token` (`""`, optional gate for `x-strata-pin` requests),
`tls_insecure` (`False`, https backends only: skip cert verification).
Tiering keys (`priority`, `max_inflight`, `require_idle`) live per backend --
see *Tiered placement* below.

## Wire the clients

```powershell
# Claude Code (Anthropic Messages)
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8088"
$env:ANTHROPIC_API_KEY  = "strata-local"
```

The key value you set here is yours to choose: when the router holds a key
for a box it ALWAYS replaces whatever the caller sends (shim and CLI
credentials authenticate to the shim, not to the box), and a caller's auth
is forwarded verbatim only to boxes the router holds no key for.

```toml
# Codex ~/.codex/config.toml  -- only base_url moves
[model_providers.custom]
name = "custom"
base_url = "http://127.0.0.1:8088/v1"   # -> the router
wire_api = "responses"
experimental_bearer_token = "..."
```

### If there is already a shim in front of the model

A `ccs-`/`cc-switch`-style model switcher already sits on a local port (e.g.
`http://127.0.0.1:15721/v1`) and rewrites `model` names. Then do not replace it
-- put this router *behind* it: point the shim's upstream for that one model at
the router, and keep Codex pointed at the shim. One translation/renaming layer,
one load-balancing layer, still no protocol translation in either.

Nail down the `/v1` suffix once: this router serves the API at its root, so an
Anthropic-style shim that appends `/v1/messages` itself takes
`http://127.0.0.1:8088` -- NO `/v1`. A shim whose field wants a full API root
would need `.../v1` only if it appends bare `/messages`; get it wrong and the
box answers 404 at `/v1/v1/messages` (the router forwards paths verbatim and
invents none). Not sure which convention your shim uses? Send one turn and
read the router log: a `POST /v1/v1/messages` line means strip `/v1` from what
you typed into the shim.

If the shim queues on your behalf, verify it does not hold a tighter timeout than
Codex itself, or you have stacked a second ceiling on top of this one.

### Capacity, so the queue depth is not a surprise

`[agents] max_concurrent_threads_per_session = 10` against two boxes with
`parallel` off means 2 conversations run and 8 wait. That is the arithmetic, not
a misconfiguration: the second box doubles concurrency, it does not absorb ten.
If you want fewer waits, lower `max_concurrent_threads_per_session`; if you want
to absorb more, the lever is a third box (or `parallel` on a box that can afford
the decode cost).

## Read this before you debug "it stopped after N minutes"

Rule 2 means the router never refuses; the waiting happens inside the backend.
On Strata the wait is *not* silent: a stream queued for the single turn emits a
`: keep-alive` SSE comment about every 10 seconds (its 200 and headers are
already out), so a **stream-idle timeout does not fire while queueing** -- what
kills a long wait is a **total wall-clock ceiling** on the client. The router
relays those bytes the moment Strata writes them (`read1` on the backend
socket, never a fill-read, which would buffer the whole stream to its end). A
non-streaming request, by contrast, truly sends nothing while queued, so for
those the read timeout is the ceiling. A **hang-up is heard, not waited for**:
the router watches its caller's socket the way Strata watches its own clients
(MSG_PEEK every 0.5 s -- a dead localhost socket keeps accepting writes for
ages, so write failures alone would never notice), and on EOF/RST it drops the
backend connection at once. The box's own watcher then sets its cancel flag
within its 0.5 s poll: a request already in the slot stops within ~1 s; one
parked in the FIFO notices at its next keep-alive beat (<= ~10 s). Either way
the seat goes free on its own -- this is what stops one killed agent from
making the whole FIFO burn minutes of compute for a corpse.

* Raise the client-side timeout. Whatever you tolerate today through your
  existing shim is the tolerance this router inherits -- keep `--read-timeout`
  (default 3600s, `0` disables) at or above it, and raise the client's stream /
  request timeout if you want longer waits to be survivable. `httpx`-based
  clients: a large `read` timeout or `timeout=None`.
* If a request parked in a backend queue does exceed `--read-timeout`, the
  router answers `502 backend_timeout` saying the request *was handed over and
  may still complete there -- retrying can duplicate the turn*, and the box
  **stays in the pool** (rule 4: a slow box is not a dead box). Do not "fix"
  those by lowering the timeout; raise it.
* Do **not** enable the admission cap with `--queue-timeout` on Strata unless you
  also turn on client retries for 429. Without the cap Strata just queues, which
  is the behaviour you want to keep.
* A proxy or TLS terminator between Codex and this router must also have its read
  timeout raised, or you have reintroduced the bug you were trying to remove.
  Through a cc-switch shim specifically: with failover off its stream timeouts
  are zeroed (nothing cuts a parked stream), and its streaming path tolerates
  24 h -- but a **non-streaming** request parked in a queue inherits the shim's
  own ~10-minute ceiling and would get the shim's timeout while the box keeps
  working the turn (duplicate bait). Always stream.
* Once the first byte has been sent the router never retries: re-sending a
  half-delivered agent turn would duplicate tool calls. It surfaces the break
  and keeps the box in the pool.

## Ops

```powershell
Invoke-RestMethod http://127.0.0.1:8088/healthz        # up / down per box
Invoke-RestMethod http://127.0.0.1:8088/__router/stats # per-box state, in-flight,
                                                       # reported serving (Strata
                                                       # reports ONE load number,
                                                       # there is no separate
                                                       # queue count), ttfb,
                                                       # sticky_hits / new_placements /
                                                       # overflow_placements /
                                                       # overflow_rollbacks /
                                                       # overflow_fizzles /
                                                       # overflow_pending /
                                                       # migrations / last_resort
Invoke-RestMethod -Method Post http://127.0.0.1:8088/__router/sticky/clear  # forget all pins (POST-only)
```

**The steering endpoints are open to localhost unless you gate them.**
`x-strata-pin` and `sticky/clear` share the router's blanket localhost trust:
any local process can pin lanes (past the courtesy gate) or fire a mass
re-home, and a page served from ANY loopback origin can fire the one-way
clear (a browser can send it; it cannot read the answer -- it does not need
to). Set a control token to close that: `python router.py --set-key control
--config router.json` (hidden prompt, stored in the 0600 keys file; the
config field `control_token` works too -- ASCII only, a non-ASCII token is
refused at boot because no header could ever match it), then send the header
`x-strata-control` with the pin or the clear -- the boot log says which state
you are in (`control surface: GATED ...` vs `open to local callers`). The
router NEVER forwards that header to a box: it gates the router, and a pinned
turn travels to the (possibly borrowed) box -- forwarding the token would
hand it to the box's owner.
`/healthz` and `/__router/stats` stay open by design: they are ops readouts,
read-only, and the smoke/liveness tooling depends on them -- but they do
reveal box endpoints and metrics to every local process, so treat
"who can reach this port" as part of the deployment decision.

Per-request response headers say what happened: `x-strata-backend`,
`x-strata-affinity`, `x-strata-placement` (`sticky` / `placed` / `overflow` /
`migrated` / `pinned` / `last_resort`). `--no-expose-affinity` hides them.

The router injects your backend keys for callers that send none, so it knows
its callers: it answers only requests whose `Host` is a loopback name (or the
configured `listen` address) and rejects browser `Origin`/`Referer` from
elsewhere -- the standard DNS-rebinding move (a web page re-resolving its own
domain onto `127.0.0.1`) gets 403. Booting with a non-loopback `listen` logs a
loud warning; if you must do it, firewall the port first.

How a conversation is recognised, per wire API:

| Client | Affinity source |
|--------|-----------------|
| Claude Code (`/v1/messages`) | `metadata.user_id` as the session SCOPE + hash of system+tools+first turn as the LANE |
| Codex (`/v1/responses`) | `prompt_cache_key` / `user` / `session_id` scope + first-input-item lane, else the lane hash alone |
| Anything else | the lane hash (stable-prefix hash) |

Two levels, deliberately. `metadata.user_id` identifies a Claude Code
*session* -- and its subagents all share it. Keyed on the session alone, every
parallel branch would stick to one box and queue serially behind its own
siblings while the second box idled (this was observed in production). The
lane -- the hash of system+tools+first turn -- separates the branches (their
first turns differ) without separating a branch from its own future turns
(its first turn never changes; system+tools participate too, and a tool set
that changes mid-run deliberately reads as a new prompt prefix -- the warm
cache was keyed on the old one regardless). So each branch is placed like its
own conversation and keeps its own warm cache. Spreading has two paths: a
branch's FIRST turn landing on a busy local box is a fresh `placed` placement
onto the open peer; a later turn finding its home full `overflow`s. Same
doctrine, different counters.

Only the *first* turn is hashed. That is deliberate: the transcript tail grows
every turn, and a key that changed each turn would re-place the conversation onto
a cold cache on every request.

Manual override -- force a conversation onto one box (it also pins that
conversation there). Reachable only where *you* set the header -- curl, a
CLI, a scripted probe: Claude Code cannot attach custom headers per
subagent, so subagent placement stays automatic (the lanes decide):

```
x-strata-pin: box-b
```

The pin overrides affinity, tier and `max_inflight` -- but **not** `require_idle`.
Borrowing a peer's box still requires that box to be verifiably idle; the peer's
courtesy is not the operator's to waive. Pinning also cancels that lane's
in-flight provisional re-homes: you took manual control, a late first byte
from an older overflow will not move the lane back. (Pinning a box that is in
its down-cooldown may consume its single half-open recovery trial -- pin it
while it is UP, or let the poller recover it first.)

## Tiered placement: local first, the peer only when it is verifiably idle

The default places every new conversation on the shallowest queue -- correct for
two boxes you own. When one box is *borrowed* (a peer's machine, used only when
it is free), give each backend three extra keys:

| Key | Meaning |
|-----|---------|
| `priority` | Tier number, lower preferred. Your box `0`, the borrowed box `1`. |
| `max_inflight` | Hard cap on conversations this router places there (`1` with `parallel` off). Enforced atomically: gate check and reservation happen in one step, so a burst of parallel subagents cannot both take the last slot. |
| `require_idle` | Place new work only while the box reports **external** load of zero: its own total load -- Strata reports it as `activity.in_flight` (requests running **plus** waiting) -- minus this router's in-flight, confirmed on two consecutive status polls. Fields that name a *capacity* (Strata's `concurrency.serving` slot count, its `vram.reserve_mib` / `expert_slots` figures) are never read as load. A box whose status endpoint has **never** answered (wrong borrower key, wrong path, unreadable schema) is unknown, and unknown is not idle -- the gate fails **closed**. |

```json
"backends": [
  { "id": "local",  "url": "http://127.0.0.1:8081",           "priority": 0, "max_inflight": 1, "require_idle": true },
  { "id": "remote", "url": "http://peer-box.tsnet.invalid:8080", "priority": 1, "max_inflight": 1, "require_idle": true }
]
```

What that gets you:

* An idle local box always takes the conversation. Overflow goes to the peer
  **only** when local cannot take the conversation -- at its cap, carrying
  load that is not ours, or reporting stale (its own `require_idle` gate is
  closed) -- **and** the peer is verifiably idle.
* "Verifiably idle" means the peer's `/v1/status` reports load that is not ours:
  the box counts every request on it (`activity.in_flight` -- running plus the
  ones parked in its FIFO), the router subtracts what it sent (and what it
  aborted seconds ago -- an aborted request of ours stays in the box's own
  count until that box's next keep-alive beat; the courtesy verdict subtracts
  that ghost, so our corpses never close a gate -- and since v1.2.11 the same
  ghost is recorded when the ROUTER abandons a sent request on read timeout,
  because that corpse is ours exactly the same way), and any remainder belongs to
  the owner (or another borrower). Two consecutive
  confirmations, so one stale sample right after our own request finished cannot
  bounce us onto the cold box. Truth is still seconds-behind in both
  directions: a request is registered on the box only once its prompt is being
  prepared, and the friend resuming takes a poll or two to appear. The single
  status poller walks the boxes one at a time, so a box that accepts TCP but
  stalls its status answer slows the other box's refresh too -- its courtesy
  gate can flap closed for a cycle or two (fail-closed: traffic queues at
  home, nothing is refused). Courtesy is
  best-effort politeness, not a lock -- never build a guarantee on it. The
  ghost subtraction is directional too, and honestly bounded only per ghost:
  ONE aborted turn subtracts genuine foreign load for at most the grace
  window (~12 s), but a SUSTAINED ESC storm (aborts arriving faster than the
  window drains -- the pre-release stress round measured ~0.1-0.5/s as enough) keeps courtesy
  blind for as long as it keeps arriving. That storm can only ever hide the
  courtesy gate -- it cannot forge an idle verdict or exile a lane; briefly
  borrowing a busy friend during someone's kill-storm is the accepted cost of
  never exiling a lane over our own corpse (capping the subtraction fixes
  nothing: it would punish real aborts to guard a localhost-trusted one).
  The debt is booked only where it is owed: when the box ANSWERED and it was
  the router's own write to the caller that failed (a mid-relay RST lands
  there), the request is done on the box -- that books as an abort, never as
  a timeout-shaped ghost-debt (v1.2.13, pre-release stress round).
  The window has arithmetic to respect too: the subtraction only helps while
  the box still counts our corpse, so the real margin is
  `ghost_grace (~12 s) minus the box's keep-alive beat (~10 s)` -- change the
  grace constant or borrow a box whose beat is slower (≥~16 s) and revisit
  both sides; the coupling lives across two files on purpose.
* A borrowed box whose status went silent (mid-update, network blip) ages out of
  the idle verdict after `max(3 x status_interval, 5s)` and is **not borrowed**
  until reporting returns -- you may not stack on a machine you cannot see.
  Silence is courtesy-blindness, not a health failure: the box stays in the pool
  (rule 4), and it becomes borrowable again the second its reports come back.
* When neither box accepts, the conversation queues in the primary's FIFO. The
  gate redirects, it never rejects; rule 2 still holds.
* Sticky affinity is unchanged: a conversation that overflowed stays where it
  warmed its cache. And a lane refused by its home (home at capacity or gate
  closed -- still healthy) does not queue behind its own siblings: it overflows
  to the next box that accepts (`x-strata-placement: overflow`), re-homes there,
  and keeps that box for its later turns. Only when *no* box accepts does it
  queue at home.
* The re-home is provisional until proven, **per request**: the lane re-homes
  when the overflow target **answers** (any HTTP status -- busy is not dead).
  The provisional entry is keyed to the *request*, not the lane, because a
  stalled stream makes Claude Code's SDK **retry the same lane** while the
  original overflow is still in flight to a third box -- both are legitimate,
  and each settles on its own. Three ways an overflow request ends: it answers
  (re-home becomes real, ticks `overflow_placements`); it dies before a byte is
  sent (TCP-dead but its status was fresh -- roll back, **queue at home** or
  migrate if the home itself died, ticks `overflow_rollbacks`, never a 502 for
  a queueable turn); or it ends any other way without ever answering (a read
  timeout, the caller hung up) -- its provisional entry **fizzles**, ticks
  `overflow_fizzles`, and cannot landmine the lane's next turn. `overflow_pending`
  in stats is the count still waiting on a first byte; a number that only grows
  means something is wedged. A `count_tokens` overflow never re-homes -- token
  counting warms no cache, so it must not exile a conversation on a preview
  call; that entry fizzles.
* **Overflow is permanent by design** -- a re-homed lane does not drift back the
  moment home frees, because any return trigger pays a cold prompt re-read and
  risks ping-pong under alternating bursts. The cost is honest and worth
  watching: if your interactive lane keeps overflowing onto the borrowed box
  while your own GPU idles, its cache geography has inverted for the session and
  nothing auto-corrects it (Claude Code cannot set a per-turn pin, so
  `__router/sticky/clear` -- which cold-starts every lane -- is the only lever).
  The signal is `affinity_by_backend` skewed to the *borrowed* box while the
  primary's `inflight` sits near zero between turns. A narrow hysteretic
  homecoming (return home only when it has been empty at pick time, so
  re-overflow needs real load) is a possible future refinement, not shipped.

### Mirror deployment (two friends, two boxes, one shared file)

The router carries no knowledge of which machine is "yours". Both sides run
the same `router.py` and share ONE `router.json` template, filled in as
mirror images -- each side declares its OWN box under `local` and the
peer's under `remote`, with `local` at priority 0 on both boxes (the
priorities never swap, the boxes do) and ports per the one-port doctrine
above:

* your side: `local = your Strata (priority 0)`, `remote = peer's Strata (priority 1)`
* their side: `local = their Strata (priority 0)`, `remote = your Strata (priority 1)`
  -- see `router.remote.example.json` on how that looks.

Each side's overflow hits the *other's Strata directly* (not the other's router),
and each router sees the borrowed traffic as external load on its own box, so
both sides automatically get out of each other's way through the same status
polls. Bind each Strata with `--host 0.0.0.0` (it binds ONE address, and its
own router reaches it on loopback -- a tailnet-only bind would break that)
and scope the port by firewall instead: `-LocalPort <your port>
-RemoteAddress <peer-tailnet-IP> -InterfaceAlias Tailscale`.

**Keys: one per box, borrower keys across the wire.** Each backend spec may
carry its own `backend_api_key`; inference, status polling and `--probe` all
authenticate per box. The global `backend_api_key` (or
`STRATA_BACKEND_API_KEY`) stays as the fallback for boxes whose spec sets none.
A mirror deployment therefore holds: your own box's key under `local`, and the
*borrower key* your peer issued you under `remote` -- and vice versa on their
side. Revoking a peer is then a single-sided move: rotate your box's key, the
peer's stale borrower key 401s (relayed faithfully, box stays in the pool),
your own traffic keeps flowing. Keys travel face-to-face or over an encrypted
channel, never through chat logs, git, or cloud drives; `chmod`/`icacls` the
config to your user alone -- or type the keys at the `--set-key` port below and
leave the config keyless (since v1.2.11 that rewrite is atomic: temp file,
locked ACL, one rename -- an interrupted `--set-key` can no longer leave half
a keys file that refuses every later boot, and entries it does not touch are
re-stored byte-faithful).

```json
"backends": [
  { "id": "local",  "url": "http://127.0.0.1:8081",           "priority": 0, "max_inflight": 1, "require_idle": true, "backend_api_key": "OWN-BOX-KEY" },
  { "id": "remote", "url": "http://peer-box.tsnet.invalid:8080", "priority": 1, "max_inflight": 1, "require_idle": true, "backend_api_key": "PEER-BORROWER-KEY" }
]
```

**The standard key input port is a hidden prompt.** The key is typed twice,
never echoed, never placed in a shell history or a config file, and only its
length is ever printed (the same port stores the `control` gate token with
`--set-key control` -- see *Ops*):

```powershell
python router.py --set-key local  --config router.json
python router.py --set-key remote --config router.json   # the borrower key
```

It lands in `router.keys.json` next to the config (created `0600`; on Windows
the file's NTFS inheritance is stripped so only your account can read it --
verify with `icacls router.keys.json`; and since v1.2.14 its CONTENT is DPAPI
ciphertext: one blob that opens only for your Windows account on this machine,
so a stray grep, an agent scan or a copied file sees base64 noise, never a
key. An existing plaintext file migrates itself on the next boot -- same
entries, encrypted. A blob moved to another account or machine deliberately
refuses to open: keys were never meant to travel), and `router.json` itself
stays safe to show, edit or paste into an issue. Delete the file to wipe the
keys. Outside Windows there is no DPAPI: the keys file stays plaintext JSON
there (still created `0600`) -- treat it as the secret it is, same red line:
never git, never chat, never a cloud drive.
Alternative ports: name an environment variable per backend
(`"backend_api_key_env": "STRATA_KEY_REMOTE"` -- export it in a private window;
`setx` echoes the key into the command line and stores it in the registry, so
prefer `[Environment]::SetEnvironmentVariable`), or keep the inline
`backend_api_key` field, in which case `router.json` is itself the secret and
must be `icacls`-stripped too. Resolution order: inline field > keys file >
env var > keys file `global` > global field > `STRATA_BACKEND_API_KEY`. A
box's configured key is injected EVEN WHEN the caller sent its own auth --
shim credentials belong to the shim; the boxes get the box's key. Keys
never appear in argv, in any log line, or in `/__router/stats` (which reports
only `has_api_key`).

**Facts a monitor must not guess (v1.2.14).** The top-level block carries
`status_interval` (the interval actually in use -- the courtesy blind-window
base, so a dashboard never hardcodes a wrong one), and `started_at` /
`uptime_s` (a restart is a fact now, not an inference from counter rollback).
Per box, presence-gated extras ride along WHEN the box publishes them (never
fabricated zeros): `reported.decode_tok_s` -- the box's own measured generation
speed (Strata's `predicted_per_second` for the last finished request, the
`/metrics` instant rate where that is the shape), `reported.box_uptime_s`,
`reported.gpu_util_pct` -- plus `stats.bytes_out` (cumulative forwarded
response bytes: the raw material for a fleet tok/s estimate at bytes/4, the
same "chars/4" yardstick Strata's own UI labels *estimated*) and the
`recent_ttfb_avg_s` / `_p95_s` / `_n` window over the last 30 finished
requests (true per-request sampling -- none of the bias a monitor's own
polling of `last_ttfb` carries). All of it is read-side only: the placement
ledger and the accounting identity are untouched.

**Startup refuses a half-configured file.** A `REPLACE-WITH-` placeholder (box
keys, global key, or `control_token`), a key
that cannot be encoded as an HTTP header, a mistyped or mistyped-type tier knob
(`"require_idle": "false"` is a string, not `false`), a garbage numeric, a
non-numeric per-backend `status_interval`, a `backend_api_key_env` naming an
unset variable, a broken or placeholder-holding keys file, a configured
`keys_file` path that does not exist, an IPv6 `listen`, a malformed
`status_paths`: all of them abort the boot with a named error instead of
silently serving with a weakened gate. A gate-relevant box (`require_idle`
or `priority > 0`) whose key resolves only from a SHARED fallback logs a
warning -- for a borrowed box that is usually the wrong key -- and the boot
log names where every key came from. Unknown config keys are logged as
ignored at every start.

**What to watch in `/__router/stats`.** Per box, `reported.serving` is the
box's own load (Strata's `activity.in_flight`: running + waiting) and
`inflight` is what this router sent. Both high while traffic flows = the queue
is doing its job. Since lanes split a session's parallel branches across boxes,
load concentrated on one box while the other idles means the branches are not
actually concurrent (or arrive after each other's lanes went idle). What to
actually watch: the `affinity_by_backend` spread and the per-request
`x-strata-backend` header -- a subagent lane reaching the peer **on its first
turn is a fresh `placed` placement** (`new_placements` ticks), because an
idle-or-busy-aware tier is what spreads subagents; `overflow_placements`
counts the narrower case -- a lane already homed somewhere redirected off a
full home on a later turn (rolled-back attempts tick `overflow_rollbacks`
instead). `requests` / `new_placements` count every forwarded request,
including bodyless GETs like a UI's "fetch models" -- read spread from
`affinity_by_backend`, not from absolute counter sizes. Do not read queue depth
from `avg_ttfb_s`: Strata queues with keep-alives, so a parked stream's first
byte lands within ~10 s no matter how deep the queue -- ttfb measures service,
not waiting. In the router block, `gate_bypass_borrow` counts the times work
was admitted onto a `require_idle` box whose **gate was actually closed**
(foreign load, silence, never-reported -- not merely full on our own capacity)
because nothing else accepted (the gate redirects, it never rejects). Do not
read it as "work landed on a dubious peer": when BOTH boxes are closed -- a
new turn whose home gate a visitor closed, with the peer not verifiably idle
either -- the work queues in its OWN box's FIFO and still ticks, so during a
mutual-borrow hour this counter climbs once per such turn: the counter
working, not the fault. The alarm shape is a tick while the PEER sits
verifiably idle -- its gate was open and would have taken the work; that
means the two boxes really are missing each other. Our own traffic waiting
behind our own traffic is NOT a
bypass and never ticks it -- a third lane queueing at a capped-but-open home
is a capacity fact, not a courtesy alarm, and a metric that cried wolf on
every such queue would hide the real borrow alarms. `overflow_fizzles` and the
live `overflow_pending` gauge
together say the provisional re-home window is draining; the placement counters
form a closed identity (`requests` equals the sum of the terminal counters plus
the operator-cancelled overflows -- home-migration drops count AS fizzles since
v1.2.9, and since v1.2.13 the last exception is observable too: pin takeovers
and sticky/clear tick `operator_cancelled`, so the identity is re-derivable
from `/stats` alone even after an operator touched a lane; the one other way
the ledger can lag is LRU-evicting pending overflow tokens past 4096 concurrent
parked re-homes, a flood shape this deployment cannot reach without first
exhausting its threads -- and since v1.2.11 even that is COUNTED
(`overflow_evictions`, and a non-zero value there is worth an eyeball), so a counter that stops
explaining requests is itself the alarm. Since v1.2.16 keyless GET/HEAD proxies
(monitor probes at `/v1/models` and friends) book their own terminal
`passthrough_gets` -- `new_placements` counts real new conversations only, and
the identity still closes over every request.

## Limits

* **Localhost is the perimeter, and localhost is trusted -- by design.** Every
  local process can read `/__router/stats` (box endpoints included) and can
  send inference, which the router forwards WITH THE BOX KEY injected even
  when the caller sends no auth: that key injection is the design, not a
  hole. The two steering endpoints (`x-strata-pin`, `sticky/clear`) are the
  sharpest edge of that trust -- gate them with `--set-key control` (see
  *Ops*). A browser page from a foreign origin cannot reach any of it (Host +
  Origin guards); a page from a LOOPBACK origin can fire one-way requests
  (it can clear affinity; it cannot read responses -- and since v1.2.12 the
  relay also strips `access-control-*` from every box response, so not even a
  LYING box can open a browser-readable window through this passthrough;
  OPTIONS answers a named 405 on EVERY path, so CORS preflight dies before
  any body, and since v1.2.13 header names must be RFC 7230 tokens on BOTH
  legs of the relay -- a junk name never enters the box either). Slow clients
  hold handler threads with no cap (stdlib threading server): hostile locals
  can exhaust threads -- and a caller that stalls WITHOUT closing (full TCP
  window, never EOF) additionally pins its relay thread, its home box's
  max_inflight slot and the box's FIFO seat until it finally hangs up:
  everyone else's traffic drifts to the borrowed box meanwhile. That is the
  one real exception to "the seat frees itself" -- it stays inside the
  localhost-trust model; the deployment answer is the same as for every other
  local-port tool, don't run hostile locals.
* A **lying backend can truncate a relayed stream silently**: `content-length`
  is forwarded as-is (byte passthrough), so a box that lies about its body
  length hands the caller a well-formed short turn. The two boxes are trusted
  principals here -- yours and your friend's -- same class as trusting them
  with your prompts.
* One Python process, two threads per in-flight stream (relay + the 0.5 s
  hang-up watcher): fine for tens of concurrent agents, not a public endpoint.
  Keep it on localhost or a LAN.
* No TLS to the backends' clients side, no auth of its own. If Codex runs on
  another machine, restrict `--listen` to a private interface and firewall it
  -- and note that a NON-loopback bind tightens the guards: only the bound
  address passes as Host (the loopback names stop being a pass, because
  off-loopback they prove nothing).
* Affinity lives in memory (bounded LRU, `sticky_ttl` counts idle time since
  the conversation's last turn, so an active session never drifts). Losing it
  is cheap: one cold prompt re-read, no lost work.
* `count_tokens` is synthesized when a box returns 404/405/501, because Claude
  Code treats that call as mandatory. It is an estimate, so the number is only
  for context-budget display. Reach honesty: through a cc-switch shim the call
  never reaches the router at all (the shim has no `count_tokens` route -- it
  404s at the shim), and real Strata implements it natively, so this is a
  direct-wire (`ANTHROPIC_BASE_URL` at the router) rescue for non-Strata
  backends.
* Two branches of one session whose FIRST message is textually identical share
  one lane (same session scope + same stable prefix = same key). They are
  served correctly, just from one box -- and two interleaved conversations
  sharing one conversation cache re-read more than one conversation would.
  One consequence to know (measured in the pre-release stress round): the overflow re-home is keyed to the
  lane, so when colliding conversations share a lane, ONE branch's overflow
  re-home moves the SHARED lane -- both conversations migrate together to the
  borrowed box, permanently (and can flip back if the homes alternate).
  Correctness survives (the ledger stays closed, the caches are real), only
  the separation is lost. Rare (same task wording fired twice in parallel);
  name your parallel tasks differently and they separate on their own.

## Tests

```powershell
python smoke_test.py     # 210 checks; needs loopback
```

The fakes speak Strata's real status schema (`activity.in_flight` plus the
capacity decoys -- `concurrency.serving`, `vram` figures -- that the extractor
must ignore) and behave like Strata with `parallel` off: one slot, real FIFO,
a silent wait for non-streaming requests and Strata's `: keep-alive` comments
for parked STREAMS. They cover SSE/thinking/tool_use integrity, pin-and-stick
across a growing transcript, queue depth seen from both in-flight and the
box's own report, queued requests waiting ~1.6s and succeeding, 429 relayed
with `Retry-After` while the box stays healthy, `count_tokens` fallback,
Responses API passthrough plus prefix-based affinity without any session
header, connection failure -> migrate -> survivor carries on -> automatic
rejoin. Relay liveness is checked as DELIVERY TIMING (the keep-alive must
cross while the fake's stream is still open -- a fill-read relay would buffer
it to EOF), together with the key-replacement rule, the status-stall rule
(busy is not dead), the hang-up watchdog (a killed caller releases the box
in ~1 s and is counted as an abort, while pipelined bytes mid-stream must
NOT trigger it), non-ASCII refusal at the edge, and Windows exclusive
port binding. Smart distribution is guarded at both levels: two Claude Code
branches sharing one `metadata.user_id` must get different lane keys (and a
branch's own follow-ups must stay sticky), and a lane whose home is FULL must
overflow to the open peer, re-home there, and be counted in
`overflow_placements`. The review-hardening rounds add their own guards: an
overflow target that dies before a byte was sent must cost the turn a queue
at home, never a 502; queueing at a closed-gate borrowed home must tick
`gate_bypass_borrow`, while pure-capacity queueing at an open gate must NOT;
and a key holding control bytes is refused at every input port (it would ride
http.client's error message into the 502 body, the log and stats). The
aborted-request ghost gets its own scene too: a box still counting a stream we
already released (its beat has not landed) must NOT close its courtesy gate
and exile an innocent lane -- the fake's beat lag makes the ghost real, and
the guard runs inside the window. The retry-door scene (a third fake box,
tier-ordered) stages the overlaps the two-box rig cannot: two overflows of
ONE lane in flight together (the retry an SDK fires after a stalled park),
the retry's box dying mid-park -- the lane must re-home to the box that
ANSWERED, the dead retry must fizzle its own provisional entry, and a later
turn must find its warm box; an operator pin lands through a pending overflow
commit; a `count_tokens` preview that overflowed must NOT re-home;
capacity-only queueing must not cry borrow; and the placement counters must
form a closed identity. Two direct Pool contracts cover the deaths HTTP
timing cannot stage: a sibling overflow's rollback must release only its own
reservation, and a rollback whose home died mid-request must migrate onward
with the alt released exactly once -- never the 502-over-live-boxes, never
the double-release that would breach the cap. `--probe` is tested against a
parked stream, because the verdict must come from the headers: a fill-read
probe declares a busy, healthy box `unreachable` (and then the operator
reboots a box that was fine). A pristine placeholder config must log the named
placeholder error without also crying "shared fallback key" about a key that
does not exist. The adversarial round adds its own: hostile chunk sizes
(`-2`, `-1`, `0x21`, `1_0` -- the shapes `int(x,16)` accepts, one of which was
an unbounded read past the body cap) must all die at a named 400;
`OPTIONS` must not execute the destructive clear; the sanctioned model
rewrite must not kill the relay on an unhashable `model` nor bill a healthy
box for a lone-surrogate body; a set `control_token` must gate pin and clear
while leaving plain traffic untouched; and a router bound OFF loopback must
refuse `Host: localhost` (off-loopback the loopback names prove nothing).
And one hygiene rule guards the reviewers' red line from the
inside: a router booted without `--config` anchors its keys-file on the
**current directory**, so the whole suite runs from a private temp dir -- a
test run must never read the real `router.keys.json`.
The concurrency round (v1.2.11) adds: a fake box must report having seen NO
`x-strata-control` header ever, pinned turns included (the token gates the
router, never a box); a non-ASCII control header gets a named 403, not a dead
connection; a stall turn that dies at `backend_timeout` must leave its lane
HOME -- the box still counting our abandoned request is a ghost we recorded,
not the owner's load; the DOWN/HEALTHY transitions must log OUTSIDE the
backend lock (probed by asking the lock from inside a patched log call);
4096-cap evictions must tick `overflow_evictions`; a non-string keys-file
value must be refused boot; and `--set-key` must rewrite atomically with
untouched siblings byte-faithful.
The adversarial stress round (v1.2.12) adds the protocol edges that review walked:
an absolute-form request target dies at a named 400 (never relayed into the
box's request line); the rebinding 403 must REACH a 2 MB sender (the refusal
survives a timed graceful drain instead of being eaten by a Windows RST);
the chunked reader refuses an empty size line, a missing CRLF terminator and
a 65-line trailer flood -- each by name -- and a chunked `HEAD` closes the
connection rather than letting the leftovers become a second request;
`Host: [::1]` parses; an HTTP/1.0 caller gets close-delimited framing (never
chunk bytes it cannot parse); a LYING box's raw response cannot put
`access-control-*` on the wire (stripped by name at the relay) while status
and body relay intact; inline typed junk (`true` as a key or token, a dict
as a rewrite value) refuses boot like the keys file already did. And the
distribution edges: `metadata.user_id` as an int still SCOPES (three
sessions with an identical first turn get three lanes, and 12345 is not
"12345"); anon lanes hash the FULL body (two malformed bodies past 64 KB
with an identical prefix part ways); and the `last_resort` counter is honest
in both directions -- a reservation race at a LIVE box books as
placed+borrow, while a genuine all-down cooldown forwards (never rejects)
and books the named `last_resort`.
The round's second wave (v1.2.13) closed what the first wave
left open, and made the error taxonomy honest about WHO vanished: a reason
phrase carrying CR/LF never reaches the caller's status line (the standard
phrase relays instead -- a lying box's forged header riding the STATUS LINE,
above every header-side filter, dies there); a box that answered with
unparseable framing gets the named `backend_protocol_error` instead of the
"may still complete" timeout story; a caller that RSTs mid-relay of an
ALREADY-ANSWERED request books as an abort, never as a backend stall and
never as a baseless ghost-debt; `OPTIONS` answers a named 405 on EVERY path
(the README always said so -- it now does, body eaten first); the rebinding
guard understands IPv6 literals in `Origin:` (admits `[::1]`, still 403s
`[::2]`); a door-refusal against a chunked body still reaches its sender;
header NAMES are token-checked in both directions of the relay; a
control_token carrying control bytes refuses boot and an embedded boot that
skipped `apply_keys` honors its inline token instead of silently opening the
gate; `operator_cancelled` makes the identity's last term countable; and the
last-resort forward takes the candidate whose half-open trial is actually
free (a walk in load order, not a random tie-break coin flip).
