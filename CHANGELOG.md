# Changelog

All versions are public releases of the Strata router. `DV-RNN` names an
internal review ROUND and `DV-fixNN` names the commit that lands that
round's harvest -- neither is ever a release version, and rehearsals of a
release never get a tag.

## v1.0.1 -- 2026-11-26

Compatibility and correctness fixes. Anyone running the router on a
current CPython, or on a machine that gets rebooted, should upgrade from
v1.0.0; nothing else changes -- no API, no config, drop-in.

The fix rounds since v1.0.0 were the internal ledger DV-R23..DV-R26
(the program's post-release collateral rounds, one fix commit each);
two of them changed what a user can feel:

- Modern Python, two-word requests. CPython 3.13.10 onward (and
  3.14.1 onward -- the lone stable on the 3.14 line, v3.14.0, missed
  the stdlib change; the era boundaries sit in the source comments,
  the full per-tag census in the release commits) reworked the HTTP
  request parser so a bare two-word request line short-circuits the
  header block: the router received a plain dict where a headers
  object was expected, its duplicate-content-length gate died on it,
  and the caller read ZERO bytes. The router now re-reads the skipped
  block at its one parse choke -- bounded (one 0.4 s quiet window),
  fail-closed, gated by the era's own runtime marker and never by a
  version number -- so for every request the parse lets through, the
  router's law (named, framed, fail-closed) answers on every era.
  Verified on both eras (3.13.17 and 3.12.10)
  and, for the first time in this suite era, on CI's 3.8 floor leg.
- Rebooted machines. The smart-placement cooldown clocks were born at
  zero, and zero on a monotonic clock is the machine's power-on -- so
  a recently booted host made every lane look like it had just moved,
  and the mover and homing never fired. A never-moved sentinel now
  separates "never" from "just now" on every machine.

The rest was the harness and the release discipline: the packaging gate
learned to tell audit-ledger citations from tokens; the suite grew two
CI-era locks and seven parse-era locks (648 -> 657 checks); the test
harness now prints every red line's name -- past a 64-line cap that
announces itself -- instead of trimming the list, and era-stamps the
suite interpreters it spawns by reading the stdlib's own source; a
workflow_dispatch door lets CI be refired on demand when a platform
incident eats a push event -- built in response to the 2026-11-25
GitHub incident, which ate one outright, and proven live on 2026-11-26
after the incident resolved; and one published commit message was
corrected TWICE by errata -- a
label that hid which layer failed, then an attribution wrong by three
-- because a claim that outruns its evidence is a defect whoever wrote
it, including us.

## v1.0.0 -- 2026-11-25 (prepared 2026-11-21)

First public release. This version is the beginning of the public line;
what shipped before it lives only in the commit history and is not
numbered as if the world had seen it.

The engine: a small single-file OpenAI-compatible router
(`router/router.py`, stdlib only) that spreads callers across one or more
Strata/llama.cpp boxes with an honest placement ladder -- per-key
affinity that respects capacity, sticky sessions behind a control token,
overflow that never silently queues, and stats that are aggregates only
(no key ever leaves the process). Security posture was built by 22
adversarial review rounds (blind faces -> independent red team ->
council reproduction) and is enforced by a 648-check local suite
(`router/smoke_test.py`): fail-closed doors for Host/Origin rebinding and
userinfo shapes, framed-refusal delivery on both legs, a duplicate
content-length door (RFC 7230 3.3.3, request and response), inbound and
outbound header-name policing, chunked-framing law with a bounded drain
(the price of a closing door is documented per mechanism), and a
capacity door that refuses over-cap bodies by name before any box opens.

Pre-history (internal ledger, unnumbered): the line hardened through
rounds DV-R1..DV-R22 with fixes DV-fix1..DV-fix23 on top of the last
pre-open-source build; the earlier tags (v1.2.x and rmon-0.x) were
removed from this repository before v1.0.0 because they numbered work
no user ever received.
