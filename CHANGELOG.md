# Changelog

All versions are public releases of the Strata router. `DV-RNN` names an
internal review ROUND and `DV-fixNN` names the commit that lands that
round's harvest -- neither is ever a release version, and rehearsals of a
release never get a tag.

## v1.0.0 -- 2026-11-21

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
