---
name: Problem report
about: Something misbehaves — paste the de-identified diagnose output
title: "[router|rmon] "
---
**Package + version**
router: `python router.py --version` · rmon: version shown in the panel.

**What happened vs what the README promised**
(name the promise; this repo writes its promises precisely and holds itself to them)

**Environment**
OS, `python -V`, loopback or tailnet; Windows Terminal vs legacy cmd if relevant.

**Diagnostics**
monitor: run `python rmon.py diagnose` (de-identified by design) and paste it.
router: paste the last ~20 router log lines — check first that they contain no
secrets you care about; do not paste router.json.
