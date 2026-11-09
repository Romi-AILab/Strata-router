# Contributing

Small repo, strict self-gates. Run them BEFORE opening a PR — the CI here runs
exactly these commands.

1. `python run_all_tests.py` (Windows) must print ALL GREEN. It runs the
   packaging gate and its self-test, then both suites, each with a floor on the
   number of checks: suites may grow, they may not shrink. A deliberately
   retired check lowers the floor IN THE SAME COMMIT, with the reason.
2. File set is a whitelist. `audit_package.py` enforces SET EQUALITY between
   tracked files and `EXPECTED_TRACKED`. Adding or removing a file means
   editing that set in the same commit — that is intentional friction, not a
   bug to route around.
3. Secrets never enter, not even as examples. The gate scans every tracked file
   in worktree, index, AND HEAD for key/token/overlay-address/machine-identity
   shapes. If legitimate prose trips a pattern, fix the prose, not the pattern
   (and say why in the commit).
4. Promises live in the READMEs and in tests. Honest measurement wording
   (estimated vs measured), fail-closed display (None never becomes 0),
   zero POST / zero web UI in `monitor/`, `launch.py` never imports `router.py`:
   each of those is a test you can run, and new behavior around them wants a
   red-first test too.
5. Layout red line: `monitor/` must keep working as a plain copy of the folder.
   No test may lean on the monorepo sibling layout.
6. `monitor/` is currently Windows-only (`launch.py` imports msvcrt at module
   level); `router.py` runs wherever Python 3.8+ runs. Don't mix the two scopes
   in one PR unless you also update the README platform notes.
