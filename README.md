# Strata

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib--only-brightgreen)
![Router](https://img.shields.io/badge/router-cross--platform-green)
![Monitor](https://img.shields.io/badge/monitor-Windows--only-blue)

**Two sibling packages, one repo, still two independent programs.**
`router/` is a single-file, pure-stdlib passthrough proxy that steers
Anthropic/OpenAI streaming traffic across identical local inference boxes —
affinity first, least-queued second. `monitor/` is a terminal-only live panel
with a windowed watchdog. One command proves the whole repo:
`python run_all_tests.py`.

**[中文 ↓](#中文)**

## Contents

- [What you get](#what-you-get)
- [Requirements](#requirements)
- [Quick start — router](#quick-start--router)
- [Quick start — monitor](#quick-start--monitor)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Testing](#testing)
- [Limitations (honest list)](#limitations-honest-list)
- [Repository layout](#repository-layout)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)
- [中文](#中文)

## What you get

- **router** — one `router.py` (no dependencies) in front of two or more
  identical inference boxes: requests stick to the box that answered first
  (session affinity), new work lands on the least-queued box, a slow box is
  never marked dead, and every abort is booked under its true cause.
- **monitor** — `rmon.py`, a read-only terminal panel (byte-level zero POST)
  plus `launch.py`, a one-command launcher with a windowed watchdog
  (Windows-only; the standalone `rmon.py` runs anywhere).

## Requirements

Python **3.8+**, standard library only — no pip installs. `router/` runs on
any OS (its smoke suite is certified on Windows; run it on yours to see).
`monitor/`'s launcher and watchdog are **Windows-only** (console API); the
standalone `rmon.py` read-only panel also runs on POSIX, untested there.

## Quick start — router

```powershell
cd router
copy router.remote.example.json router.json      # `cp` on POSIX
python router.py --set-key local  --config router.json   # only on keyed boxes (hidden prompt)
python router.py --probe          --config router.json   # verdict table per box
python router.py                  --config router.json   # run
```

Point your client's base URL at `http://127.0.0.1:8088` (no `/v1` suffix for
Anthropic SDKs that append paths themselves). A `--config` that does not
exist — or cannot be a config (directory, empty, broken bytes, JSON
non-object) — refuses to boot with a named error, never a traceback. Flag
map: `--listen`/`--port` are the router's; `--host`/`--queue-timeout` seen in
the docs belong to the Strata box itself. Full guide:
[router/README.md](router/README.md).

## Quick start — monitor

Windows: double-click `!-start.bat` at the repo root (or `python monitor/launch.py go`).
POSIX: `python monitor/rmon.py` for the read-only panel.
Details: [monitor/README.md](monitor/README.md).

## Configuration

Every router knob — CLI flag, matching `router.json` key, default, meaning —
is tabulated in
[router/README.md — Configuration reference](router/README.md#configuration-reference).
Monitor's knobs live in `monitor/monitor.json` (template:
[monitor.json.example](monitor/monitor.json.example)); machine-local files
are git-ignored by design.

## How it works

The router never invents a request body: it relays bytes and rewrites
nothing except routing decisions. Each box is polled for its own queue depth
(one cheap GET per second); affinity pins a session to the box it first hit,
until the pin's TTL expires. Placement reads queue depth first, so an
already-busy box never receives a second turn's worth of surprise. A box
that fails connect N times is parked for a backoff window — a slow box keeps
streaming, only a dead box is removed. Every stream abort is classified by
its real cause (client hang-up vs backend stall), which is what makes the
stats panel honest.

## Testing

```powershell
python run_all_tests.py
```

Runs the packaging red-line gate (`audit_package.py`: whitelist set-equality,
secret grep across worktree/index/HEAD, ignore assertions, `--selftest`
canaries) then both suites, each held to a **minimum check count** — checks
that silently vanish are worse than red tests, so fewer checks fails the
run. Current floors: smoke **205**, rmon **203**. CI runs exactly these
commands on Windows legs (Python 3.8 and 3.13 prove the floor claim).

## Limitations (honest list)

- No TLS on the backends' client side, no auth of its own — a localhost/LAN
  tool; a non-loopback bind tightens the Host guards and is still yours to
  firewall.
- On POSIX the keys file is plaintext at rest (DPAPI, the encrypted keyring,
  is a Windows facility); keep POSIX deployments on loopback.
- Monitor's one-command launcher and watchdog are Windows-only; the test
  suite is certified on Windows.
- A single Python process, two threads per in-flight stream: fine for tens
  of concurrent agents, not a public endpoint.

## Repository layout

| Directory | What it is | Version source |
|---|---|---|
| [`router/`](router/README.md) | OpenAI/Anthropic reverse proxy + smart steering (`router.py`) | `VERSION` in `router.py` — tags `v*` |
| [`monitor/`](monitor/README.md) | Terminal panel + launcher (`rmon.py`, `launch.py`) | `VERSION` in `rmon.py` — tags `rmon-*` |

Merging the repos did not merge the programs — the panel never enters the
router's process, the zero-POST and terminal-only doctrines depend on that
separation, and the two packages release independently.

## Security

Key in/out flows only through `python router.py --set-key` (DPAPI-encrypted
on Windows). Machine-local files (`router.json`, `*.keys.json`,
`monitor.json`) are git-ignored, and the packaging gate re-proves that on
every run. What counts as a vulnerability here — and how to report one
privately — is in [SECURITY.md](SECURITY.md).

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md): six rules, the red-first
convention, and the honest-numbers doctrine (test floors move only with an
explicit reason). Fix batches ship as `-fixN` tags without version bumps.

## License

Apache License 2.0 — full text in [LICENSE](LICENSE).
Copyright 2026 Romi-AILab.

---

## 中文

同一個 repo 裡的**兩個平級包裝**,仍是**兩支獨立程序、各自版本**:repo 合併
≠ 程序合併——面板絕不進 router 進程(router 過載的時刻正是最需要「另一支
程序」讀數的時刻),rmon 的檔案級零 POST 與終端限定零網頁教義都靠「分開」
才成立。兩包唯一的縫是 `launch.py` 找到 router 目錄(`../router` 預設,
舊的獨立 `strata-router` 姊妹目錄仍 fallback,`STRATA_ROUTER_DIR` 可覆寫)。

**資安紅線(整個 repo 的結構性約束,`audit_package.py` 每次驗「擋著的事實」)**

- **機器-local 永不進 git**:`router/router.json`(真實箱位)、`*.keys.json`
  (DPAPI 金鑰,含 `*.keys.json.lock` 鎖檔)、`monitor/monitor.json`(監控目標
  座標)、`*.log`。範本用 `router/router.remote.example.json` 與
  `monitor/monitor.json.example`。
- 金鑰進出的唯一門是 `router/router.py --set-key`(DPAPI 加密落盤)。
- 朋友鏡像應得的檔案集合 = `audit_package.py` 的白名單,**集合等式**,不多不少。
- **行尾**:`.gitattributes` 把 `!-start.bat` 鎖定為 checkout 必 CRLF(cmd 的
  硬要求)、`.py` 必 LF——朋友拿到什麼形態是 repo 的性質,不取決於各人机器的
  `core.autocrlf`。

**版本與發行列車**:router 升級改 `router/router.py` 的 `VERSION` → tag
`vX.Y.Z`;monitor 升級改 `monitor/rmon.py` 的 `VERSION` → tag `rmon-X.Y.Z`
(兩序列互不撞號);L2 修訂批在原版本 tag 後加 `-fixN`,不改 `VERSION`
常數——tag 凍結快照,`VERSION` 是發行版本。歷史從本樹的初始 commit 起算,
更早的獨立 repo 歷史不在此樹,版本/tag 序列本身連續。

**給朋友(鏡像/自用)**:clone 後 `router/` 照
[router/README.md](router/README.md) 快速開始;整組一條龍雙擊根目錄
`!-start.bat`(委派 `monitor/launch.py go`;`monitor/!-start.bat` 保留,兩者
等價)。兩包同一棵樹時面板自動找到 router;只要一包,複製那個子資料夾走
也照常單獨運作。
