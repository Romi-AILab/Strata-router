#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rmon.py -- Strata router 即時監控面板(純唯讀,結構性零 POST)。

本檔案永遠只發 GET;任何 POST/操作只准出現在 launch.py。朋友複製這一個檔案
加上 launch.py 與 bat 即可用。純 stdlib,Python 3.8+,零監聽 port、零告警:
這是「低頭就能看」的儀表板(cc-switch/strata 原生監控同款體驗),不是值守哨兵。

誠實教義:None 不編 0;計數絕對值永不判斷對錯;缺欄=永灰=意圖行為;
每個數字的口徑都標在畫面邊上。金鑰紅線:本檔不讀 router.json、不讀任何
*keys*.json、不請求金鑰,資料 100% 來自 /__router/stats + /healthz + monitor.json。

ctypes 在本檔只准用於 Get/SetConsoleMode(防凍窗與 VT 輸出),這是紅線級約束,
tests_rmon.py 對 windll 呼叫點計數把關 —— 拿 ctypes 去打網路就違反本檔的存在理由。
"""
import argparse
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import sys
import time
import unicodedata

VERSION = "0.1.4"
SCHEMA_KNOWN_MAX = (1, 2, 17)           # rmon 內建對照的 router schema 上限
TERMS = ["sticky_hits", "new_placements", "migrations", "pinned", "last_resort",
         "overflow_placements", "overflow_rollbacks", "overflow_fizzles",
         "overflow_evictions", "operator_cancelled", "passthrough_gets"]
TRUNC = 100
INTERVAL_DEF = 2.0

# ---------------------------------------------------------------- 路徑與狀態

def state_dir():
    d = os.environ.get("RMON_STATE_DIR")
    if d:
        return d
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "strata-monitor")


def my_dir():
    return os.path.dirname(os.path.abspath(__file__))


def cfg_path():
    return os.environ.get("RMON_CONFIG") or os.path.join(my_dir(), "monitor.json")


def _atomic_write(path, text):
    tmp = "%s.tmp%d" % (path, os.getpid())     # per-pid:雙實例不得共寫同一 tmp
    try:
        with open(tmp, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise

# ---------------------------------------------------------------- monitor.json

_SECRET_TOKENS = {"key", "keys", "token", "tokens", "secret", "secrets", "password", "passwords"}
_CFG_FIELDS = {"host": str, "port": int, "mode": str, "names": dict, "interval": float}


def _is_secret_name(name):
    toks = [t for t in re.split(r"[^0-9a-zA-Z]+", str(name).lower()) if t]
    return any(t in _SECRET_TOKENS for t in toks)      # token 邊界,不殺 monkey


class ConfigError(Exception):
    pass


def load_cfg():
    p = cfg_path()
    if not os.path.exists(p):
        raise ConfigError(
            "找不到設定檔 %s\n"
            "  請複製 monitor.json.example 為 monitor.json,填上 router 的 host 與 port。" % p)
    try:
        with open(p, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception:
        raise ConfigError("設定檔 %s 讀不起來(JSON 格式問題)。修好它,rmon 不去猜。" % p)
    if not isinstance(raw, dict):
        raise ConfigError("設定檔 %s 必須是一個 JSON 物件。" % p)
    bad = [k for k in raw if _is_secret_name(k)]
    if bad:
        raise ConfigError("設定檔含疑似金鑰欄位 %s -- rmon 不收金鑰(紅線)。金鑰請用 "
                          "router.py --set-key。" % ", ".join(sorted(str(b) for b in bad)))
    cfg = {"host": "127.0.0.1", "port": 8088, "mode": "friend", "names": {},
           "interval": INTERVAL_DEF}
    for k, v in raw.items():
        if k.startswith("_"):
            continue                                   # 註解欄,靜默忽略
        if k not in _CFG_FIELDS:
            print("警告:monitor.json 未知欄位 %r 已忽略(與 router 同款紀律)。" % k)
            continue
        if k == "interval":
            try:
                cfg[k] = max(0.5, float(v))
            except (TypeError, ValueError):
                raise ConfigError("monitor.json 欄位 %s 必須是數字(秒)。" % k)
        elif k == "port":
            if not isinstance(v, int) or isinstance(v, bool) or not (1 <= v <= 65535):
                raise ConfigError("monitor.json 欄位 port 必須是 1-65535 的整數。")
            cfg[k] = v
        elif k == "mode":
            if v not in ("owner", "friend"):
                raise ConfigError("monitor.json mode 只能是 'owner' 或 'friend'。")
            cfg[k] = v
        elif k == "names":
            if not isinstance(v, dict):
                raise ConfigError("monitor.json names 必須是 盒id->顯示名 的扁平物件。")
            out = {}
            for a, b in v.items():
                if isinstance(b, (dict, list)) or b is None or isinstance(b, bool):
                    raise ConfigError("monitor.json names 的值必須是純字串(盒 %r)。" % (a,))
                if _is_secret_name(a):                 # 盒 id 也不准長成金鑰欄名
                    raise ConfigError("monitor.json names 含疑似金鑰欄名 %r(紅線)。" % (a,))
                out[clean(str(a))] = clean(str(b))
            cfg[k] = out
        else:                                          # host
            if not isinstance(v, str) or not v:
                raise ConfigError("monitor.json 欄位 %s 必須是非空字串。" % k)
            cfg[k] = clean(v)
    return cfg

# ---------------------------------------------------------------- 不可信字串

_RX_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_RX_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_RX_ESC2 = re.compile(r"\x1b.")
_RX_C0 = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RX_C1 = re.compile(u"[\x80-\x9f]")


def clean(s):
    """任何來自 /stats 或 monitor.json 的字串都是不可信資料:
    換行/歸位/定位先轉可見(整行偽造是真實攻擊,R1-A/B),再剝 escape、C0、DEL、
    C1、Cf(RLO/ZWSP 類視覺欺騙)、孤立代理字元(讓 UTF-8 寫檔崩潰的 R1-B/F3),
    超長截斷並標記。render 只准吃清洗後的副本。"""
    if not isinstance(s, str):
        return s
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", " ")
    s = _RX_OSC.sub("", s)
    s = _RX_CSI.sub("", s)
    s = _RX_ESC2.sub("", s)
    s = _RX_C0.sub("", s)
    s = _RX_C1.sub("", s)
    s = "".join(ch for ch in s
                if unicodedata.category(ch) != "Cf" and not (u"\ud800" <= ch <= u"\udfff"))
    if len(s) > TRUNC:
        s = s[:TRUNC] + "[截斷]"
    return s

# ---------------------------------------------------------------- 連線(唯讀)

def http_get(host, port, path, timeout=1.0):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Connection": "close", "Host": "%s:%d" % (host, port)})
        resp = conn.getresponse()
        body = resp.read(4 * 1024 * 1024)
        return resp.status, body
    finally:
        conn.close()                                    # 永不託命給 GC


class Dead(Exception):
    def __init__(self, kind, detail):        # kind: refused|timeout|dns|reset|http|decode
        Exception.__init__(self, detail)
        self.kind = kind
        self.detail = detail


GUIDE = {
    "refused": "refused=沒人監聽這個埠(router 沒起:launch 選單 [S],或 launch.py start)",
    "dns": "dns=主機名解析不了(VPN 斷了?機器改名?)-- 先修網路,不是 router 的問題",
    "timeout": "timeout=可能在應但太慢(查慢客戶端/線程,README 有教)",
    "reset": "reset=連線中途被切(VPN 抖動/router 重啟瞬間)-- 幾秒後自動重試",
    "http": "http=那個埠回話了但不是 router 協定(填錯 port?被別的程序佔了?)",
    "decode": "decode=HTTP 200 但內容不是合法 JSON(router/-proxy 出事,跑 diagnose 看)",
}


def _classify(exc):
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, (ConnectionResetError, http.client.RemoteDisconnected)):
        return "reset"
    if isinstance(exc, OSError) and getattr(exc, "winerror", None) in (10053, 10054):
        # WSAECONNABORTED:Windows 端偶發直接中止(本機堆疊/軟體切線),語意是
        # 「中途被切」,不是「沒人監聽」-- 誤報 refused 會把使用者導向错误那帖藥。
        return "reset"
    if isinstance(exc, (http.client.HTTPException, ValueError, UnicodeError)):
        return "http"
    if "timed out" in str(exc).lower():
        return "timeout"
    if isinstance(exc, (ConnectionRefusedError, BrokenPipeError, ConnectionAbortedError, OSError)):
        return "refused"
    return "http"


def http_get_safe(host, port, path, timeout=1.0):
    """http_get + 例外分類:任何底層炸點都收斂成 Dead(kind),
    絕不把 traceback 或攻擊者的位元組帶進使用者的終端(R1-B/F4)。"""
    try:
        return http_get(host, port, path, timeout)
    except Dead:
        raise
    except Exception as exc:
        raise Dead(_classify(exc), clean(str(exc))[:120])


def fetch(cfg):
    st, body = http_get_safe(cfg["host"], cfg["port"], "/__router/stats")
    if st != 200:
        raise Dead("http", "HTTP %s" % st)
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        raise Dead("decode", "/stats 回應不是合法 JSON")

# ---------------------------------------------------------------- 小工具

def _pick_int(d, k):
    v = (d or {}).get(k)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _pick_float(d, k):
    v = (d or {}).get(k)
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    return None


def _ver(t):
    out = []
    t = re.sub(r"^[^0-9]+", "", str(t or ""))   # "v2.0.0"/"ver1.2" 類前綴先剝(R2-D):
    for p in t.split("."):                      # 否則 () falsy 掉進紅燈分支=對健康新版誤報
        m = re.match(r"^(\d+)", p)
        if not m:
            break
        out.append(int(m.group(1)))
    return tuple(out)


def dw(s):
    n = 0
    for ch in str(s):
        n += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return n


def pad(s, w, right=False):
    gap = max(0, w - dw(s))
    return (s + " " * gap) if right else (" " * gap + s)


def fmt_dur(sec):
    sec = int(sec or 0)
    if sec < 90:
        return "%ds" % sec
    if sec < 5400:
        return "%dm%02ds" % (sec // 60, sec % 60)
    return "%dh%02dm" % (sec // 3600, (sec % 3600) // 60)

# ---------------------------------------------------------------- build

def _loopback(url):
    return "://" in url and re.search(r"://(127\.0\.0\.1|localhost|\[::1\])", url) is not None


def _is_loopback_host(host):
    return str(host) in ("127.0.0.1", "localhost", "::1")


def _gate_state(be, si_eff, si_assumed):
    """禮讓閘以 router 自己的 accepting(放不放行)為首訊號(R2-C):
    只報「狀態新鮮」卻不報「router 其實拒放」會讓使用者把請求送進拒絕放置的盒。"""
    if not be.get("require_idle"):
        return "不適用", None
    tag = "(間隔假設1.0s)" if si_assumed else ""
    acc = be.get("accepting")
    if acc is False:
        why = "ext_streak=%s:盒上有非經本 router 的流量" % be.get("ext_streak") \
            if (_pick_int(be, "ext_streak") or 0) >= 2 else None
        return "關:router 現正拒絕放置", why
    if acc is None:
        return "問不到 accepting(fail-closed)", None
    blind = max(3.0 * si_eff, 5.0)
    age = _pick_float(be, "reported_age_s")
    if age is None:                    # router 端 reported_age_s=None => 從未回報
        return "從未證明空閒(fail-closed)", None      # 原因已寫在閘字裡,不另養死資料(R3)
    if age > blind:
        return "盲:狀態 %ss 前更新 > %ss%s" % (age, blind, tag), None
    return "開:可證空閒(%ss 前有回報)%s" % (age, tag), None


def build(snapshot, prev, now):
    """snapshot: /stats dict(不可信)|prev: 上一拍快取|now: epoch float"""
    snap = snapshot or {}
    router = snap.get("router") if isinstance(snap.get("router"), dict) else {}
    boxes = snap.get("backends") if isinstance(snap.get("backends"), list) else []
    ver = clean(str(snap.get("version") or ""))
    m = {"kind": "snapshot", "rmon": VERSION, "schema_known": ".".join(str(x) for x in SCHEMA_KNOWN_MAX),
         "ts": now, "router_ver": ver or None,
         "started_at": _pick_int(snap, "started_at"), "uptime_s": _pick_int(snap, "uptime_s"),
         "status_interval": _pick_float(snap, "status_interval"),
         "time_skew_s": None, "requests": _pick_int(router, "requests"),
         "inflight_fleet": 0, "inflight_unknown": 0, "boxes": [], "prev": prev is not None}
    if m["uptime_s"] is not None and m["uptime_s"] < 0:
        m["uptime_s"] = None           # 時鐘後調的負上線時間:如實說問不到(R1-A/F14)
    ts = _pick_float(snap, "time")
    if ts is not None:
        skew = now - ts
        m["time_skew_s"] = round(skew, 1) if abs(skew) > 5 else None
    si = m["status_interval"]
    m["si_assumed"] = si is None
    si_eff = si if si is not None else 1.0

    inst_change = False
    if prev:
        if prev.get("ver") not in (None, m["router_ver"]):
            inst_change = True
        pr = prev.get("requests")
        if pr is not None and m["requests"] is not None and m["requests"] < pr:
            inst_change = True
        # C2 的正解用法:started_at 不同 = 換了實例,就算版本與計數都接得上。
        # 容忍 ≤5s 漂移:合規 router 的 started_at 是啟動常數,但「以 now-uptime 現算」的
        # 相容實作每秒都在漂;嚴格相等會讓估算腿對這種伺服器終身死亡。漂移>5s 才算換實例;
        # 5s 內的真重啟由「版本變/計數倒退」兩條腿兜住。
        ps = prev.get("started_at")
        if ps is not None and m["started_at"] is not None and abs(ps - m["started_at"]) > 5:
            inst_change = True
    m["instance"] = "changed" if inst_change else "same"

    total_bytes = 0.0
    have_bytes = False
    # 相鄰拍的跨度閘:dreq 與估算腿共用同一把尺(R2-C:一天前的差值不配叫「本窗」)
    dt_prev = None
    if prev and isinstance(prev.get("ts"), (int, float)):
        dt_prev = now - float(prev["ts"])
    span_ok = dt_prev is not None and 0.2 < dt_prev <= 180
    prev_boxes = {}
    if prev:
        prev_boxes = {b.get("id"): b for b in (prev.get("boxes") or [])}
    for be in boxes:
        if not isinstance(be, dict):
            continue
        bid = clean(str(be.get("id") or "?"))     # id 也是 /stats 來的,一律洗
        st = _pick_int(be, "inflight")
        if st is None:
            m["inflight_unknown"] += 1           # 缺欄盒:總數只能宣稱「至少」(R2-C)
        else:
            m["inflight_fleet"] += max(0, st)
        rep = be.get("reported") if isinstance(be.get("reported"), dict) else {}
        b = {"id": bid,
             "state": clean(str(be.get("state") or "")) or None,
             "url": clean(str(be.get("url") or "")),
             "inflight": st, "max_inflight": _pick_int(be, "max_inflight"),
             "accepting": be.get("accepting") if isinstance(be.get("accepting"), bool) else None,
             "require_idle": be.get("require_idle") if isinstance(be.get("require_idle"), bool) else None,
             "has_api_key": be.get("has_api_key") if isinstance(be.get("has_api_key"), bool) else None,
             "serving": _pick_float(rep, "serving"), "queued": _pick_float(rep, "queued"),
             "reported_age_s": _pick_float(be, "reported_age_s"),
             "ext_streak": _pick_int(be, "ext_streak"),
             "decode_tok_s": _pick_float(rep, "decode_tok_s"),
             "box_uptime_s": _pick_int(rep, "box_uptime_s"),
             "gpu_util_pct": _pick_int(rep, "gpu_util_pct"),
             "avg_ttfb_s": _pick_float(be, "avg_ttfb_s"),
             "recent_ttfb_avg_s": _pick_float(be, "recent_ttfb_avg_s"),
             "recent_ttfb_p95_s": _pick_float(be, "recent_ttfb_p95_s"),
             "recent_ttfb_n": _pick_int(be, "recent_ttfb_n"),
             "down_remaining_s": _pick_float(be, "down_remaining_s"),
             "half_open_trial": be.get("half_open_trial") if isinstance(be.get("half_open_trial"), bool) else None,
             "connect_failures": _pick_int(be, "connect_failures"),
             "box_requests": _pick_int(be.get("stats") if isinstance(be.get("stats"), dict) else {}, "requests"),
             "bytes_out": _pick_int(be.get("stats") if isinstance(be.get("stats"), dict) else {}, "bytes_out")}
        b["loopback"] = _loopback(b["url"] or "")
        if b["require_idle"]:
            g, ev = _gate_state(b, si_eff, m["si_assumed"])
            b["gate"] = g
            b["gate_ev"] = ev
        else:
            b["gate"] = None
        # 借用者估計:ext_streak>=2 ∧ 新鮮 ∧ 本機盒(去「朋友」點名)
        if b["ext_streak"] is not None and b["ext_streak"] >= 2 and b["loopback"] \
                and b["reported_age_s"] is not None and b["reported_age_s"] <= max(3.0 * si_eff, 5.0):
            b["borrow"] = "盒上有非經本 router 的流量(估計,來源不限)"
        elif b["ext_streak"] == 1:
            b["borrow"] = "未確認(單拍證據)"
        else:
            b["borrow"] = None
        pb = prev_boxes.get(bid) or {}
        dreq = None
        if (not inst_change) and span_ok and b["box_requests"] is not None \
                and isinstance(pb.get("requests"), int):
            dreq = b["box_requests"] - pb["requests"]
            if dreq < 0:
                dreq = None                              # 負 Δ:取樣丟棄
        b["dreq"] = dreq
        if (not inst_change) and b["bytes_out"] is not None and isinstance(pb.get("bytes_out"), int):
            d = b["bytes_out"] - pb["bytes_out"]
            if d >= 0:
                total_bytes += d
                have_bytes = True
        m["boxes"].append(b)

    # 混合算力 tok/s(估算腿:字節/4,與 Strata 前端同口徑)
    m["tok_s_est"] = None
    m["tok_s_span_s"] = None
    m["no_bytes_leg"] = bool(boxes) and all(b["bytes_out"] is None for b in m["boxes"])
    if prev and not inst_change and have_bytes and span_ok:
        m["tok_s_est"] = round(total_bytes / dt_prev / 4.0, 1)
        m["tok_s_span_s"] = round(dt_prev, 1)

    # 帳目燈(三態;缺欄=永灰=意圖;新版失配=灰但措辭誠實;綠需連續 3 拍靜止)
    req = m["requests"]
    missing_terms = [t for t in TERMS if t not in router]
    bad_terms = [t for t in TERMS if t in router and _pick_int(router, t) is None]
    if missing_terms:
        why = "缺欄(等 router 提供完整終態欄位;永灰=預設行為)"
    elif bad_terms:
        why = "欄位型別不符(%s;欄在但非整數,已拒用)" % "、".join(bad_terms[:3])
    else:
        why = "requests 欄缺或型別不符"
    m["ledger"] = {"light": "gray", "why": why}
    if not missing_terms and not bad_terms and req is not None:
        total = sum(_pick_int(router, t) for t in TERMS)
        delta = req - total
        prev_tot = prev.get("ledger_total") if prev else None
        prev_req = prev.get("requests") if prev else None
        streak_prev = prev.get("ledger_streak") if prev else None
        streak_prev = streak_prev if isinstance(streak_prev, int) else 0
        stable = prev is not None and req == prev_req and total == prev_tot
        if prev is None:
            m["ledger"] = {"light": "gray", "total": total, "delta": delta, "streak": 0,
                           "why": "首拍無基準(尚無第二拍可比)"}
        elif not stable:
            m["ledger"] = {"light": "motion", "total": total, "delta": delta, "streak": 0,
                           "why": "運動中(計數在變,靜態帳目不適用)"}
        elif req == total:
            streak = streak_prev + 1
            if streak >= 2:                    # 連續 3 拍相同才宣稱綠(spec §验收 ≥3 拍)
                m["ledger"] = {"light": "green", "total": total, "delta": 0, "streak": streak,
                               "why": "連續 %d 拍靜止且 Σ 合" % (streak + 1)}
            else:
                m["ledger"] = {"light": "motion", "total": total, "delta": delta, "streak": streak,
                               "why": "靜止 2 拍(第 3 拍仍同才轉綠)"}
        elif _ver(ver) and _ver(ver) > SCHEMA_KNOWN_MAX:
            # R2-D:單方面歸因「疑似新增欄位」會把新版真帳目 bug 永久偽裝成「等更新」
            m["ledger"] = {"light": "gray", "total": total, "delta": delta,
                           "why": "未知新版 router(%s):無法區分「新增帳目欄位」與「真失配」,"
                                  "先當未知並更新 rmon" % ver}
        else:
            m["ledger"] = {"light": "red", "total": total, "delta": delta,
                           "why": "靜止帳目失配(差 %s)" % delta}
    return m

# ---------------------------------------------------------------- 快取(跨 once 拍)

def _cache_file(cfg):
    tag = hashlib.sha1(("%s:%s" % (cfg["host"], cfg["port"])).encode("utf-8")).hexdigest()[:12]
    return os.path.join(state_dir(), "rmon-cache-%s.json" % tag)


def cache_load(cfg):
    try:
        with open(_cache_file(cfg), "r", encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        return None
    # 形態驗證(R2-C):舊版寫過/手改過/半寫入的 cache 只准當「無前拍」,
    # 形態不對就讓 build 吃下是拿裸 traceback 換使用者體驗。
    if not isinstance(d, dict) or not isinstance(d.get("ts"), (int, float)) \
            or isinstance(d.get("ts"), bool):
        return None
    boxes = d.get("boxes")
    if boxes is not None and (not isinstance(boxes, list)
                              or not all(isinstance(b, dict) for b in boxes)):
        return None
    # build 會對這些 top-level 欄做算術/比較(R3-P2-1):任一型別不對就是裸
    # TypeError,而且拋在 cache_save 之前 -- 壞 cache 將永不自癒。只准 int|None。
    for k in ("requests", "started_at", "ledger_total", "ledger_streak"):
        v = d.get(k)
        if v is not None and (not isinstance(v, int) or isinstance(v, bool)):
            return None
    return d


def cache_save(cfg, model):
    try:
        os.makedirs(state_dir(), exist_ok=True)
        c = {"target": "%s:%s" % (cfg["host"], cfg["port"]), "ts": model["ts"],
             "ver": model.get("router_ver"), "requests": model.get("requests"),
             "started_at": model.get("started_at"),
             "ledger_total": (model.get("ledger") or {}).get("total"),
             "ledger_streak": (model.get("ledger") or {}).get("streak"),
             "boxes": [{"id": b["id"], "requests": b.get("box_requests"),
                        "bytes_out": b.get("bytes_out")} for b in model["boxes"]]}
        path = _cache_file(cfg)
        _atomic_write(path, json.dumps(c, ensure_ascii=True))
        _gc_caches(path)
    except OSError:
        pass


def _gc_caches(keep):
    """host 改名/搬機後的幽魂 cache 回收(R2-D):同前綴、90 天未動才刪,
    宁可不刪也不動正在輪替的目標。"""
    cutoff = time.time() - 90 * 86400
    try:
        names = os.listdir(state_dir())
    except OSError:
        return
    for n in names:
        if not (n.startswith("rmon-cache-") and n.endswith(".json")):
            continue
        p = os.path.join(state_dir(), n)
        try:
            if p != keep and os.path.getmtime(p) < cutoff:
                os.remove(p)
        except OSError:
            pass

# ---------------------------------------------------------------- 渲染

def _term_ok(force_ascii):
    if force_ascii:
        return False
    # 只在確定支援 ANSI 的終端自動開色(Windows Terminal);legacy cmd 要色用
    # --color(屆時由 _enable_vt 去開 VT 輸出模式,開了就有真色)。
    return bool(os.environ.get("WT_SESSION"))


def _c(text, code, use_color):
    if not use_color:
        return text
    return "\x1b[%sm%s\x1b[0m" % (code, text)


STATE_LABEL = {"healthy": "健康", "down": "DOWN", "suspect": "連線不穩(仍在服務)"}
LIGHT = {"green": "●帳目OK", "motion": "○帳目運動中", "gray": "○帳目灰", "red": "!!帳目失配"}


def render(model, cfg, width=None, color=False, dead=None, replay=False):
    w = width or min(shutil.get_terminal_size((88, 24)).columns, 100)
    narrow = w < 78
    L = []
    head = "rmon v%s · schema@%s" % (model.get("rmon", VERSION), model.get("schema_known", "?"))
    if replay:
        head = "REPLAY 回放(非即時)"
    L.append(_c(head, "90", color))
    if dead is not None:
        L.append(_c("router 摸不到:%s(%s)" % (dead.kind, dead.detail[:60]), "1;31", color))
        L.append("  " + GUIDE.get(dead.kind, "未知連線病名 -- 拍 debug 給 rmon"))
        return L
    ver = model.get("router_ver") or "?"
    up = _c("● 在線", "1;32", color)
    line1 = "%s router v%s" % (up, ver)
    if model.get("uptime_s") is not None:
        line1 += " · 啟動至今 %s" % fmt_dur(model["uptime_s"])
    if model.get("time_skew_s") is not None:
        line1 += " · 與 router 時鐘差 %ss(延遲/校時,非漂移)" % model["time_skew_s"]
    L.append(line1)
    led = model.get("ledger") or {}
    ledline = LIGHT.get(led.get("light"), "○帳目")
    if led.get("delta"):
        ledline += "(差%s)" % led["delta"]
    ledline += " -- %s" % led.get("why", "")
    col = {"green": "1;32", "red": "1;31", "motion": "90", "gray": "90"}.get(led.get("light"), "0")
    L.append(_c(ledline, col, color))
    tk = []
    if model.get("tok_s_est") is not None:
        tk.append("≈%s tok/s(估算:字節/4,近 %ss)" % (model["tok_s_est"], model.get("tok_s_span_s")))
    elif model.get("no_bytes_leg"):
        tk.append("估算腿:此 router 未發布 bytes_out(較舊版無此欄,不會预热)")
    else:
        tk.append("tok/s 預熱中(需相鄰兩拍)")
    if model.get("inflight_unknown"):
        tk.append("≥%d 個請求在飛(%d 盒未知)" % (model.get("inflight_fleet", 0),
                                                 model["inflight_unknown"]))
    else:
        tk.append("%d 個請求在飛" % model.get("inflight_fleet", 0))
    L.append("算力:" + " · ".join(tk))
    L.append("")
    for b in model["boxes"]:
        nm = cfg["names"].get(b["id"], b["id"])
        sl = STATE_LABEL.get((b.get("state") or "").lower(), b.get("state") or "問不到")
        stc = {"健康": "1;32", "DOWN": "1;31", "連線不穩(仍在服務)": "1;33"}.get(sl, "0")
        row = "%s %s" % (_c(pad(nm, 12, True), stc, color), sl)
        inf = "%s/%s" % (b["inflight"] if b["inflight"] is not None else "?",
                         b["max_inflight"] if b["max_inflight"] is not None else "?")
        row += " · 在飛 %s" % inf
        if b["serving"] is not None:
            row += " · 盒自報總載入 %g" % b["serving"]
            if b["queued"] is not None:
                row += "(含排隊 %g)" % b["queued"]
        elif b["reported_age_s"] is None:
            row += " · 盒自報:從未回報"
        if b["gate"]:
            gc = "1;33" if any(w in b["gate"] for w in ("盲", "從未", "關", "問不到")) else "90"
            row += "\n    禮讓閘:" + _c(b["gate"], gc, color)
            if b.get("gate_ev"):
                # 拒放原因必須到得了畫面(R3-P3-1):borrow 行要 loopback∧新鮮才出,
                # 遠端拒放盒的「為什麼」否則永遠 invisible。
                row += _c("(%s)" % b["gate_ev"], "90", color)
        r2 = []
        if b["decode_tok_s"] is not None:
            # 這是「上一個請求」的實測解碼速率:空置盒上它是殘值,不能裸顯成現況(R2-C)
            if b["serving"] == 0:
                r2.append("上一單 %g tok/s(盒實測,現空置)" % b["decode_tok_s"])
            elif b["serving"]:
                r2.append("生成 %g tok/s(盒實測)" % b["decode_tok_s"])
            else:
                # serving 缺欄:None 不准被當成「非 0 = 在忙」而宣稱現行速率(R3-P3-3)
                r2.append("最近實測 %g tok/s(盒實測,忙閒未知)" % b["decode_tok_s"])
        if not narrow:
            if b["gpu_util_pct"] is not None:
                r2.append("GPU %d%%" % b["gpu_util_pct"])
            if b["box_uptime_s"] is not None:
                r2.append("盒上線 %s" % fmt_dur(b["box_uptime_s"]))
        if r2:
            row += "\n    " + " · ".join(r2)
        r3 = []
        if b["recent_ttfb_n"] and b["recent_ttfb_avg_s"] is not None:
            # n>0 卻缺 avg/p95 時不准印 "Nones"(R3-P3-2):缺的欄問號,avg 整個缺就退终身腿
            p95 = ("%ss" % b["recent_ttfb_p95_s"]) if b["recent_ttfb_p95_s"] is not None else "?"
            r3.append("近期首字 avg %ss / p95 %s(近 %d 筆)" % (b["recent_ttfb_avg_s"], p95,
                                                              b["recent_ttfb_n"]))
        elif b["avg_ttfb_s"] is not None:
            r3.append("首字終身均值 %ss(含探測;無近期窗欄位=router 較舊)" % b["avg_ttfb_s"])
        if b.get("dreq"):
            r3.append("本窗轉發 +%d" % b["dreq"])
        if b["state"] == "down" and b.get("down_remaining_s") is not None:
            r3.append("約 %ds 後自動重試(可能更早恢復)" % b["down_remaining_s"])
        if b["borrow"]:
            r3.append(_c(b["borrow"], "1;33", color))
        if r3:
            row += "\n    " + " · ".join(r3)
        L.append(row)
    if model.get("instance") == "changed":
        L.append("")
        L.append(_c("(偵測到 router 實例更換:計數倒退、版本變或 started_at 跳變>5s -- 速率與窗口從頭預熱)", "90", color))
    return L

# ---------------------------------------------------------------- 输出模式

def _print_lines(L):
    for line in L:
        print(line)


def _snapshot_state(cfg):
    try:
        snap = fetch(cfg)
    except Dead as d:
        return None, d, None
    now = time.time()
    prev = cache_load(cfg)
    model = build(snap, prev, now)
    cache_save(cfg, model)
    return model, None, snap

# ---------------------------------------------------------------- diagnose

def do_diagnose(cfg, full=False):
    model, dead, _ = _snapshot_state(cfg)
    out = {"rmon": VERSION, "ts": time.strftime("%F %T")}
    if full:
        out["target"] = "%s:%s" % (cfg["host"], cfg["port"])
    else:                              # 去識別化:貼群求援不帶實址(R1-A/B/F5)
        out["target_kind"] = "loopback" if _is_loopback_host(cfg["host"]) else "remote"
    if dead is not None:
        out["reach"] = dead.kind
        out["note"] = "router 摸不到,以下是監控側事實"
        print(json.dumps(out, ensure_ascii=True, indent=2))
        return 0
    out["reach"] = "ok"
    out["router_version"] = model.get("router_ver")
    out["uptime_s"] = model.get("uptime_s")
    out["status_interval"] = model.get("status_interval")
    out["ledger"] = model.get("ledger")
    out["tok_s_est"] = model.get("tok_s_est")
    boxes = []
    for i, b in enumerate(model["boxes"]):
        disp = ("box-" + (chr(ord("A") + i) if i < 26 else str(i + 1))) if not full else b["id"]
        row = {"id": disp, "state": b["state"], "inflight": b["inflight"],
               "max_inflight": b["max_inflight"], "serving": b["serving"], "queued": b["queued"],
               "gate": b["gate"], "gate_ev": b.get("gate_ev"), "ext_streak": b["ext_streak"],
               "decode_tok_s": b["decode_tok_s"],
               "gpu_util_pct": b["gpu_util_pct"], "recent_ttfb_n": b["recent_ttfb_n"],
               "recent_ttfb_avg_s": b["recent_ttfb_avg_s"], "recent_ttfb_p95_s": b["recent_ttfb_p95_s"],
               "has_api_key": b["has_api_key"], "loopback": b["loopback"]}
        if full:
            row["url"] = b["url"]
        boxes.append(row)
    out["boxes"] = boxes
    print(json.dumps(out, ensure_ascii=True, indent=2))
    return 0

# ---------------------------------------------------------------- replay / live / once

def _replay_ticks(path):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read(10 * 1024 * 1024)
    try:
        return [json.loads(text)]
    except ValueError:
        pass
    ticks = []
    for ln in text.splitlines():
        ln = ln.strip()
        if ln:
            try:
                ticks.append(json.loads(ln))
            except ValueError:
                continue
    if not ticks:
        raise SystemExit("replay 檔讀不進去(既不是單一 JSON 也不是 JSONL 拍序列):%s" % path)
    return ticks


def _tick_prev(model, ts):
    return {"ts": ts, "ver": model.get("router_ver"), "requests": model.get("requests"),
            "started_at": model.get("started_at"),
            "ledger_total": (model.get("ledger") or {}).get("total"),
            "boxes": [{"id": b["id"], "requests": b.get("box_requests"),
                       "bytes_out": b.get("bytes_out")} for b in model["boxes"]]}


def do_replay(cfg, path, color):
    ticks = _replay_ticks(path)
    prev = None
    now = time.time()
    base = now - 2.0 * len(ticks)
    model = None
    for i, t in enumerate(ticks):
        model = build(t, prev, base + 2.0 * i)
        prev = _tick_prev(model, base + 2.0 * i)
    _print_lines(render(model, cfg, color=color, replay=True))
    print("")
    print("(回放 %d 拍;回放模式不碰網路、不碰操作,重播完就結束)" % len(ticks))
    return 0


def do_once(cfg, color):
    model, dead, _ = _snapshot_state(cfg)
    _print_lines(render(model or {}, cfg, color=color, dead=dead))
    return 0 if dead is None else 2


def do_live(cfg, interval, color):
    if os.name == "nt":
        _console_nice(True)
    try:
        while True:
            model, dead, _ = _snapshot_state(cfg)
            L = render(model or {}, cfg, color=color, dead=dead)
            if color:
                sys.stdout.write("\x1b[H\x1b[2J")
            _print_lines(L)
            sys.stdout.write("\nq 離開 · r 立刻刷新 · 關窗就關窗(無值守承諾)\n")
            sys.stdout.flush()
            waited = 0.0
            while waited < interval:
                try:
                    import msvcrt
                    if msvcrt.kbhit():
                        ch = msvcrt.getwch().lower()
                        if ch == "q":
                            return 0
                        if ch == "r":
                            waited = interval
                except ImportError:
                    pass
                time.sleep(0.15)
                waited += 0.15
    except KeyboardInterrupt:
        return 0
    finally:
        if color:
            sys.stdout.write("\x1b[0m\x1b[?25h\n")   # 無色終端不噴裸游標碼(R1-A/F11)
        sys.stdout.flush()
        if os.name == "nt":
            _console_nice(False)

# ---------------------------------------------------------------- 控制台


_SAVED_MODE = [None]


def _console_nice(on, want_color=False):
    """live/選單期間關掉本窗快速編輯/游標並(若要色)開 VT 輸出(R1-A/F11);
    退出全部還原原值。本檔 ctypes 只准出現在這裡與 VT 開啟的分工內。"""
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k32.GetConsoleMode(h, ctypes.byref(mode)):
            QE, INS, VT = 0x0040, 0x0020, 0x0004
            if on:
                _SAVED_MODE[0] = mode.value
                newm = mode.value & ~QE & ~INS
                if want_color:
                    newm |= VT                 # legacy cmd 的 --color:先開 VT 再談色
                k32.SetConsoleMode(h, newm)
            elif _SAVED_MODE[0] is not None:
                k32.SetConsoleMode(h, _SAVED_MODE[0])
                _SAVED_MODE[0] = None
    except Exception:
        pass

# ---------------------------------------------------------------- main

def main(argv=None):
    try:                     # 編碼防呆:cp950 等小編碼下 ≈/● 只能降級,不准崩潰
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="rmon", description="Strata router 唯讀監控面板(零 POST、零金鑰、零告警)")
    ap.add_argument("cmd", nargs="?", default="once", choices=["once", "live", "diagnose"])
    ap.add_argument("--replay", metavar="FILE", help="回放 JSON 單拍或 JSONL 拍序列(同一條 build 管線)")
    ap.add_argument("--full", action="store_true", help="diagnose 出實址與真實盒名(預設去識別化)")
    ap.add_argument("--ascii", action="store_true", help="強制純 ASCII(無色)")
    ap.add_argument("--color", action="store_true", help="強制開色(legacy cmd 會順手開 VT 輸出)")
    ap.add_argument("--interval", type=float, help="live 更新秒數(預設 monitor.json 或 2s)")
    a = ap.parse_args(argv)
    color = (not a.ascii) and (a.color or _term_ok(False))
    if a.replay:
        cfg = {"host": "-", "port": 0, "mode": "friend", "names": {}, "interval": INTERVAL_DEF}
        return do_replay(cfg, a.replay, color)
    try:
        cfg = load_cfg()
    except ConfigError as exc:
        print(str(exc))
        return 2
    if a.cmd == "diagnose":
        return do_diagnose(cfg, full=a.full)
    if a.cmd == "live":
        return do_live(cfg, a.interval or cfg["interval"], color)
    return do_once(cfg, color)


if __name__ == "__main__":
    sys.exit(main())
