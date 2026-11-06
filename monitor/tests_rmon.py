#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tests_rmon.py -- monitor v0.2.0 驗收(tests first red line:全部 temp dir、零真實 port)。

跑法:python tests_rmon.py -v
涵蓋:3.8 相容(AST+compile 雙閘)、結構性零 POST、清洗(含 R1 換行偽造/Cf/代理字元)、
寬度、設定紅線(含植樁清洗/巢狀拒絕)、presence 降級、tok/s 估算、帳目三態、禮讓閘三態、
借用估計、replay 管線、diagnose 去識別化(含 target 遮罩)、HTML 逃脫、
launch(探活不炸/pid 三因子/EOF 誠實/金鑰零讀取)、bat 純 ASCII+CRLF、零 ESC 金絲雀、
固定框引擎與降級路徑(v0.2.0:絕對歸位源碼+行為雙鎖、VT 讀回閘、RMON_NO_FRAME、NO_COLOR)。
"""
import ast
import builtins
import contextlib
import ctypes
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import unittest

try:                     # M2-A/P1-3:本套輸出大量 CJK(測詞、docstring、失敗 detail),
    sys.stdout.reconfigure(errors="replace")   # cp950/Big5 控制台上紅測只准變 mojibake,
    sys.stderr.reconfigure(errors="replace")   # 不准在 verdict 之前炸掉整套
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

_TMP = tempfile.mkdtemp(prefix="rmon-test-")
os.environ["RMON_STATE_DIR"] = os.path.join(_TMP, "state")
os.environ["RMON_CONFIG"] = os.path.join(_TMP, "monitor.json")

import rmon  # noqa: E402
import launch  # noqa: E402

TERMS = rmon.TERMS
BOX_URL_PRIV = "http://203.0.113.71:18443/v1"       # 文件保留假址,測去識別化用


def mock_mod():
    """假 subprocess:Popen 成功且 pid 恆 424242,零真 spawn。"""
    class _P:
        def __init__(self, cmd, **kw):
            self.pid = 424242
    return type("M", (), {"Popen": _P, "DEVNULL": -3,
                          "call": staticmethod(lambda *a, **k: 0)})


def mock_time_mod():
    """假 time 模組:牆鐘一經核心觸碰即刻紅(F-P2-7 注入時鐘的牙),sleep 零耗時。"""
    def _boom():
        raise AssertionError("do_start_core 不得用牆鐘 time.time()")
    return type("T", (), {"time": staticmethod(_boom),
                          "sleep": staticmethod(lambda s: None)})


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


def mk_stats(version="1.2.14", requests=10, terms=None, drop=None, boxes=None, si=1.0,
             started=True, now=None):
    tr = {t: 0 for t in TERMS}
    if terms is not None:
        tr.update(terms)
    elif requests is not None:
        tr["new_placements"] = requests          # 默認Σ=requests(帳目合的基準態)
    for t in (drop or []):
        tr.pop(t, None)
    if requests is not None:
        tr["requests"] = requests
    top = {"version": version, "router": tr, "backends": boxes or [],
           "time": now if now is not None else time.time()}
    if si is not None:
        top["status_interval"] = si
    if started:
        n = now if now is not None else time.time()
        top["started_at"] = int(n) - 120
        top["uptime_s"] = 120
    return top


def mk_box(bid="local", url="http://127.0.0.1:18080/v1", state="healthy",
           inflight=0, maxif=2, reported=None, stats=None, require_idle=False,
           reported_age_s=1.0, ext_streak=0, v14=True, avg_ttfb=None, accepting=True):
    rep = {"serving": 0.0, "queued": 0.0} if reported is None else dict(reported)
    st = {"requests": 3, "bytes_out": 4000} if stats is None else dict(stats)
    b = {"id": bid, "url": url, "state": state, "inflight": inflight,
         "connect_failures": 0, "down_remaining_s": 0.0, "half_open_trial": False,
         "reported": rep, "max_inflight": maxif, "require_idle": require_idle,
         "has_api_key": True, "accepting": accepting, "ext_streak": ext_streak,
         "reported_age_s": reported_age_s, "avg_ttfb_s": avg_ttfb, "stats": st}
    if v14:
        b.update({"recent_ttfb_avg_s": 1.2, "recent_ttfb_p95_s": 3.4, "recent_ttfb_n": 7})
        rep.update({"decode_tok_s": 38.4, "box_uptime_s": 3601, "gpu_util_pct": 75})
    return b


def mk_prev(model, ts=None):
    return {"ts": ts if ts is not None else model["ts"], "ver": model.get("router_ver"),
            "requests": model.get("requests"), "started_at": model.get("started_at"),
            "ledger_total": (model.get("ledger") or {}).get("total"),
            "ledger_streak": (model.get("ledger") or {}).get("streak"),
            "boxes": [{"id": b["id"], "requests": b.get("box_requests"),
                       "bytes_out": b.get("bytes_out")} for b in model["boxes"]]}


def base_cfg():
    return {"host": "127.0.0.1", "port": 9, "mode": "owner",
            "names": {"local": "地端"}, "interval": 2.0}


def render_text(model, cfg=None, **kw):
    return "\n".join(rmon.render(model, cfg or base_cfg(), **kw))


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Test38Compat(unittest.TestCase):
    def _src(self, name):
        with open(os.path.join(HERE, name), "r", encoding="utf-8") as fh:
            return fh.read()

    def test_no_39_plus_syntax(self):
        for name in ("rmon.py", "launch.py"):
            tree = ast.parse(self._src(name), name)
            for node in ast.walk(tree):
                self.assertNotIsInstance(node, ast.NamedExpr, "%s 含 walrus(3.8 炸)" % name)
                if hasattr(ast, "Match"):
                    self.assertNotIsInstance(node, ast.Match, "%s 含 match(3.10)" % name)

    def test_compile_feature_version_38(self):
        for name in ("rmon.py", "launch.py"):
            compile(self._src(name), name, "exec", dont_inherit=True, _feature_version=38)


class TestZeroPostStructure(unittest.TestCase):
    WHITELIST = {"argparse", "http.client", "hashlib", "json", "os", "re",
                 "shutil", "socket", "sys", "time", "unicodedata",
                 "ctypes", "msvcrt"}   # html/webbrowser 已依使用者指示永久移出(見 TestNoWebSurface)

    def _src(self, name):
        with open(os.path.join(HERE, name), "r", encoding="utf-8") as fh:
            return fh.read()

    def test_no_post_literal(self):
        for name in ("rmon.py", "launch.py"):
            src = self._src(name)
            self.assertNotIn('"POST"', src)
            self.assertNotIn("'POST'", src)
            for node in ast.walk(ast.parse(src, name)):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                        and node.func.attr == "request":
                    self.assertTrue(node.args and isinstance(node.args[0], ast.Constant)
                                    and node.args[0].value == "GET",
                                    "%s 有非 GET 的 .request()" % name)

    def test_rmon_import_whitelist(self):
        tree = ast.parse(self._src("rmon.py"), "rmon.py")
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    mods.add(a.name)
            elif isinstance(node, ast.ImportFrom):
                mods.add(node.module or "")
        for m in ("subprocess", "socketserver", "threading", "urllib"):
            self.assertNotIn(m, mods, "rmon 不准 import %s" % m)
        for m in mods:
            root = m.split(".")[0]
            self.assertTrue(root in self.WHITELIST or m in self.WHITELIST,
                            "rmon import 超出白名單:%s" % m)

    def test_rmon_ctypes_is_pinned_to_console(self):
        # rmon 的 ctypes 只准碰控制台(R1-A 紅線備忘):windll 取用點計數封頂
        tree = ast.parse(self._src("rmon.py"), "rmon.py")
        n = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "windll":
                n += 1
        self.assertLessEqual(n, 2, "rmon 的 windll 取用點長出了新地方 -- 查是不是往網路伸了")

    def test_launch_never_imports_router(self):
        tree = ast.parse(self._src("launch.py"), "launch.py")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertNotEqual(a.name, "router")
            self.assertFalse(isinstance(node, ast.ImportFrom) and (node.module or "") == "router")


class TestClean(unittest.TestCase):
    def test_strips_escapes(self):
        self.assertEqual(rmon.clean("\x1b[2Jboom"), "boom")
        self.assertEqual(rmon.clean("\x1b]0;evil\x07title"), "title")
        self.assertEqual(rmon.clean("a\x1bM b"), "a b")
        self.assertEqual(rmon.clean("x\x00\x07\x1f\x7fy"), "xy")
        self.assertEqual(rmon.clean("ok\x85end"), "okend")

    def test_line_breaks_become_visible(self):          # R1-B/F1 反轉後的鎖
        self.assertEqual(rmon.clean("a\nb"), "a\\nb")
        self.assertEqual(rmon.clean("a\rb"), "a\\rb")
        self.assertEqual(rmon.clean("a\tb"), "a b")
        self.assertNotIn("\n", rmon.clean("多餘\n換行"))
        self.assertNotIn("\r", rmon.clean("多餘\r換行"))

    def test_invisible_and_surrogates_stripped(self):    # R1-B/F3、F9
        self.assertEqual(rmon.clean("a‮b​c"), "abc")
        self.assertEqual(rmon.clean("x\ud800y"), "xy")

    def test_truncation_marked(self):
        out = rmon.clean("z" * 500)
        self.assertTrue(out.endswith("[截斷]"))
        self.assertEqual(len(out), rmon.TRUNC + len("[截斷]"))


class TestWidth(unittest.TestCase):
    def test_dw(self):
        self.assertEqual(rmon.dw("中文ab"), 6)
        self.assertEqual(rmon.dw(""), 0)

    def test_pad(self):
        self.assertEqual(rmon.dw(rmon.pad("中", 6, True)), 6)
        self.assertEqual(rmon.dw(rmon.pad("ab", 6, True)), 6)
        self.assertTrue(rmon.pad("很長很長很長", 2, True).startswith("很"))


class TestCfg(unittest.TestCase):
    def _cfg(self, obj):
        with open(rmon.cfg_path(), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return rmon.load_cfg()

    def test_missing_file_points_to_example(self):
        p = rmon.cfg_path()
        if os.path.exists(p):
            os.remove(p)
        with self.assertRaises(rmon.ConfigError) as cm:
            rmon.load_cfg()
        self.assertIn("monitor.json.example", str(cm.exception))

    def test_secret_names_rejected_token_boundary(self):
        for bad in ({"api_key": "x"}, {"token": "x"}, {"backend_secret": "x"},
                    {"keys": {}}, {"refresh token": "x"}):
            with self.assertRaises(rmon.ConfigError):
                self._cfg(bad)

    def test_names_keys_and_nesting_guarded(self):       # R1-B/F8
        with self.assertRaises(rmon.ConfigError):
            self._cfg({"names": {"api_key": "顯示名"}})
        with self.assertRaises(rmon.ConfigError):
            self._cfg({"names": {"b": {"api_key": 1}}})   # 巢狀物件=拒絕
        with self.assertRaises(rmon.ConfigError):
            self._cfg({"names": {"b": None}})             # 非純字串=拒絕

    def test_cfg_values_are_cleaned(self):               # R1-B/F6 植樁設定檔
        cfg = self._cfg({"host": "host\x1b[31mname", "names": {"a": "n\x1b[2Jo\nfake"}})
        self.assertEqual(cfg["host"], "hostname")
        self.assertNotIn("\x1b", cfg["names"]["a"])      # ESC 被剝
        self.assertNotIn("\n", cfg["names"]["a"])        # \n 轉可見形態,不落盤成真換行
        self.assertIn("\\n", cfg["names"]["a"])

    def test_port_really_lands_in_cfg(self):
        cfg = self._cfg({"host": "127.0.0.1", "port": 9187})
        self.assertEqual(cfg["port"], 9187)
        self.assertEqual(rmon.load_cfg()["port"], 9187)

    def test_port_bool_rejected(self):
        with self.assertRaises(rmon.ConfigError):
            self._cfg({"port": True})

    def test_keypad_not_killed(self):
        cfg = self._cfg({"keypad": "x"})
        self.assertEqual(cfg["port"], 8088)

    def test_unknown_ignored_with_warn_underscore_silent(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cfg = self._cfg({"_note": "註解", "future_field": 1, "host": "10.0.0.2"})
        self.assertEqual(cfg["host"], "10.0.0.2")
        out = buf.getvalue()
        self.assertIn("future_field", out)
        self.assertNotIn("_note", out)

    def test_validation(self):
        for bad in ({"port": 0}, {"port": "x"}, {"mode": "admin"}, {"names": []},
                    {"host": ""}, {"interval": "abc"}):
            with self.assertRaises(rmon.ConfigError):
                self._cfg(bad)
        cfg = self._cfg({"interval": 0.01})
        self.assertGreaterEqual(cfg["interval"], 0.5)


class TestNoLineForgery(unittest.TestCase):
    EVIL_ID = "ok\n● 在線 router v9.9.9 FORGED-LINE · ●帳目OK"

    def _pair(self, evil=True):
        bid = self.EVIL_ID if evil else "ok"
        snap = mk_stats(boxes=[mk_box(bid=bid)])
        model = rmon.build(snap, None, 1000.0)
        return render_text(model)

    def test_forged_line_cannot_add_rows(self):          # R1-B/F1
        clean_txt, evil_txt = self._pair(False), self._pair(True)
        self.assertEqual(evil_txt.count("\n"), clean_txt.count("\n"),
                         "惡意 id 讓輸出多了行 -- 整行偽造路徑未封")
        self.assertIn("FORGED-LINE", evil_txt)           # 內容仍在(誠實),但只能待在同一行內
        self.assertIn("\\n", evil_txt)                    # 且換行以可見形態顯示

    def test_zero_esc_canary(self):                      # R1-B:端對端零 ESC 金絲雀
        snap = mk_stats(version="\x1b[31m9.9", boxes=[
            mk_box(bid="a\r\n● FORGED", state="healthy‮x"),
            mk_box(bid="b", url=BOX_URL_PRIV, state="down\x00")])
        model = rmon.build(snap, None, 1000.0)
        txt = render_text(model, color=False)
        self.assertNotIn("\x1b", txt)
        self.assertNotIn("\x00", txt)
        for line in txt.split("\n"):
            self.assertFalse(line.startswith("FORGED"))


class TestPresence(unittest.TestCase):
    def test_empty_snapshot_never_fabricates(self):
        m = rmon.build({}, None, time.time())
        self.assertIsNone(m["requests"])
        self.assertIsNone(m["tok_s_est"])
        self.assertTrue(m["si_assumed"])
        self.assertEqual(m["boxes"], [])
        self.assertEqual(m["ledger"]["light"], "gray")
        self.assertIn("缺欄", m["ledger"]["why"])
        self.assertIn("預熱中", render_text(m))

    def test_v1213_shape_degrades_honestly(self):
        box = mk_box(require_idle=True, reported_age_s=60.0, v14=False, avg_ttfb=0.5)
        snap = mk_stats(version="1.2.13", boxes=[box], si=None, started=False)
        m = rmon.build(snap, None, time.time())
        self.assertTrue(m["si_assumed"])
        b = m["boxes"][0]
        self.assertIsNone(b["decode_tok_s"])
        self.assertIn("間隔假設1.0s", b["gate"])
        self.assertIn("盲", b["gate"])
        txt = render_text(m)
        self.assertIn("終身均值", txt)
        self.assertIn("含探測", txt)
        prev = mk_prev(m, ts=time.time() - 2)
        m2 = rmon.build(snap, prev, time.time())
        self.assertEqual(m2["ledger"]["light"], "motion")      # 靜止 2 拍:候補
        m3 = rmon.build(snap, mk_prev(m2, ts=time.time() - 2), time.time())
        self.assertEqual(m3["ledger"]["light"], "green")       # 連續 3 拍:轉綠

    def test_negative_uptime_is_none(self):              # R1-A/F14 時鐘後調
        snap = {"version": "1.2.15", "router": {}, "backends": [],
                "uptime_s": -45, "started_at": 1}
        m = rmon.build(snap, None, time.time())
        self.assertIsNone(m["uptime_s"])


class TestTokSEst(unittest.TestCase):
    def test_estimate_arithmetic(self):
        s1 = mk_stats(boxes=[mk_box(stats={"requests": 3, "bytes_out": 1000})],
                      now=1000.0, started=False)
        s2 = mk_stats(boxes=[mk_box(stats={"requests": 3, "bytes_out": 17000})],
                      now=1010.0, started=False)
        m0 = rmon.build(s1, None, 1000.0)
        self.assertIsNone(m0["tok_s_est"])
        m = rmon.build(s2, mk_prev(m0), 1010.0)
        self.assertEqual(m["tok_s_est"], 400.0)          # (17000-1000)/10/4
        self.assertIn("估算:字節/4", render_text(m))

    def test_negative_delta_dropped(self):
        box = mk_box(stats={"requests": 1, "bytes_out": 100})
        snap = mk_stats(requests=1, boxes=[box], started=False)
        prev = {"ts": 990.0, "ver": "1.2.14", "requests": 1, "ledger_total": 1,
                "boxes": [{"id": "local", "requests": 5, "bytes_out": 99999}]}
        m = rmon.build(snap, prev, 1000.0)
        self.assertIsNone(m["tok_s_est"])
        self.assertIsNone(m["boxes"][0]["dreq"])

    def test_instance_change_blocks_rate_via_version(self):
        box = mk_box(stats={"requests": 9, "bytes_out": 99000})
        snap = mk_stats(requests=9, boxes=[box], started=False)
        prev = {"ts": 990.0, "ver": "1.2.13", "requests": 1, "ledger_total": 1,
                "boxes": [{"id": "local", "requests": 1, "bytes_out": 10}]}
        m = rmon.build(snap, prev, 1000.0)
        self.assertEqual(m["instance"], "changed")
        self.assertIsNone(m["tok_s_est"])

    def test_instance_change_blocks_rate_via_started_at(self):   # R1-A/F7 C2 的正解
        box = mk_box(stats={"requests": 5, "bytes_out": 40000})
        snap = {"version": "1.2.14", "router": {"requests": 5}, "backends": [box],
                "started_at": 555, "status_interval": 1.0}
        prev = {"ts": 998.0, "ver": "1.2.14", "requests": 0, "started_at": 111,
                "ledger_total": 0, "boxes": [{"id": "local", "requests": 0, "bytes_out": 0}]}
        m = rmon.build(snap, prev, 1000.0)
        self.assertEqual(m["instance"], "changed")       # 同版本秒級重啟也抓得到
        self.assertIsNone(m["tok_s_est"])

    def test_started_at_drift_within_5s_is_not_a_restart(self):  # 現算型相容伺服器的漂移
        b1 = mk_box(stats={"requests": 3, "bytes_out": 1000})
        s1 = {"version": "1.2.14", "router": {"requests": 3}, "backends": [b1],
              "started_at": 900098, "status_interval": 1.0}
        m0 = rmon.build(s1, None, 1000.0)
        b2 = mk_box(stats={"requests": 3, "bytes_out": 17000})
        s2 = {"version": "1.2.14", "router": {"requests": 3}, "backends": [b2],
              "started_at": 900100, "status_interval": 1.0}   # 漂了 2s(每秒 +1 的相容實作)
        m = rmon.build(s2, mk_prev(m0, ts=1000.0), 1010.0)
        self.assertEqual(m["instance"], "same")
        self.assertEqual(m["tok_s_est"], 400.0)          # 估算腿不被漂移終身餓死

    def test_stale_span_rejected(self):
        box = mk_box(stats={"requests": 3, "bytes_out": 8000})
        snap = mk_stats(boxes=[box], started=False)
        prev = {"ts": 1.0, "ver": "1.2.14", "requests": 10, "ledger_total": 10,
                "boxes": [{"id": "local", "requests": 3, "bytes_out": 4000}]}
        m = rmon.build(snap, prev, 1000.0)
        self.assertIsNone(m["tok_s_est"])


class TestLedger(unittest.TestCase):
    def test_motion_then_green(self):                    # R2-C:綠需連續 3 拍靜止
        snap = mk_stats(requests=10, boxes=[])
        m1 = rmon.build(snap, None, 1000.0)
        self.assertEqual(m1["ledger"]["light"], "gray")   # 首拍無基準,不宣稱「運動中」
        self.assertIn("首拍", m1["ledger"]["why"])
        m2 = rmon.build(snap, mk_prev(m1, ts=998.0), 1000.0)
        self.assertEqual(m2["ledger"]["light"], "motion")  # 靜止 2 拍仍候補
        self.assertIn("第 3 拍", m2["ledger"]["why"])
        m3 = rmon.build(snap, mk_prev(m2, ts=998.0), 1000.0)
        self.assertEqual(m3["ledger"]["light"], "green")
        self.assertEqual(m3["ledger"]["delta"], 0)

    def test_stable_mismatch_red(self):
        terms = {"sticky_hits": 7}
        snap = mk_stats(requests=10, terms=terms)
        m1 = rmon.build(snap, None, 1000.0)
        m2 = rmon.build(snap, mk_prev(m1, ts=998.0), 1000.0)
        self.assertEqual(m2["ledger"]["light"], "red")
        self.assertEqual(m2["ledger"]["delta"], 3)
        self.assertIn("!!帳目失配", render_text(m2))

    def test_newer_router_downgrades_to_gray(self):
        snap = mk_stats(version="99.0.0", requests=10, terms={"sticky_hits": 7})
        m1 = rmon.build(snap, None, 1000.0)
        m2 = rmon.build(snap, mk_prev(m1, ts=998.0), 1000.0)
        self.assertEqual(m2["ledger"]["light"], "gray")
        self.assertIn("無法區分", m2["ledger"]["why"])    # 不替新版辯護成「疑似新增欄位」

    def test_missing_terms_gray_forever(self):
        snap = mk_stats(requests=10, drop=["migrations"])
        m1 = rmon.build(snap, None, 1000.0)
        m2 = rmon.build(snap, mk_prev(m1, ts=998.0), 1000.0)
        self.assertEqual(m2["ledger"]["light"], "gray")
        self.assertIn("缺欄", m2["ledger"]["why"])


class TestGate(unittest.TestCase):
    def _gate(self, age, si, require=True):
        box = mk_box(require_idle=require, reported_age_s=age)
        m = rmon.build(mk_stats(boxes=[box], si=si), None, 1000.0)
        return m["boxes"][0]["gate"]

    def test_never_reported_fail_closed(self):
        g = self._gate(None, 1.0)
        self.assertIn("從未證明空閒", g)
        self.assertIn("fail-closed", g)

    def test_blind_window(self):
        self.assertIn("盲", self._gate(30.0, 1.0))
        self.assertIn("開:可證空閒", self._gate(2.0, 1.0))
        self.assertIn("開:可證空閒", self._gate(25.0, 10.0))

    def test_not_required(self):
        self.assertIsNone(self._gate(30.0, 1.0, require=False))


class TestBorrow(unittest.TestCase):
    def _b(self, ext, url, age=1.0):
        box = mk_box(url=url, ext_streak=ext, reported_age_s=age)
        m = rmon.build(mk_stats(boxes=[box]), None, 1000.0)
        return m["boxes"][0]["borrow"]

    def test_two_ticks_loopback_fresh_is_estimate(self):
        self.assertIn("估計", self._b(2, "http://127.0.0.1:8081/v1"))

    def test_remote_box_no_pointing(self):
        self.assertIsNone(self._b(2, BOX_URL_PRIV))

    def test_single_tick_unconfirmed(self):
        self.assertIn("未確認", self._b(1, "http://127.0.0.1:8081/v1"))


class TestReplay(unittest.TestCase):
    def _write(self, name, text):
        p = os.path.join(_TMP, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def test_single_json(self):
        p = self._write("one.json", json.dumps(mk_stats(boxes=[mk_box()])))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rmon.do_replay(base_cfg(), p, color=False)
        self.assertIn("REPLAY 回放", buf.getvalue())

    def test_jsonl_sequence_and_junk(self):
        lines = []
        for i in (1, 2, 3):
            box = mk_box(stats={"requests": i, "bytes_out": 1000 + 4000 * i})
            lines.append(json.dumps(mk_stats(requests=i, boxes=[box], started=False)))
        text = lines[0] + "\n(這行是垃圾)\n\n" + "\n".join(lines[1:])
        p = self._write("seq.jsonl", text)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rmon.do_replay(base_cfg(), p, color=False)
        out = buf.getvalue()
        self.assertIn("回放 3 拍", out)
        self.assertIn("估算:字節/4", out)

    def test_garbage_only_exits(self):
        p = self._write("bad.json", "not json at all\nnor this\n")
        with self.assertRaises(SystemExit):
            rmon.do_replay(base_cfg(), p, color=False)


class TestDiagnoseScrub(unittest.TestCase):
    def _diag(self, full=False):
        snap = mk_stats(boxes=[mk_box(bid="local", url=BOX_URL_PRIV),
                               mk_box(bid="remote", url="http://127.0.0.1:18081/v1")])
        old = rmon.fetch
        rmon.fetch = lambda cfg: snap
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rmon.do_diagnose(base_cfg(), full=full)
            return buf.getvalue()
        finally:
            rmon.fetch = old

    def test_default_scrubs_urls_ids_and_target(self):   # R1-A/B/F5
        out = self._diag()
        self.assertNotIn("203.0.113.71", out)
        self.assertIn("box-A", out)
        self.assertIn("box-B", out)
        self.assertIn('"target_kind"', out)
        self.assertNotIn('"target"', out)
        self.assertNotIn(":9", out)                      # cfg port 不得外洩

    def test_full_keeps_target_and_url(self):
        out = self._diag(full=True)
        self.assertIn("203.0.113.71", out)
        self.assertIn('"target"', out)


class TestNoWebSurface(unittest.TestCase):               # 使用者指示:一切在 terminal,不要網頁
    def _src(self, name):
        with open(os.path.join(HERE, name), "r", encoding="utf-8") as fh:
            return fh.read()

    def test_no_browser_or_html_anywhere(self):
        for name in ("rmon.py", "launch.py"):
            src = self._src(name)
            self.assertNotIn("webbrowser", src)
            self.assertNotIn("import html", src)
            self.assertNotIn("<!doctype", src.lower())
            for node in ast.walk(ast.parse(src, name)):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        self.assertNotIn(a.name.split(".")[0], ("html", "webbrowser"))

    def test_page_command_rejected(self):
        with self.assertRaises(SystemExit):              # argparse choices 裡已無 page
            rmon.main(["page"])


class TestCache(unittest.TestCase):
    def test_roundtrip_and_target_isolation(self):       # R1-A/F6 分流不再互砸
        a, b = base_cfg(), base_cfg()
        a["port"], b["port"] = 11111, 22222
        ma = rmon.build(mk_stats(boxes=[mk_box()]), None, 100.0)
        mb = rmon.build(mk_stats(boxes=[mk_box()]), None, 200.0)
        rmon.cache_save(a, ma)
        rmon.cache_save(b, mb)
        self.assertEqual(rmon.cache_load(a)["ts"], 100.0)   # 交替目標後 A 快取還在
        self.assertEqual(rmon.cache_load(b)["ts"], 200.0)

    def test_corrupt_cache_ignored(self):
        os.makedirs(rmon.state_dir(), exist_ok=True)
        with open(rmon._cache_file(base_cfg()), "w") as fh:
            fh.write("{corrupt")
        self.assertIsNone(rmon.cache_load(base_cfg()))


class TestFetch(unittest.TestCase):
    def test_refused_classified(self):
        cfg = base_cfg()
        cfg["port"] = closed_port()
        with self.assertRaises(rmon.Dead) as cm:
            rmon.fetch(cfg)
        self.assertIn(cm.exception.kind, ("refused", "timeout"))

    def test_dns_classified_separately(self):            # R1-A/F8
        cfg = {"host": "no-such-host-should-not-resolve.invalid", "port": 80,
               "mode": "friend", "names": {}, "interval": 2.0}
        with self.assertRaises(rmon.Dead) as cm:
            rmon.fetch(cfg)
        self.assertEqual(cm.exception.kind, "dns")

    def test_garbage_http_is_dead_not_traceback(self):   # R1-B/F4
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        stop = threading.Event()

        def serve():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    c.sendall(b"NOT-HTTP 9.9\r\n\r\n")
                except OSError:
                    pass
                finally:
                    c.close()
        threading.Thread(target=serve, daemon=True).start()
        cfg = base_cfg()
        cfg["port"] = srv.getsockname()[1]
        try:
            for _ in range(3):   # 常駐聆聽可重複接;timeout 只可能是首次啟程抖動
                with self.assertRaises(rmon.Dead) as cm:
                    rmon.fetch(cfg)
                if cm.exception.kind != "timeout":
                    break
            self.assertIn(cm.exception.kind, ("http", "reset", "decode"))
        finally:
            stop.set()
            srv.close()

    def test_control_char_host_is_dead_not_traceback(self):
        cfg = base_cfg()
        cfg["host"] = "127.0.0.1\nEVIL"
        with self.assertRaises(rmon.Dead):
            rmon.http_get_safe(cfg["host"], cfg["port"], "/x", 1.0)

    def test_win_aborted_is_reset_not_refused(self):     # WSAECONNABORTED 開對藥方
        e = OSError("aborted")
        e.winerror = 10053
        self.assertEqual(rmon._classify(e), "reset")
        e2 = ConnectionRefusedError(10061, "refused")
        self.assertEqual(rmon._classify(e2), "refused")


class TestRenderDead(unittest.TestCase):
    def test_all_kinds_get_one_line_guidance(self):      # R1-A/F8
        for kind in rmon.GUIDE:
            lines = rmon.render({}, base_cfg(), dead=rmon.Dead(kind, "x"))
            self.assertLessEqual(len(lines), 3)
            self.assertTrue(any(kind in ln or "摸不到" in ln for ln in lines))


class TestVerFmt(unittest.TestCase):
    def test_ver(self):
        self.assertGreater(rmon._ver("1.2.14"), (1, 2, 13))
        self.assertEqual(rmon._ver("1.2.14rc1"), (1, 2, 14))
        self.assertEqual(rmon._ver(""), ())

    def test_fmt_dur(self):
        self.assertEqual(rmon.fmt_dur(45), "45s")
        self.assertEqual(rmon.fmt_dur(125), "2m05s")
        self.assertEqual(rmon.fmt_dur(7260), "2h01m")


class TestVersionStripped(unittest.TestCase):
    def test_router_version_string_sanitized(self):
        m = rmon.build(mk_stats(version="\x1b[2Jboom", boxes=[]), None, 1000.0)
        self.assertEqual(m["router_ver"], "boom")
        self.assertNotIn("\x1b", render_text(m))


class TestStartBat(unittest.TestCase):                   # R1-A/F4
    def test_ascii_and_crlf(self):
        with open(os.path.join(HERE, "!-start.bat"), "rb") as fh:
            raw = fh.read()
        self.assertTrue(all(b < 0x80 for b in raw), "bat 必須純 ASCII")
        self.assertIn(b"\r\n", raw)
        self.assertNotIn(b"/dev/null", raw)              # batch 的/dev/null 是地雷
        self.assertIn(b">nul", raw)


class TestLaunchShell(unittest.TestCase):
    def test_pid_alive_facts(self):
        self.assertTrue(launch.pid_alive(os.getpid()))
        self.assertFalse(launch.pid_alive(None))
        self.assertFalse(launch.pid_alive(-1))
        self.assertFalse(launch.pid_alive(0x7FFFFF00))

    def test_char_device_stdin_is_not_a_terminal(self):   # M3-B/P2-1
        # NUL 字元裝置過得了 isatty、過不了 console 偵測。假 stdin 宣稱 True 時,
        # _stdin_tty 必須回到偵測的原始事實:_redirected 測試下兩者同 False(== NUL
        # 世界,即修複生效),真終端下兩者同 True -- 斷言對兩種環境都成立。
        saved = sys.stdin
        try:
            sys.stdin = type("NulStdin", (), {"isatty": lambda s: True})()
            self.assertEqual(launch._stdin_tty(), launch._console_input_attached())
        finally:
            sys.stdin = saved

    def test_router_dir_env_override(self):
        old = os.environ.get("STRATA_ROUTER_DIR")
        os.environ["STRATA_ROUTER_DIR"] = _TMP
        try:
            self.assertEqual(launch.router_dir(), _TMP)
        finally:
            if old is None:
                os.environ.pop("STRATA_ROUTER_DIR", None)
            else:
                os.environ["STRATA_ROUTER_DIR"] = old

    # ---- merge-1 定位器:monorepo 的 ../router 優先,舊姊妹 strata-router 保留 fallback
    def test_router_dir_merged_prefers_sibling_router_package(self):
        root = os.path.join(_TMP, "mergedrepo")
        mon = os.path.join(root, "monitor")
        merged = os.path.join(root, "router")
        legacy = os.path.join(root, "strata-router")
        for d in (mon, merged, legacy):
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "router.py") if d != mon else os.path.join(d, "rmon.py"),
                      "w", encoding="utf-8") as fh:
                fh.write("# fixture\n")
        old = os.environ.pop("STRATA_ROUTER_DIR", None)
        real = rmon.my_dir
        try:
            rmon.my_dir = lambda: mon
            self.assertEqual(launch.router_dir(), merged)   # BOTH exist -> merged wins
            os.unlink(os.path.join(merged, "router.py"))
            self.assertEqual(launch.router_dir(), legacy)   # merged empty -> legacy fallback
            os.unlink(os.path.join(legacy, "router.py"))
            self.assertEqual(launch.router_dir(), legacy)   # neither -> legacy hint (message-stable)
        finally:
            rmon.my_dir = real
            if old is not None:
                os.environ["STRATA_ROUTER_DIR"] = old

    def test_router_dir_env_beats_merged_layout(self):
        root = os.path.join(_TMP, "mergedrepo2")
        mon = os.path.join(root, "monitor")
        merged = os.path.join(root, "router")
        for d in (mon, merged):
            os.makedirs(d, exist_ok=True)
        with open(os.path.join(merged, "router.py"), "w", encoding="utf-8") as fh:
            fh.write("# fixture\n")
        real = rmon.my_dir
        old = os.environ.get("STRATA_ROUTER_DIR")
        try:
            rmon.my_dir = lambda: mon
            os.environ["STRATA_ROUTER_DIR"] = _TMP
            self.assertEqual(launch.router_dir(), _TMP)     # env still rules the monorepo
        finally:
            rmon.my_dir = real
            if old is None:
                os.environ.pop("STRATA_ROUTER_DIR", None)
            else:
                os.environ["STRATA_ROUTER_DIR"] = old

    def test_healthz_down_never_raises(self):            # R1-A/F1
        cfgp = rmon.cfg_path()
        with open(cfgp, "w", encoding="utf-8") as fh:
            json.dump({"host": "127.0.0.1", "port": closed_port()}, fh)
        alive, ver, kind = launch.healthz(timeout=1.0)
        self.assertFalse(alive)
        self.assertIn(kind, ("refused", "timeout", "dns", "reset", "http"))

    def test_pid_identity_three_factors(self):           # R1-A/F2 + R1-B/F7
        launch.write_pid(os.getpid(), target="127.0.0.1:8088")
        rec = launch.read_pid()
        self.assertIsInstance(rec, dict)
        self.assertEqual(rec.get("target"), "127.0.0.1:8088")   # 刀0:血統必須帶目標
        self.assertTrue(launch.pid_matches(rec))          # 自己:活+時間對+python 映像
        self.assertFalse(launch.pid_matches({"pid": os.getpid(), "created": 1}))
        self.assertFalse(launch.pid_matches({"pid": os.getpid()}))   # 舊格式=不給殺
        self.assertFalse(launch.pid_matches(None))

    def test_ask_eof_is_no(self):                        # R1-A/F9
        real = builtins.input

        def boom(*a):
            raise EOFError()
        builtins.input = boom
        try:
            self.assertEqual(launch._ask("y/N: "), "n")
        finally:
            builtins.input = real

    def test_start_passes_config_file_when_present(self):   # 切版前實測缺口:--config 無預設值
        fake = os.path.join(_TMP, "fakerouter3")
        os.makedirs(fake, exist_ok=True)
        with open(os.path.join(fake, "router.py"), "w", encoding="utf-8") as fh:
            fh.write("VERSION = '9.9.9'\n")
        with open(os.path.join(fake, "router.json"), "w", encoding="utf-8") as fh:
            fh.write('{"NEVER": "READ-SENTINEL"}')
        captured = {}

        class FakePopen:
            def __init__(self, cmd, **kw):
                captured["cmd"] = list(cmd)
                captured["cwd"] = kw.get("cwd")
                self.pid = os.getpid()
        state = {"n": 0}

        def hz(timeout=2.0):
            state["n"] += 1
            return (False, None, "refused") if state["n"] == 1 else (True, "9.9.9", "http200")
        real = (launch.subprocess, launch.healthz, launch.healthz_local)
        old_env = os.environ.get("STRATA_ROUTER_DIR")
        os.environ["STRATA_ROUTER_DIR"] = fake
        launch.subprocess = type("S", (), {
            "Popen": FakePopen,
            "DEVNULL": -3,
            "call": staticmethod(lambda *a, **k: 0)})
        launch.healthz = hz
        launch.healthz_local = lambda port, timeout=2.0: True
        real_owner = launch.port_owner_pid
        launch.port_owner_pid = lambda port: os.getpid()   # 自家子=本測試程序
        real_hzat = launch.healthz_at
        launch.healthz_at = lambda cfg, timeout=2.0: (False, None, "refused")
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = launch.do_start(assume_yes=True)
            out = buf.getvalue()
        finally:
            launch.subprocess, launch.healthz, launch.healthz_local = real
            launch.port_owner_pid = real_owner
            launch.healthz_at = real_hzat
            if old_env is None:
                os.environ.pop("STRATA_ROUTER_DIR", None)
            else:
                os.environ["STRATA_ROUTER_DIR"] = old_env
            launch.clear_pid()
        self.assertEqual(rc, 0)
        self.assertIn("--config", captured["cmd"])
        self.assertEqual(captured["cmd"][captured["cmd"].index("--config") + 1],
                         os.path.join(fake, "router.json"))
        self.assertNotIn("READ-SENTINEL", out)              # 存在檢查 ≠ 內容讀取

    def test_check_cfg_never_reads_secrets(self):
        fake = os.path.join(_TMP, "fakerouter")
        os.makedirs(fake, exist_ok=True)
        with open(os.path.join(fake, "router.py"), "w", encoding="utf-8") as fh:
            fh.write('# x\nVERSION = "9.9.9"\n')
        with open(os.path.join(fake, "router.keys.json"), "w", encoding="utf-8") as fh:
            fh.write('{"dummy": "TOPSECRET-NOT-A-REAL-KEY"}')
        with open(os.path.join(fake, "router.json"), "w", encoding="utf-8") as fh:
            fh.write('{"NEVER": "READ-THIS-SENTINEL"}')
        old = os.environ.get("STRATA_ROUTER_DIR")
        os.environ["STRATA_ROUTER_DIR"] = fake
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                launch.check_cfg()
            out = buf.getvalue()
        finally:
            if old is None:
                os.environ.pop("STRATA_ROUTER_DIR", None)
            else:
                os.environ["STRATA_ROUTER_DIR"] = old
        self.assertIn("9.9.9", out)
        self.assertNotIn("NOT-A-REAL-KEY", out)
        self.assertNotIn("READ-THIS-SENTINEL", out)
        self.assertIn("內容未讀", out)


class TestCacheAtomicity(unittest.TestCase):             # R1-B/F3 改盯 cache 路徑(page 已移除)
    def test_surrogate_and_tmp_residue_free(self):
        snap = mk_stats(boxes=[mk_box(bid="x\ud800y")])
        m = rmon.build(snap, None, time.time())
        cfg = base_cfg()
        rmon.cache_save(cfg, m)                          # 半代字元在 cache 裡不許炸
        self.assertIsNotNone(rmon.cache_load(cfg))
        leftovers = [n for n in os.listdir(rmon.state_dir()) if ".tmp" in n]
        self.assertEqual(leftovers, [])


class TestRound2Locks(unittest.TestCase):                # 第二輪 2×2(資料誠實 C + 演化相容 D)
    # ---- C-P2:禮讓閘以 router 的 accepting 為首訊號
    def _gate_of(self, **kw):
        box = mk_box(**kw)
        m = rmon.build(mk_stats(boxes=[box]), None, 1000.0)
        return m["boxes"][0]

    def test_refusing_box_cannot_claim_open(self):
        b = self._gate_of(accepting=False, ext_streak=3, reported_age_s=0.5,
                          require_idle=True)
        self.assertTrue(b["gate"].startswith("關:router 現正拒絕放置"))
        self.assertIn("ext_streak", b["gate_ev"] or "")
        self.assertNotIn("開", b["gate"])                  # 「閘開」+「借用量」同框的矛盾封死

    def test_accepting_unknown_fails_closed(self):
        b = self._gate_of(accepting=None, reported_age_s=0.5, require_idle=True)
        self.assertIn("問不到", b["gate"])

    def test_open_gate_tags_assumed_interval(self):        # D-P3-1:「開」也要帶假設標
        box = mk_box(require_idle=True, reported_age_s=2.0)
        m = rmon.build(mk_stats(boxes=[box], si=None, started=False), None, 1000.0)
        g = m["boxes"][0]["gate"]
        self.assertIn("開:可證空閒", g)
        self.assertIn("間隔假設1.0s", g)

    # ---- C-P2:形態壞 cache 不得讓 build 吐 traceback
    def test_cache_shape_validation(self):
        os.makedirs(rmon.state_dir(), exist_ok=True)
        p = rmon._cache_file(base_cfg())
        for bad in ('{"ts":1,"boxes":[123]}', '{"ts":"x","boxes":[]}', '[1,2]',
                    '{"ts":1,"boxes":{"a":1}}'):
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(bad)
            self.assertIsNone(rmon.cache_load(base_cfg()), bad)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write('{"ts":1.0,"boxes":[]}')
        self.assertIsInstance(rmon.cache_load(base_cfg()), dict)

    # ---- C-P3:inflight 缺欄 => 總數只能宣稱「至少」
    def test_inflight_unknown_shows_at_least(self):
        b2 = mk_box(bid="remote2")
        b2.pop("inflight")
        m = rmon.build(mk_stats(boxes=[mk_box(inflight=3), b2]), None, 1000.0)
        self.assertEqual(m["inflight_unknown"], 1)
        txt = render_text(m)
        self.assertIn("≥3 個請求在飛(1 盒未知)", txt)

    # ---- C-P3:dreq 與 est 共用時間尺,一天前的差值不配叫「本窗」
    def test_dreq_respects_time_gate(self):
        s1 = mk_stats(boxes=[mk_box(stats={"requests": 3, "bytes_out": 1000})],
                      now=1000.0, started=False)
        m0 = rmon.build(s1, None, 1000.0)
        s2 = mk_stats(boxes=[mk_box(stats={"requests": 12, "bytes_out": 9000})],
                      now=4620.0, started=False)
        m_stale = rmon.build(s2, mk_prev(m0, ts=1000.0), 4620.0)   # 跨度 3620s
        self.assertIsNone(m_stale["boxes"][0]["dreq"])
        self.assertIsNone(m_stale["tok_s_est"])
        m_fresh = rmon.build(s2, mk_prev(m0, ts=4610.0), 4620.0)   # 跨度 10s
        self.assertEqual(m_fresh["boxes"][0]["dreq"], 9)

    # ---- C-P3:帳目「型別不符」不冒充「缺欄」;無 bytes_out 不裝「預熱中」
    def test_wrong_type_terms_wording(self):
        snap = mk_stats(terms={"migrations": 1.5})
        m = rmon.build(snap, None, 1000.0)
        self.assertEqual(m["ledger"]["light"], "gray")
        self.assertIn("型別不符", m["ledger"]["why"])
        self.assertNotIn("缺欄", m["ledger"]["why"])

    def test_no_bytes_leg_wording(self):
        snap = mk_stats(boxes=[mk_box(stats={"requests": 1})])
        prev = {"ts": 998.0, "ver": "1.2.14", "requests": 10, "boxes": []}
        m = rmon.build(snap, prev, 1000.0)
        self.assertTrue(m["no_bytes_leg"])
        self.assertIn("無此欄", render_text(m))

    # ---- C-P3:空置盒的 decode 殘值要標「上一單」
    def test_decode_residual_label(self):
        idle = mk_box(reported={"serving": 0.0, "queued": 0.0, "decode_tok_s": 45.2,
                                "box_uptime_s": 1, "gpu_util_pct": 0}, v14=False)
        busy = mk_box(reported={"serving": 1.0, "queued": 0.0, "decode_tok_s": 40.0,
                                "box_uptime_s": 1, "gpu_util_pct": 9}, v14=False)
        t1 = render_text(rmon.build(mk_stats(boxes=[idle]), None, 1000.0))
        t2 = render_text(rmon.build(mk_stats(boxes=[busy]), None, 1000.0))
        self.assertIn("上一單 45.2 tok/s(盒實測,現空置)", t1)
        self.assertIn("生成 40 tok/s(盒實測)", t2)

    # ---- D-P2:_ver 帶前綴
    def test_ver_strips_prefix(self):
        self.assertEqual(rmon._ver("v2.0.0"), (2, 0, 0))
        self.assertGreater(rmon._ver("v2.0.0"), rmon.SCHEMA_KNOWN_MAX)
        self.assertEqual(rmon._ver(""), ())

    # ---- router v1.2.16/v1.2.17 同步:帳目終端第 11 項 passthrough_gets;
    #      v1.2.17 無終端增減(修的是 score 同調/清洗補角/日誌/鑰鎖),TERMS 不變、SCHEMA 抬版
    def test_terms_synced_with_router_1_2_17(self):
        self.assertEqual(len(TERMS), 11)
        self.assertIn("passthrough_gets", TERMS)
        self.assertGreaterEqual(rmon.SCHEMA_KNOWN_MAX, (1, 2, 17))

    # ---- D-P3:幽魂 cache 回收
    def test_cache_gc_90d(self):
        os.makedirs(rmon.state_dir(), exist_ok=True)
        ghost = os.path.join(rmon.state_dir(), "rmon-cache-ffffffffffff.json")
        with open(ghost, "w") as fh:
            fh.write("{}")
        old = time.time() - 91 * 86400
        os.utime(ghost, (old, old))
        keep = os.path.join(rmon.state_dir(), "rmon-cache-eeeeeeeeeeee.json")
        with open(keep, "w") as fh:
            fh.write("{}")
        rmon._gc_caches(rmon._cache_file(base_cfg()))
        self.assertFalse(os.path.exists(ghost), "91 天幽魂檔應回收")
        self.assertTrue(os.path.exists(keep), "新檔不准動")
        os.remove(keep)

    # ---- P1 補網:show_procs 煙霧(R1 崩潰 regression lock)+ 身分標籤
    def test_show_procs_smoke_and_identity_tag(self):
        old_procs, old_pid, old_match = launch.py_procs, launch.read_pid, launch.pid_matches
        launch.py_procs = lambda: [
            {"ProcessId": 123, "ParentProcessId": 1, "CommandLine": "py -3 router.py"},
            {"ProcessId": 999, "ParentProcessId": 1, "CommandLine": None},
        ]
        launch.read_pid = lambda: {"pid": 999, "created": 5}
        launch.pid_matches = lambda rec: False       # 999 活著但身分不符
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                launch.show_procs()                  # 舊版此處必 TypeError(R2-C P1)
            out = buf.getvalue()
        finally:
            launch.py_procs, launch.read_pid, launch.pid_matches = old_procs, old_pid, old_match
        self.assertIn("router.py", out)
        self.assertIn("身分未核可", out)
        self.assertNotIn("本殼記錄的 router<", out)


class TestConsoleFlow(unittest.TestCase):               # 使用者指示:同窗一條龍
    def setUp(self):
        self._undo = []
        p = rmon.cfg_path()
        self._cfg_backup = None
        if os.path.exists(p):
            with open(p, "rb") as fh:
                self._cfg_backup = fh.read()

    def _patch(self, alive, ver=None, kind=None):
        self._undo = []

        def setp(obj, name, val):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, val)

        class Box:
            n_start = 0
            live_calls = []

        def fake_start(assume_yes=False):
            Box.n_start += 1
            return 0

        def fake_live(cfg, interval, color, watch=None):   # 刀4 簽名跟進(watch 單鉤子)
            Box.live_calls.append((cfg["host"], cfg["port"]))
            return 0

        setp(launch, "healthz", lambda timeout=2.0: (alive, ver, kind))
        setp(launch, "do_start", fake_start)
        setp(launch.rmon, "do_live", fake_live)
        setp(launch, "_stdin_tty", lambda: True)   # 本類測「真終端」路徑;非 tty 另有專測
        return Box

    def tearDown(self):
        for obj, name, val in self._undo:
            setattr(obj, name, val)
        p = rmon.cfg_path()                     # cfg 檔還原:不污染後續測試的預設態
        if self._cfg_backup is None:
            try:
                os.remove(p)
            except OSError:
                pass
        else:
            with open(p, "wb") as fh:
                fh.write(self._cfg_backup)

    def _cfgfile(self, host):
        with open(rmon.cfg_path(), "w", encoding="utf-8") as fh:
            json.dump({"host": host, "port": 9187}, fh)

    def test_alive_skips_start_and_lives(self):
        B = self._patch(True, "1.2.15", "http200")
        self._cfgfile("127.0.0.1")
        launch.run_console()
        self.assertEqual(B.n_start, 0)
        self.assertEqual(len(B.live_calls), 1)

    def test_dead_loopback_auto_starts_then_lives(self):
        B = self._patch(False, kind="refused")
        self._cfgfile("127.0.0.1")
        old = os.environ.get("STRATA_ROUTER_DIR")
        fake = os.path.join(_TMP, "fakerouter2")
        os.makedirs(fake, exist_ok=True)
        with open(os.path.join(fake, "router.py"), "w", encoding="utf-8") as fh:
            fh.write("VERSION = '9.9.9'\n")
        os.environ["STRATA_ROUTER_DIR"] = fake
        try:
            launch.run_console()
        finally:
            if old is None:
                os.environ.pop("STRATA_ROUTER_DIR", None)
            else:                                # 雙向還原:外部已設的值不得洩漏給後續測
                os.environ["STRATA_ROUTER_DIR"] = old
        self.assertEqual(B.n_start, 1)                 # 本機目標:自動起
        self.assertEqual(len(B.live_calls), 1)         # 面板照掛,死活由面板誠實回報

    def test_remote_target_never_starts_local(self):   # A-F10 幽靈 router 防線延伸
        B = self._patch(False, kind="timeout")
        self._cfgfile("203.0.113.71")
        launch.run_console()
        self.assertEqual(B.n_start, 0)                 # 遠端摸不到 != 本機要起一台
        self.assertEqual(len(B.live_calls), 1)

    def test_non_tty_stdin_falls_to_single_shot(self):  # R3-P2-2:管線/排程永不掛死
        B = self._patch(False, kind="refused")
        self._cfgfile("127.0.0.1")
        launch._stdin_tty = lambda: False               # 覆蓋 _patch 的 tty=True(undo 記的是原函式)
        calls = []
        self._undo.append((launch, "_run_rmon", launch._run_rmon))
        launch._run_rmon = lambda args: calls.append(list(args))
        launch.run_console()
        self.assertEqual(B.live_calls, [])              # 常駐面板永不進入(q 在管線下永按不出)
        self.assertEqual(calls, [["once"]])             # 單拍 + 選單(EOF 自退),不會 rc=124

    def test_ctrl_c_during_start_returns_clean(self):   # R3-P3-5:等上線期間 Ctrl+C 不裸 traceback
        B = self._patch(False, kind="refused")
        self._cfgfile("127.0.0.1")
        # M2-B/P2-1:run_console 只有在找得到 router.py 時才會碰 do_start --
        # 自給 fake 佈局,本測在「純 monitor 副本」下也必須綠(比照隣測)。
        old = os.environ.get("STRATA_ROUTER_DIR")
        fake = os.path.join(_TMP, "fakerouter3")
        os.makedirs(fake, exist_ok=True)
        with open(os.path.join(fake, "router.py"), "w", encoding="utf-8") as fh:
            fh.write("VERSION = '9.9.9'\n")
        os.environ["STRATA_ROUTER_DIR"] = fake

        def boom(assume_yes=False):
            raise KeyboardInterrupt()
        launch.do_start = boom                          # _undo 已記真原函式,tearDown 會還原
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = launch.run_console()               # 舊版此處直接拋穿 -> traceback rc=1
        finally:
            if old is None:
                os.environ.pop("STRATA_ROUTER_DIR", None)
            else:
                os.environ["STRATA_ROUTER_DIR"] = old
        self.assertEqual(rc, 0)
        self.assertIn("中斷", buf.getvalue())
        self.assertEqual(B.live_calls, [])


class TestRound3Locks(unittest.TestCase):               # 第三輪 R3 紅隊(ops lens)
    def test_cache_top_level_ints_rejected(self):       # R3-P2-1:壞 cache 永不自癒的洞
        os.makedirs(rmon.state_dir(), exist_ok=True)
        p = rmon._cache_file(base_cfg())
        for bad in ('{"ts":1.0,"ver":"1.2.15","requests":"oops","boxes":[]}',
                    '{"ts":1.0,"boxes":[],"started_at":"x"}',
                    '{"ts":1.0,"boxes":[],"ledger_streak":true}',
                    '{"ts":1.0,"boxes":[],"ledger_total":"10"}',
                    '{"ts":true,"boxes":[]}'):
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(bad)
            self.assertIsNone(rmon.cache_load(base_cfg()), bad)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write('{"ts":1.0,"boxes":[],"requests":10,"started_at":5,'
                     '"ledger_total":10,"ledger_streak":1}')
        self.assertIsInstance(rmon.cache_load(base_cfg()), dict)

    def test_gate_ev_reaches_screen_and_diagnose(self):  # R3-P3-1:原因不準是死資料
        box = mk_box(bid="peer", url="http://203.0.113.71:18443/v1", accepting=False,
                     require_idle=True, ext_streak=3, reported_age_s=0.5)
        txt = render_text(rmon.build(mk_stats(boxes=[box]), None, 1000.0))
        self.assertIn("關:router 現正拒絕放置", txt)
        self.assertIn("ext_streak=3", txt)               # 遠端盒無 borrow 行也看得到「為什麼」
        self.assertIn("非經本 router", txt)
        with open(os.path.join(rmon.my_dir(), "rmon.py"), "r", encoding="utf-8") as fh:
            src = fh.read()
        seg = src[src.index("def do_diagnose"):src.index("def _replay_ticks")]
        self.assertIn("gate_ev", seg)                    # diagnose JSON 也帶原因

    def test_ttfb_missing_fields_never_prints_nones(self):   # R3-P3-2
        b1 = mk_box()
        b1.pop("recent_ttfb_avg_s")
        b1["avg_ttfb_s"] = 2.0
        t1 = render_text(rmon.build(mk_stats(boxes=[b1]), None, 1000.0))
        self.assertNotIn("avg None", t1)
        self.assertIn("終身均值", t1)                    # avg 整個缺 -> 退終身腿(帶含探測標)
        b2 = mk_box()
        b2.pop("recent_ttfb_p95_s")
        t2 = render_text(rmon.build(mk_stats(boxes=[b2]), None, 1000.0))
        self.assertIn("近期首字 avg 1.2s / p95 ?", t2)   # 缺的欄問號,不編數
        self.assertNotIn("p95 None", t2)

    def test_decode_serving_none_is_not_busy(self):     # R3-P3-3:None != 非0=在忙
        box = mk_box(reported={"decode_tok_s": 50.0}, v14=False)
        txt = render_text(rmon.build(mk_stats(boxes=[box]), None, 1000.0))
        self.assertIn("最近實測 50 tok/s(盒實測,忙閒未知)", txt)
        self.assertNotIn("生成 50", txt)

    def test_run_rmon_flushes_before_child(self):      # R3-b NEW-P3:重導向時父橫幅不许落后
        with open(os.path.join(launch.rmon.my_dir(), "launch.py"), "r", encoding="utf-8") as fh:
            src = fh.read()
        seg = src[src.index("def _run_rmon"):src.index("def menu")]
        self.assertLess(seg.index("sys.stdout.flush()"), seg.index("subprocess.call"))

    def test_cfg_fallback_announces_itself(self):       # R3-P3-4:默認直連生產 port 要先宣告
        old_cfg_env = os.environ.get("RMON_CONFIG")
        old_flag, old_hz = launch._cfg_default_warned, launch.healthz
        launch.healthz = lambda timeout=2.0: (False, None, "refused")   # 絕不真連 8088(生產紅線)
        os.environ["RMON_CONFIG"] = os.path.join(_TMP, "no-such-dir", "monitor.json")
        launch._cfg_default_warned = False
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                launch.status_lines()
            out = buf.getvalue()
        finally:
            launch._cfg_default_warned = old_flag
            launch.healthz = old_hz
            if old_cfg_env is None:
                os.environ.pop("RMON_CONFIG", None)
            else:
                os.environ["RMON_CONFIG"] = old_cfg_env
        self.assertIn("monitor.json 缺失/損壞", out)
        self.assertIn("127.0.0.1:8088", out)


class TestFrameEngine(unittest.TestCase):
    """v0.2.0 固定框引擎(裁決 P1 §7):絕對歸位、寬度、SGR、攤平。
    io.StringIO 直測,零 port、零真實 console、layout-free(純副本可重放)。"""

    def _rmon_src(self):
        with open(os.path.join(HERE, "rmon.py"), "r", encoding="utf-8") as fh:
            return fh.read()

    def test_abs_home_no_relative_up(self):
        # 行為鎖:框輸出流裡任何相對游標移動(ESC[<n>A/B)都禁止;絕對歸位必在場
        buf = io.StringIO()
        fr = rmon._Frame(out=buf)
        fr.draw(["alpha", "beta"])
        fr.draw(["gamma"])
        out = buf.getvalue()
        self.assertIn("\x1b[H", out)
        # \d* 不是 \d+:ECMA-48 的無參數形 ESC[A(預設=1)也是相對游標移動
        # (round-1/A-P2-2 修復:雙鎖同刀,無參數形不得從牙縫溜過)
        self.assertNotRegex(out, r"\x1b\[\d*[AB]")

    def test_source_no_relative_cursor(self):
        # 源碼鎖:相對游標字面形(ESC[數字A/B,含無參數 ESC[A)在 rmon 源碼永不現形。
        # 文件與註解裡的「ESC[<n>A/B」是散文,不匹配此模式 —— 鎖的正是可執行形。
        self.assertNotRegex(self._rmon_src(), r"\\x1b\[\d*[AB]")

    def test_two_draws_no_scrollback_growth(self):
        # 第二幀只含自己的內容、往下蓋;無尾換行;\n 全部成對 \r\n(裸 \n 會推捲動)
        buf = io.StringIO()
        fr = rmon._Frame(out=buf)
        fr.draw(["alpha", "beta"])
        buf.truncate(0)
        buf.seek(0)
        fr.draw(["gamma"])
        out = buf.getvalue()
        self.assertTrue(out.startswith("\x1b[H"))
        self.assertFalse(out.endswith("\n"))
        plain = rmon._RX_SGR.sub("", out.replace("\x1b[K", "").replace("\x1b[J", ""))
        self.assertIn("gamma", plain)
        self.assertNotIn("beta", plain)
        self.assertEqual(plain.count("\n"), plain.count("\r\n"))

    def test_shrink_erases_leftover_rows(self):
        # 10 行 → 4 行:恰 6 次整行擦除(殘行清理的行數算式)
        buf = io.StringIO()
        fr = rmon._Frame(out=buf)
        fr.draw(["L%d" % i for i in range(10)])
        buf.truncate(0)
        buf.seek(0)
        fr.draw(["S0", "S1", "S2", "S3"])
        self.assertEqual(buf.getvalue().count("\r\n\x1b[K"), 6)

    def test_first_draw_clears_below_once(self):
        # 首拍清一次框下殘字;之後永不重複(3 拍全程 ESC[J 恰好 1 次)
        buf = io.StringIO()
        fr = rmon._Frame(out=buf)
        fr.draw(["a", "b"])
        fr.draw(["a"])
        fr.draw(["c", "d", "e"])
        self.assertEqual(buf.getvalue().count("\x1b[J"), 1)

    def test_clip_wide_cjk_dw(self):
        # 全角=2 算寬裁到 cols;截斷帶誠實標記;短行逐字元不動
        cut = rmon._clip("盒" * 60, 40)
        self.assertLessEqual(rmon.dw(rmon._RX_SGR.sub("", cut)), 40)
        self.assertTrue(cut.endswith("…\x1b[0m"))
        self.assertEqual(rmon._clip("盒盒盒", 40), "盒盒盒")

    def test_clip_never_cuts_sgr(self):
        # 剪點落在色段中段:SGR 整段跳過不攔腰;輸出無半截 escape;一律 reset 收尾
        s = "\x1b[1;32m" + "盒" * 40 + "\x1b[0m"
        cut = rmon._clip(s, 10)
        self.assertTrue(cut.startswith("\x1b[1;32m"))
        self.assertTrue(cut.endswith("…\x1b[0m"))
        self.assertNotIn("\x1b", rmon._RX_SGR.sub("", cut))
        self.assertLessEqual(rmon.dw(rmon._RX_SGR.sub("", cut)), 10)
        # 命名危害本體:強制剪點落在 escape 字元中間(budget=4 < 色段 7 字元)
        mid = rmon._clip(s, 5)
        self.assertTrue(mid.startswith("\x1b[1;32m"))
        self.assertTrue(mid.endswith("…\x1b[0m"))
        self.assertNotIn("\x1b", rmon._RX_SGR.sub("", mid))
        self.assertLessEqual(rmon.dw(rmon._RX_SGR.sub("", mid)), 5)

    def test_fit_flattens_embedded_newline(self):
        # render 邏輯行內嵌 \n(禮讓閘行)→ 物理行攤平;框行數算式的輸入契約
        self.assertEqual(rmon.fit_lines(["a\nb", "c"], 40), ["a", "b", "c"])


class TestLiveFrameFlow(unittest.TestCase):
    """do_live 的兩條路(固定框 / v0.1.4 追加)在假探測+假按鍵下可測 ——
    v0.1.4 時代 do_live 是不可測黑盒(裁決 P1 §3.7 測試縫)。全部 monkeypatch+
    StringIO:零 port、零真實 console、零真實網路。"""

    CFG = {"host": "-", "port": 0, "mode": "friend", "names": {}, "interval": 0.5}

    def setUp(self):
        self._old = {}
        for name in ("_snapshot_state", "_term_size", "_live_wait", "_frame_probe"):
            self._old[name] = getattr(rmon, name)
        self._old_env = os.environ.get("RMON_NO_FRAME")
        os.environ.pop("RMON_NO_FRAME", None)
        rmon._snapshot_state = lambda cfg: ({"boxes": []}, None, None)
        rmon._live_wait = lambda iv: "q"        # 預設:畫一拍就走(測試不許真睡)

    def tearDown(self):
        for name, val in self._old.items():
            setattr(rmon, name, val)
        if self._old_env is None:
            os.environ.pop("RMON_NO_FRAME", None)
        else:
            os.environ["RMON_NO_FRAME"] = self._old_env

    def _go(self, probe, size=(80, 24), color=False, interval=0.5):
        rmon._frame_probe = lambda: probe
        rmon._term_size = lambda: size
        buf = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = rmon.do_live(self.CFG, interval, color)
        return rc, buf.getvalue(), err.getvalue()

    def test_frame_off_appends_exact_v014(self):
        # 「等於今天」鎖:無框路徑的 stdout 與 v0.1.4(_print_lines+footer)逐字元同
        rmon._frame_probe = lambda: (False, True)
        rmon._term_size = lambda: (80, 24)
        buf = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = rmon.do_live(self.CFG, 0.5, False)
        expect = "".join(l + "\n" for l in rmon.render({"boxes": []}, self.CFG, color=False, dead=None))
        expect += "\nq 離開 · r 立刻刷新 · 關窗就關窗(無值守承諾)\n"
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue(), expect)
        self.assertIn("不支援原地重繪", err.getvalue())   # 宣告走 stderr,不污染存檔 stdout

    def test_no_escape_when_frame_off(self):
        rc, out, err = self._go((False, False))
        self.assertNotIn("\x1b", out)          # redirect/pipe 零 escape 紅線(素色)

    def test_vt_gate_forces_plain_color(self):
        # VT 未讀回確認 → 要色請求被誠實降色(不賭裸 escape);latent 缺口轉正的行為鎖
        rc, out, err = self._go((False, False), color=True)
        self.assertNotIn("\x1b", out)
        self.assertIn("色彩強制關閉", err)

    def test_height_overflow_degrades_with_notice(self):
        rc, out, err = self._go((True, True), size=(80, 3))
        self.assertIn("視窗高度不足", out)
        self.assertIn("q 離開", out)
        self.assertIn("rmon v", out)           # 完整面板內容照印(不截帳目燈)
        self.assertNotIn("\x1b[H", out)        # 本拍走追加,未進框

    def test_env_veto_rmon_no_frame(self):
        os.environ["RMON_NO_FRAME"] = "1"      # 逃生門:能力俱全也自願退回 v0.1.4 追加
        rc, out, err = self._go((True, True))
        self.assertNotIn("\x1b[H", out)
        self.assertIn("q 離開", out)

    def test_footer_inside_frame(self):
        rc, out, err = self._go((True, True), size=(120, 40))
        self.assertIn("\x1b[H", out)
        self.assertIn("q 離開", out)
        self.assertNotIn("承諾)\n", out)       # footer 在框內:無追加式的「尾帶換行」形態
        self.assertIn("\x1b[?25l", out)        # 藏游標綁 frame_on(進場)
        self.assertIn("\x1b[?25h", out)        # 還游標(出場儀式)

    def test_q_returns_zero_first_tick(self):
        rc, out, err = self._go((True, True), size=(120, 40))
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("\x1b[H"), 1)   # 恰好一幀:q 一條路回選單

    def test_height_overflow_selfheal_clears_below(self):
        # 縮矮一拍(追加)再復原:復原框必須再發 ESC[J 收框以下,否則追加殘行
        # (含殘留的 footer 帳目行)會永遠掛在活框下面(round-1/B-P2-1 修復鎖)
        sizes = iter([(120, 40), (80, 3), (120, 40)])
        def ts():
            try:
                return next(sizes)
            except StopIteration:
                return (120, 40)
        rmon._frame_probe = lambda: (True, True)
        rmon._term_size = ts
        waits = iter(["", "", "q"])
        rmon._live_wait = lambda iv: next(waits)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rmon.do_live(self.CFG, 0.5, False)
        out = buf.getvalue()
        blocks = out.split("\x1b[H")[1:]
        self.assertEqual(len(blocks), 2)           # 第二拍追加、不進框
        self.assertIn("視窗高度不足", out)
        self.assertIn("\x1b[J", blocks[0])         # 首框清橫幅殘字一次
        self.assertIn("\x1b[J", blocks[1])         # 復原框再清框以下(自癒完整=設計 §3.6)

    def test_shrink_between_ticks_stays_inside_screen(self):
        # 中途縮窗且新框放得下:殘行擦除以現高為帽,該拍 LF 總數 ≤ rows-1
        # ——「永不捲動」不變量在縮窗角度的修復鎖(round-1/B-P3-1)
        orig_render = rmon.render
        ticks = iter(["big", "small"])
        def fake_render(model, cfg, **kw):
            return ["X%02d" % i for i in range(15)] if next(ticks) == "big" else ["Y"] * 3
        rmon.render = fake_render
        try:
            sizes = iter([(100, 20), (100, 6)])
            def ts():
                try:
                    return next(sizes)
                except StopIteration:
                    return (100, 6)
            rmon._frame_probe = lambda: (True, True)
            rmon._term_size = ts
            waits = iter(["", "q"])
            rmon._live_wait = lambda iv: next(waits)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
                rmon.do_live(self.CFG, 0.5, False)
            blocks = buf.getvalue().split("\x1b[H")[1:]
            self.assertEqual(len(blocks), 2)
            # 修復算式:殘行擦除以現高為帽 → 6 行窗、新框 4 行:擦除恰 6-4=2 次
            # (未修碼是 16-4=12 次,走 LF 過窗底 7 行 = 捲動爆發)
            self.assertEqual(blocks[1].count("\r\n\x1b[K"), 2)
        finally:
            rmon.render = orig_render

    def test_noframe_color_keeps_v014_2j_cadence(self):
        # RMON_NO_FRAME=1 + 有色:逐拍逐字元等於 v0.1.4 —— 2J 清屏節奏不是死碼
        # (full_clear 的修復鎖;round-1/B-P3-3)
        os.environ["RMON_NO_FRAME"] = "1"
        rmon._frame_probe = lambda: (True, True)
        rmon._term_size = lambda: (80, 24)
        waits = iter(["", "q"])
        rmon._live_wait = lambda iv: next(waits)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rmon.do_live(self.CFG, 0.5, True)
        out = buf.getvalue()
        self.assertEqual(out.count("\x1b[H\x1b[2J"), 2)      # 兩拍各一次,順序逐字元同 v0.1.4
        self.assertTrue(out.endswith("\x1b[0m\x1b[?25h\n"))  # 出場儀式也是 v0.1.4 原句

    # ---- round-2 L2 鎖測(B2):碼對而鎖無牙的四面,B2 變異掃描目擊後補牙 ----

    def test_frame_per_row_erase_line(self):
        # B2-P3-1:逐行 EL 要「每行恰一條、行行結尾」——舊套件只釘 `\r\n EL` 雙元組,
        # 而那形態上只由空行與殘行擦除構成(行間是 EL,CRLF,行本體,EL),首行/任意
        # 行本體的 EL 被刪仍全綠 —— 雙元組計數當行數計數器是我自己的洞,一併記帳。
        rc, out, err = self._go((True, True), size=(120, 40))
        self.assertTrue(out.startswith("\x1b[?25l\x1b[H"))   # 進場:藏游標、絕對歸位
        el = "\x1b[K"
        body = out.split("\x1b[H", 1)[1].split("\x1b[0m", 1)[0]   # 繪框塊(出場儀式前)
        self.assertTrue(body.endswith("\x1b[J"))             # 首拍清框下,掛塊尾
        rows = body[:-len("\x1b[J")].split("\r\n")
        self.assertGreater(len(rows), 3)                     # 反空洞:確為多行框
        self.assertEqual([r.endswith(el) for r in rows], [True] * len(rows))
        self.assertEqual(body.count(el), len(rows))          # 每行恰一條(不多不少)

    def test_frame_line_feed_structure(self):
        # B2-P3-2:行間 LF 結構釘死成「LF 數 == EL 行數」——舊斷言
        # `count("\n")==count("\r\n")` 在 0==0 空洞綠(把 CRLF 全刪也綠)。
        rc, out, err = self._go((True, True), size=(120, 40))
        block = out.split("\x1b[H", 1)[1]
        lf, crlf = block.count("\n"), block.count("\r\n")
        self.assertGreater(crlf, 5)                          # 反空洞:LF 必須存在
        self.assertEqual(lf, crlf)                           # 每個 LF 都是 CRLF 的一部分
        self.assertEqual(crlf, out.count("\x1b[K"))          # LF 數 = 行數(行間 N-1 + 儀式 1)

    def test_frame_color_never_full_clears(self):
        # B2-P3-3:固定框+有色任何一拍都不得發 2J —— 2J 是 v0.1.4 追加式的清屏儀式,
        # 闖進框節奏=逐拍整屏閃爍+清掉使用者捲動區。舊套件對 2J 零負向斷言。
        rc, out, err = self._go((True, True), size=(120, 40), color=True)
        self.assertIn("\x1b[H", out)                         # 真的進框(非降級路徑)
        self.assertNotIn("\x1b[2J", out)

    def test_frame_exit_ritual_exact(self):
        # B2-P3-4:框路徑出場儀式逐字元 `\x1b[0m\r\n\x1b[?25h` —— reset、落一行
        # (讓殼提示符不吃掉最後框行)、還游標;結尾不得多 \n(框契約:不越框動螢幕)。
        # 舊套件框路徑只有 assertIn(25h),刪 \r\n 或補 \n 都綠。
        rc, out, err = self._go((True, True), size=(120, 40))
        self.assertTrue(out.endswith("\x1b[0m\r\n\x1b[?25h"))


class TestConsoleNiceLock(unittest.TestCase):
    """VT 讀回仲裁器的直接鎖(round-1/B-P3-2):正值只有真 console 測得準(環境變數),
    但誠實面的契約可以釘死 —— 沒要 VT 的路徑與退出路徑永不得宣稱 VT。
    此鎖殺掉「盲目回 True」的仲裁器變異:讀回閘一旦失明,整個 escape 安全論證就塌。"""

    def tearDown(self):
        rmon._console_nice(False)        # 無論走過哪條路,本窗 console 模式一律還原

    def test_never_claims_vt_unless_asked(self):
        self.assertIs(rmon._console_nice(True), False)               # 未 request 永不宣稱
        self.assertIs(rmon._console_nice(False, want_vt=True), False)  # 退出路恆 False

    def test_readback_returns_bool(self):
        self.assertIsInstance(rmon._console_nice(True, want_vt=True), bool)


class TestNoColorEnv(unittest.TestCase):
    """NO_COLOR 慣例(v0.2.0):環境層對「自動開色」一票否決;
    顯式 --color 是使用者當下手勢,仍可越過(main 的 color 算式,非 _term_ok)。"""

    def setUp(self):
        self._old = (os.environ.get("WT_SESSION"), os.environ.get("NO_COLOR"))

    def tearDown(self):
        for k, v in zip(("WT_SESSION", "NO_COLOR"), self._old):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_no_color_beats_auto_color(self):
        os.environ["WT_SESSION"] = "1"
        self.assertTrue(rmon._term_ok(False))          # WT 自動開色基線
        os.environ["NO_COLOR"] = "1"
        self.assertFalse(rmon._term_ok(False))         # NO_COLOR 一票否決
        os.environ.pop("NO_COLOR")
        self.assertTrue(rmon._term_ok(False))          # 撤除即還原
        self.assertFalse(rmon._term_ok(True))          # --ascii 永遠赢



class TestWatchdogKnife0(unittest.TestCase):
    """刀 0(D8''/D1''/D4''/D5''):do_start_core 參數化 + kernel 埠主蓋檔 +
    pidfile target 欄 + 原子寫 + do_stop 死分支不毀佐證。假縫,零真 port、零真 spawn。"""

    CFG = {"host": "127.0.0.1", "port": 8088, "mode": "friend", "names": {},
           "interval": 2.0}

    def setUp(self):
        self.saved = {}
        for k in ("subprocess", "healthz", "healthz_local", "healthz_at", "pid_alive",
                  "port_owner_pid", "time"):
            self.saved[k] = getattr(launch, k, "<absent>")
        self.saved_env = {k: os.environ.get(k) for k in
                          ("STRATA_ROUTER_DIR", "RMON_STATE_DIR")}
        self.state = tempfile.mkdtemp(prefix="wd-k0-")
        self.rdir = tempfile.mkdtemp(prefix="wd-k0-router-")
        io.open(os.path.join(self.rdir, "router.py"), "w", encoding="utf-8").close()
        os.environ["RMON_STATE_DIR"] = self.state
        os.environ["STRATA_ROUTER_DIR"] = self.rdir
        launch.subprocess = mock_mod()
        launch.time = mock_time_mod()
        launch.healthz = lambda timeout=2.0: (False, None, "refused")
        launch.healthz_at = lambda cfg, timeout=2.0: (False, None, "refused")
        launch.pid_alive = lambda pid: True
        launch.port_owner_pid = lambda port: None

    def tearDown(self):
        for k, v in self.saved.items():
            if v == "<absent>":
                try:
                    delattr(launch, k)
                except AttributeError:
                    pass
            else:
                setattr(launch, k, v)
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.state, ignore_errors=True)
        shutil.rmtree(self.rdir, ignore_errors=True)

    def run_core(self, alive_seq=None, owner=None, cfg=None, assume_yes=False,
                 input_answer="n"):
        """alive_seq[i]=第 i 拍 healthz_local(單一額=恆回)。時鐘步進 0.5/拍。"""
        seq = list(alive_seq if alive_seq is not None else [False, True])
        calls = []

        def hz_local(port, timeout=2.0):
            calls.append(port)
            return seq[0] if len(seq) == 1 else seq.pop(0)
        launch.healthz_local = hz_local
        launch.port_owner_pid = lambda port: owner
        t = [0.0]

        def now():
            v = t[0]
            t[0] += 0.5
            return v
        real_input = builtins.input
        builtins.input = lambda *a: input_answer
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = launch.do_start_core(cfg=cfg or dict(self.CFG), now=now,
                                          assume_yes=assume_yes)
        finally:
            builtins.input = real_input
        return rc, out.getvalue(), calls

    def seed_rec(self, rec):
        os.makedirs(self.state, exist_ok=True)
        with io.open(os.path.join(self.state, "router.pid.json"), "w",
                     encoding="utf-8") as fh:
            fh.write(rec if isinstance(rec, str) else json.dumps(rec))

    def read_rec(self):
        with io.open(os.path.join(self.state, "router.pid.json"), encoding="utf-8") as fh:
            return json.load(fh)

    # --- 三因子 + target 血統(D1''(c):pid_matches 是值守唯一 kernel 佐證) ---
    def test_pid_record_three_factor_and_target(self):
        launch.write_pid(os.getpid(), target="127.0.0.1:8088")
        rec = launch.read_pid()
        self.assertEqual(rec["target"], "127.0.0.1:8088")
        self.assertTrue(launch.pid_matches(rec))               # 活 router 三因子恆真
        self.assertFalse(launch.pid_matches({"pid": os.getpid(), "created": 1}))

    # --- 變體①:上線前子進程已死(含贏家側 timeout) -> 不釘檔,rc2 誠實崩潰路 ---
    def test_dead_child_before_online_does_not_pin(self):
        launch.pid_alive = lambda pid: False
        rc, out, _ = self.run_core(alive_seq=[False])
        self.assertEqual(rc, 2)
        self.assertIsNone(launch.read_pid())
        self.assertIn("退出", out)

    # --- 變體②(C-P1-1 反例):healthz 真、子「當下」仍活、埠主是別人 -> 收編不釘檔 ---
    def test_winner_owns_port_no_pin_adopt_wording(self):
        rc, out, _ = self.run_core(alive_seq=[True], owner=999111)
        self.assertEqual(rc, 0)
        self.assertIsNone(launch.read_pid())                   # 贏家的檔輪不到我們蓋
        self.assertIn("收編", out)

    # --- 變體③:正常單起,埠主=自家子 -> 蓋檔且必帶 target ---
    def test_own_child_owner_pins_with_target(self):
        rc, out, _ = self.run_core(alive_seq=[True], owner=424242)
        self.assertEqual(rc, 0)
        rec = self.read_rec()
        self.assertEqual(rec["pid"], 424242)
        self.assertEqual(rec["target"], "127.0.0.1:8088")

    # --- E-P3-1 第三文案:上線後自家子崩 -> 不謊稱「贏家收編」 ---
    def test_child_crash_after_online_third_wording(self):
        launch.pid_alive = lambda pid: False
        rc, out, _ = self.run_core(alive_seq=[True], owner=None)
        self.assertEqual(rc, 2)
        self.assertIsNone(launch.read_pid())
        self.assertNotIn("收編", out)                          # 不是別人佔埠
        self.assertIn("退出", out)

    # --- E-P2-1:cfg 呼叫方注入;核心碰 _cfg_or_default 即紅 ---
    def test_core_uses_injected_cfg_not_reread(self):
        def boom():
            raise AssertionError("do_start_core 不得重讀 monitor.json")
        real_cfg = launch._cfg_or_default
        launch._cfg_or_default = boom
        try:
            rc, out, calls = self.run_core(
                alive_seq=[True], owner=424242,
                cfg={"host": "127.0.0.1", "port": 8123, "mode": "friend",
                     "names": {}, "interval": 2.0})
        finally:
            launch._cfg_or_default = real_cfg
        self.assertEqual(rc, 0)
        self.assertEqual(calls[-1], 8123)

    # --- F-P2-7:等待圈只認注入時鐘(mock time.time 一碰即紅);有界退出 ---
    def test_core_uses_injected_clock_bounded(self):
        rc, out, calls = self.run_core(alive_seq=[False])
        self.assertEqual(rc, 2)
        self.assertTrue(0 < len(calls) < 500)                  # 20s/0.5 = ~40 拍
        self.assertIn("沒回應", out)

    # --- 確認閘語意保留:遠端 + 答 n -> 保留原樣、零 Popen ---
    def test_remote_confirm_gate_answer_no_keeps_semantics(self):
        captured = []
        class _P:
            def __init__(self, cmd, **kw):
                captured.append(cmd)
        launch.subprocess = type("M", (), {"Popen": _P, "DEVNULL": -3,
                                           "call": staticmethod(lambda *a, **k: 0)})
        rc, out, _ = self.run_core(
            cfg={"host": "203.0.113.71", "port": 8088, "mode": "friend",
                 "names": {}, "interval": 2.0}, input_answer="n")
        self.assertEqual(rc, 0)
        self.assertEqual(captured, [])
        self.assertIn("保留原樣", out)

    # --- F-P2-5:pidfile 原子寫(每拍 read_pid 不得見到撕裂/空檔) ---
    def test_write_pid_is_atomic(self):
        real_replace, real_open = os.replace, io.open
        order = []

        def spy_replace(a, b):
            order.append("replace")
            return real_replace(a, b)

        def spy_open(f, *a, **k):
            mode = a[0] if a else k.get("mode", "r")
            if str(f).endswith("router.pid.json") and "w" in mode:
                order.append("direct-write-target")
            return real_open(f, *a, **k)
        os.replace = spy_replace
        io.open = builtins.open = spy_open
        try:
            launch.write_pid(os.getpid(), target="127.0.0.1:8088")
        finally:
            os.replace, io.open, builtins.open = real_replace, real_open, real_open
        self.assertIn("replace", order)
        self.assertNotIn("direct-write-target", order)         # 永不直接開目標檔寫

    # --- D5'':[K] 死分支:完整記錄=佐證,保留;畸形=零價值,可清 ---
    def test_stop_dead_valid_record_keeps_evidence(self):
        self.seed_rec({"pid": 424242, "created": 134000000000000000,
                       "target": "127.0.0.1:8088"})
        launch.pid_alive = lambda pid: False
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = launch.do_stop(assume_yes=True)
        self.assertEqual(rc, 0)
        self.assertIsNotNone(launch.read_pid())                # 佐證仍在 -> 准救仍可判
        self.assertIn("保留", out.getvalue())

    def test_stop_dead_malformed_record_is_cleared(self):
        self.seed_rec('{"pid": 424242}')                       # 缺 created/target
        launch.pid_alive = lambda pid: False
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = launch.do_stop(assume_yes=True)
        self.assertEqual(rc, 0)
        self.assertIsNone(launch.read_pid())


class TestWatchdogKnife1(unittest.TestCase):
    """刀1:Watch 純狀態機(D''1 兩段式觸發 / D''7 觸發後收尾 / 條款8 footer 優先序)。
    全部副作用走縫:read_rec/matches/halt_present/other_lock_pid/spawn/on_disable/now
    -- 零檔案、零 port、零真進程(宿主/鎖/日誌是刀2 的接線面)。"""

    def setUp(self):
        self.t = [0.0]
        self.rec = {"pid": 424242, "created": 1345678, "target": "127.0.0.1:9401"}
        self.rec_alive = False        # pid_matches 縫:記錄進程已死 = 准救佐證
        self.halted = False
        self.spawn_result = ("spawned_ok", 0)
        self.spawn_calls = []
        self.disabled = []

    def now(self):
        return self.t[0]

    def mk(self, host="127.0.0.1", interval=2.0):
        w = launch.Watch({"host": host, "port": 9401}, interval, now=self.now)
        w.read_rec = lambda: self.rec
        w.matches = lambda rec: self.rec_alive
        w.halt_present = lambda: self.halted
        w.other_lock_pid = lambda: 555111

        def _spawn():
            self.spawn_calls.append(1)
            return self.spawn_result
        w.spawn = _spawn
        w.on_disable = lambda: self.disabled.append(1)
        return w

    def advance(self, sec):
        self.t[0] += sec

    def tick(self, w, kind):
        self.advance(2.0)
        return w.on_tick(kind)

    def drive_to_pending(self, w):
        for _ in range(8):
            note = self.tick(w, "refused")
            if "重啟中" in note:
                return note
        self.fail("8 拍內未能武裝觸發")

    def fire(self, w):
        return self.tick(w, "refused")     # N+1 拍入口:真 spawn 在此執行

    def test_trigger_is_two_stage_and_needs_three_votes_over_six_seconds(self):
        w = self.mk()
        self.assertNotIn("重啟中", self.tick(w, "refused"))     # 1 票
        self.assertNotIn("重啟中", self.tick(w, "refused"))     # 2 票
        self.assertNotIn("重啟中", self.tick(w, "timeout"))     # 3 票但首拍跨度僅 4s
        note = self.tick(w, "refused")                          # 跨度 6s 達標
        self.assertIn("重啟中", note)
        self.assertEqual(self.spawn_calls, [])                  # 武裝拍只畫不動(D''1)
        self.tick(w, None)                                      # N+1 入口才真 spawn
        self.assertEqual(len(self.spawn_calls), 1)

    def test_dns_reset_no_vote_and_union_alternation_survives(self):
        w = self.mk()                                           # D1'(b) 聯集代數
        self.tick(w, "refused")
        self.tick(w, "timeout")                                 # 交替不清零
        self.assertNotIn("重啟中", self.tick(w, "dns"))          # dns=不投票也不清零
        self.assertNotIn("重啟中", self.tick(w, "reset"))         # 同上:票數仍 2
        self.assertIn("重啟中", self.tick(w, "refused"))          # 第 3 票,跨度 2->10=8s >=6s

    def test_http_and_alive_hard_reset(self):
        w = self.mk()
        self.tick(w, "refused")
        self.tick(w, "refused")
        self.tick(w, "http")                                    # squat 訊號=硬重置
        for _ in range(3):                                      # 重計:3 票但要跨度夠
            self.assertNotIn("重啟中", self.tick(w, "refused"))  # t8,10,12:2,3票/跨度4
        self.assertIn("重啟中", self.tick(w, "refused"))          # t14:4票/跨度6

    def test_each_condition_alone_blocks_trigger(self):
        good = dict(self.rec)
        cases = [
            ("remote", dict(host="10.0.0.1"), None, None, None),
            ("無記錄", None, None, None, "只提醒"),
            ("畸形記錄", {"pid": 1}, None, None, "只提醒"),
            ("target不符", {"pid": 5, "created": 6, "target": "127.0.0.1:9999"},
             None, None, "只提醒"),
            ("記錄進程還活(卡死)", good, True, None, None),
            ("手動停機halt", good, None, True, "手動停機"),
            ("未持鎖待機", good, None, None, "待機"),
        ]
        for name, rec, alive, halt, word in cases:
            self.setUp()                                        # 重置縫狀態
            self.rec = rec
            if alive is not None:
                self.rec_alive = alive
            if halt is not None:
                self.halted = halt
            w = self.mk(host="10.0.0.1" if name == "remote" else "127.0.0.1")
            if name == "未持鎖待機":
                w.holds_lock = False
            note = None
            for _ in range(6):
                note = self.tick(w, "refused")
            self.assertEqual(self.spawn_calls, [], name)
            if word:
                self.assertIn(word, note, name)

    def test_q_during_wait_cancels_trigger(self):
        w = self.mk()
        self.assertIn("重啟中", self.drive_to_pending(w))
        w.cancel_pending()                                      # 等待拍間按 q=明確離上面板優先
        self.assertNotIn("重啟中", self.tick(w, "refused"))
        self.assertEqual(self.spawn_calls, [])

    def test_recheck_suppression_before_spawn(self):
        w = self.mk()
        self.assertIn("重啟中", self.drive_to_pending(w))
        self.halted = True                                      # 武裝後、spawn 前抑制態改變
        note = self.fire(w)
        self.assertEqual(self.spawn_calls, [])                  # D''7:spawn 前復檢(d)
        self.assertIn("手動停機", note)

    def test_cooldown_table_and_fuse_at_four(self):
        self.spawn_result = ("failed", 2)
        w = self.mk()
        self.assertIn("重啟中1", self.drive_to_pending(w))
        note = self.fire(w)
        self.assertEqual(w.attempts, 1)                         # 額度於真 spawn 計(D''7)
        # L2-A/P3-3(失敗保 streak):第 1 格冷卻=0s -> 同一拍自然攢回、立刻再武裝
        self.assertIn("重啟中2", note)
        note = self.fire(w)                                     # 第 2 次失敗 -> 冷卻 10s
        self.assertIn("冷卻", note)
        self.assertIn("冷卻", self.tick(w, "refused"))           # 冷卻閘壓住不武裝
        self.advance(10.0)
        self.assertIn("重啟中3", self.drive_to_pending(w))       # 第3次冷卻 30s
        note = self.fire(w)                                     # 第 3 次失敗 -> 冷卻 30s
        self.assertIn("冷卻", note)
        self.advance(30.0)
        self.assertIn("重啟中4", self.drive_to_pending(w))
        note = self.fire(w)
        self.assertEqual(w.attempts, 4)
        self.assertIn("熔斷", note)
        self.assertIn("q→[S]", note)
        for _ in range(8):                                      # 熔斷=停止觸發但仍在守
            self.assertNotIn("重啟中", self.tick(w, "refused"))
        self.assertEqual(len(self.spawn_calls), 4)

    def test_already_alive_shortcut_no_burn(self):
        w = self.mk()
        self.assertIn("重啟中", self.drive_to_pending(w))
        self.spawn_result = ("already", 0)                      # 「已在應」捷徑=恢復非失敗
        note = self.fire(w)
        self.assertEqual(w.attempts, 0)                         # 不計不燒(D''7)
        self.assertNotIn("冷卻", note)
        self.assertNotIn("熔斷", note)

    def test_stable_ten_minute_reset_freezes_on_sleep_gap(self):
        self.spawn_result = ("failed", 2)
        w = self.mk()
        self.drive_to_pending(w)
        self.fire(w)                                            # 1 次失敗 -> attempts=1
        self.assertEqual(w.attempts, 1)                         #   (保 streak:同拍已再武裝)
        self.spawn_result = ("spawned_ok", 0)
        self.fire(w)                                            # 成功 spawn 仍占一格(D''7)
        self.assertEqual(w.attempts, 2)                         # -> 起「穩定歸零」累計
        self.advance(700.0)                                     # 睡眠大跳:凍結不計(F-P3-8)
        self.tick(w, None)
        self.assertEqual(w.attempts, 2)                         # 睡 600s 不得無聲重置熔斷
        for _ in range(301):                                    # 觀察到的 alive 拍距湊 602s
            self.tick(w, None)
        self.assertEqual(w.attempts, 0)                         # 穩定 10 分鐘 -> 歸零

    def test_decision_path_exception_disables_once(self):
        w = self.mk()

        def boom():
            raise PermissionError(13, "pidfile locked")          # 決策路(c)炸=終止(D''4)
        w.read_rec = boom
        self.assertIn("已停用", self.tick(w, "refused"))
        self.assertEqual(self.disabled, [1])                    # on_disable 恰一次(刀2 靠它釋鎖)
        self.assertIn("已停用", self.tick(w, "refused"))
        self.assertIn("已停用", self.tick(w, None))
        self.assertEqual(len(self.disabled), 1)                 # 不重試復活(D12)
        self.assertEqual(self.spawn_calls, [])

    def test_footer_priority_order(self):
        w = self.mk()
        self.assertEqual(self.tick(w, None), "開")               # 基態(未啟用逐字元教義由刀3 罩)
        w.log_broken = True
        self.assertEqual(self.tick(w, None), "事件紀錄:不可用")
        w.log_broken = False
        self.rec = None                                         # 無佐證 + 死訊 -> 收編詞
        self.assertIn("只提醒", self.tick(w, "refused"))
        self.assertIn("端口空時q→[S]", self.tick(w, "refused"))
        self.tick(w, None)                                      # 活了 -> 收編詞退場
        self.assertEqual(self.tick(w, None), "開")
        w.holds_lock = False                                    # 待機 > 收編
        self.rec = None
        note = self.tick(w, "refused")
        self.assertIn("待機", note)
        self.assertIn("555111", note)
        w.holds_lock = True
        self.rec = {"pid": 424242, "created": 1345678,
                    "target": "127.0.0.1:9401"}                 # 佐證回暖爐
        w.attempts = 4                                          # 熔斷 > 冷卻/收編
        self.assertIn("熔斷", self.tick(w, "refused"))
        self.halted = True                                      # 手動停機 > 熔斷
        self.assertIn("手動停機", self.tick(w, "refused"))
        w.disable()                                             # 已停用 > 一切
        self.assertIn("已停用", self.tick(w, "refused"))


class TestWatchdogKnife2(unittest.TestCase):
    """刀2:值守宿主接線 -- 鎖(條款3)、halt(D5')、watchdog.log 輪轉/降級(D'')、
    spawn 縫 tally 分類、構造閘(NO_WATCH/遠端)。全部落 temp state dir,零 port。"""

    CFG = {"host": "127.0.0.1", "port": 9401}
    REMOTE = {"host": "10.0.0.1", "port": 9401}

    def setUp(self):
        self.saved = {}
        for k in ("subprocess", "time", "healthz", "healthz_at", "healthz_local",
                  "pid_alive", "pid_matches", "port_owner_pid", "_taskkill",
                  "do_start_core"):
            self.saved[k] = getattr(launch, k, "<absent>")
        self.saved_env = {k: os.environ.get(k) for k in
                          ("RMON_STATE_DIR", "RMON_NO_WATCH", "STRATA_ROUTER_DIR")}
        self.state = tempfile.mkdtemp(prefix="wd-k2-")
        os.environ["RMON_STATE_DIR"] = self.state
        self.hosts = []
        self.fds = []

    def tearDown(self):
        for hw in self.hosts:
            launch._lock_release(getattr(hw, "lock_fd", None))
        for fd in self.fds:
            launch._lock_release(fd)
        for k, v in self.saved.items():
            if v == "<absent>":
                try:
                    delattr(launch, k)
                except AttributeError:
                    pass
            else:
                setattr(launch, k, v)
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.state, ignore_errors=True)

    def mk_host(self, cfg=None, err=None):
        hw = launch.HostWatch(cfg or self.CFG, 2.0)
        hw.out = err if err is not None else io.StringIO()
        self.hosts.append(hw)
        return hw

    # ---- 路徑與 tag ----
    def test_watch_paths_tagged_by_target(self):
        p = launch.watch_paths(self.CFG)
        tag = hashlib.sha1(b"127.0.0.1:9401").hexdigest()[:12]
        self.assertTrue(p["lock"].endswith("watch-%s.lock" % tag))
        self.assertTrue(p["halt"].endswith("watch-%s.halt" % tag))
        self.assertTrue(p["log"].endswith("watchdog.log"))
        other = {"host": "127.0.0.1", "port": 9402}
        self.assertNotEqual(launch.watch_tag(self.CFG), launch.watch_tag(other))

    # ---- 鎖(條款3;語義已親測:進程內雙 fd 互斥 True、offset1024 鎖外可讀) ----
    def test_lock_contention_standby_and_release(self):
        path = launch.watch_paths(self.CFG)["lock"]
        fd1 = launch._lock_acquire(path)
        self.assertIsNotNone(fd1)
        try:
            self.assertIsNone(launch._lock_acquire(path))      # 第二把 = 待機
            self.assertEqual(launch.lock_owner_pid(path), os.getpid())
        finally:
            launch._lock_release(fd1)
        fd2 = launch._lock_acquire(path)                       # 釋放的下一拍可接手
        self.assertIsNotNone(fd2)
        launch._lock_release(fd2)

    def test_lock_source_discipline_ast(self):
        """F-P1-1/條款3 + 親測教訓:只准 NBLCK(UNLCK 除外);seek(0) 先於 lock、
        元資料寫在鎖後 offset 1024;**UNLCK 前必回鎖點**(親測:位點 1024 直接解 ->
        PermissionError13 -- 解鎖也要 seek0 紀律,AST 罩)。"""
        src = open(os.path.join(launch.rmon.my_dir(), "launch.py"),
                   encoding="utf-8").read()
        # 只掃真引用(文件內「拒采 LK_LOCK」的討論文字是誠實史料,不禁)
        names = set(re.findall(r"msvcrt\.(LK_\w+)", src))
        self.assertTrue(names <= {"LK_NBLCK", "LK_UNLCK"}, names)
        self.assertTrue(names)                                   # 零引用也是走錯路
        tree = ast.parse(src)
        fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        def lines(fn, attr, lockname=None, off=None):
            hits = []
            for n in ast.walk(fns[fn]):
                if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                        and n.func.attr == attr):
                    if lockname is not None:
                        a = n.args[1] if len(n.args) > 1 else None
                        if not (isinstance(a, ast.Attribute) and a.attr == lockname):
                            continue
                    if off is not None:
                        a = n.args[1] if len(n.args) > 1 else None
                        ok = (isinstance(a, ast.Constant) and a.value == off) or \
                             (isinstance(a, ast.Name) and a.id == "LOCK_META_OFF")
                        if not ok:
                            continue
                    hits.append(n.lineno)
            return hits
        acq = fns["_lock_acquire"]
        s0 = lines("_lock_acquire", "lseek", off=0)
        lk = lines("_lock_acquire", "locking", lockname="LK_NBLCK")
        m10 = lines("_lock_acquire", "lseek", off=1024)
        wr = lines("_lock_acquire", "write")
        self.assertTrue(s0 and lk and m10 and wr)
        self.assertLess(min(s0), min(lk))                      # 先歸零再鎖
        self.assertLess(min(lk), min(m10))                     # 鎖到手才寫元資料(E1 陷阱)
        self.assertLess(min(m10), min(wr))
        rel0 = lines("_lock_release", "lseek", off=0)
        unl = lines("_lock_release", "locking", lockname="LK_UNLCK")
        self.assertTrue(rel0 and unl)
        self.assertLess(min(rel0), min(unl))                   # 回鎖點才解(_probe C 教訓)
        self.assertTrue(acq and fns["_lock_release"])

    def test_host_reacquires_lock_per_tick(self):
        path = launch.watch_paths(self.CFG)["lock"]
        fd = launch._lock_acquire(path)                        # 他窗先行值守
        self.fds.append(fd)
        hw = self.mk_host()
        self.assertFalse(hw.w.holds_lock)
        note = hw.on_tick(None)
        self.assertIn("待機", note)
        self.assertIn(str(os.getpid()), note)                  # 「他窗值守 pid N」可讀
        launch._lock_release(fd)
        self.fds.remove(fd)
        self.assertIn("開", hw.on_tick(None))                  # 待機每拍重試 -> 接手

    def test_disable_releases_lock(self):
        hw = self.mk_host()
        self.assertIsNotNone(hw.lock_fd)
        hw.w.disable()                                         # 條款3 餓死鏈堵點
        fd = launch._lock_acquire(launch.watch_paths(self.CFG)["lock"])
        try:
            self.assertIsNotNone(fd)
        finally:
            launch._lock_release(fd)

    # ---- halt 不對稱(D5') ----
    def test_halt_written_on_real_kill(self):
        class _Wall:                                     # halt ts=牆鐘展示(條款9 合法載主)
            @staticmethod
            def sleep(sec):
                pass
            @staticmethod
            def time():
                return 1234567890
        launch.time = _Wall()
        real_read = launch.read_pid
        launch.read_pid = lambda: {"pid": 424242, "created": 7,
                                   "target": "127.0.0.1:8088"}  # 預設 cfg 同 target
        launch.pid_matches = lambda rec: True
        seq = [True, False]                                    # 殺成功:下一探已死
        launch.pid_alive = lambda pid: seq.pop(0) if seq else False
        launch._taskkill = lambda pid, force=False: None
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = launch.do_stop(assume_yes=True)
        finally:
            launch.read_pid = real_read
        self.assertEqual(rc, 0)
        halt = launch.watch_paths(launch._cfg_or_default())["halt"]
        self.assertTrue(os.path.exists(halt))                   # 殼 [K] 真殺 -> 意圖落檔

    def test_halt_cleared_on_start_success(self):
        halt_path = launch.watch_paths(self.CFG)["halt"]
        self.assertTrue(launch.write_halt(self.CFG, 123))
        self.assertTrue(os.path.exists(halt_path))
        launch.subprocess = mock_mod()
        launch.time = mock_time_mod()
        launch.healthz_at = lambda cfg, timeout=2.0: (False, None, "refused")
        launch.healthz_local = lambda port, timeout=2.0: True
        launch.pid_alive = lambda pid: True
        launch.port_owner_pid = lambda port: os.getpid()        # 自家子收檔路徑
        rdir = tempfile.mkdtemp(prefix="wd-k2-r-")
        io.open(os.path.join(rdir, "router.py"), "w", encoding="utf-8").close()
        os.environ["STRATA_ROUTER_DIR"] = rdir
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = launch.do_start_core(cfg=self.CFG, now=lambda: 0.0)
        finally:
            shutil.rmtree(rdir, ignore_errors=True)
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(halt_path))             # 成功 do_start 清 halt

    # ---- 構造閘 ----
    def test_make_watch_construction_gates(self):
        os.environ.pop("RMON_NO_WATCH", None)
        w = launch.make_watch(self.CFG, 2.0)
        self.assertIsInstance(w, launch.HostWatch)
        self.hosts.append(w)
        os.environ["RMON_NO_WATCH"] = "1"
        self.assertIsNone(launch.make_watch(self.CFG, 2.0))     # 逃生門
        os.environ["RMON_NO_WATCH"] = "0"
        w2 = launch.make_watch(self.CFG, 2.0)                   # 「0」=不關
        self.assertIsInstance(w2, launch.HostWatch)
        self.hosts.append(w2)
        os.environ.pop("RMON_NO_WATCH", None)
        self.assertIsNone(launch.make_watch(self.REMOTE, 2.0))  # arm 構造閘:遠端不武裝

    # ---- 通知路:stderr+log,零 stdout(D9'/零 stdout 教義) ----
    def test_arm_escape_line_once_zero_stdout(self):
        err = io.StringIO()
        hw = self.mk_host(err=err)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            hw.on_tick(None)
            hw.on_tick(None)
        self.assertEqual(buf.getvalue(), "")
        self.assertIn("RMON_NO_WATCH", err.getvalue())
        self.assertIn("重開窗", err.getvalue())
        self.assertEqual(err.getvalue().count("RMON_NO_WATCH"), 1)  # 武裝句只一次
        log = launch.watch_paths(self.CFG)["log"]
        self.assertIn("武裝", io.open(log, encoding="utf-8").read())

    def test_note_changes_log_to_watchdog_log_never_stdout(self):
        hw = self.mk_host()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            hw.on_tick(None)
            hw.on_tick("refused")                               # 無佐證+死訊 -> 收編詞
            hw.on_tick(None)
        self.assertEqual(buf.getvalue(), "")
        log = io.open(launch.watch_paths(self.CFG)["log"], encoding="utf-8").read()
        self.assertIn("只提醒", log)
        self.assertIn("開", log)

    # ---- 輪轉與降級(條款4;F 探針 D:Notepad 佔檔=PermissionError13 復現) ----
    def test_rotation_uses_os_replace(self):
        log = launch.watch_paths(self.CFG)["log"]
        with io.open(log, "w", encoding="utf-8") as fh:
            fh.write("x" * 300000)                              # 越過 256KB 帽
        seen = []
        real = os.replace
        def spy(a, b, **kw):
            seen.append((a, b))
            return real(a, b, **kw)
        launch.os.replace = spy
        try:
            hw = self.mk_host()
            hw._write_log("輪轉測試")
        finally:
            launch.os.replace = real
        self.assertIn((log, log + ".old"), seen)
        self.assertTrue(os.path.exists(log + ".old"))
        self.assertLess(os.path.getsize(log), 300000)

    def test_rotation_blocked_degrades_not_disables(self):
        log = launch.watch_paths(self.CFG)["log"]
        with io.open(log, "w", encoding="utf-8") as fh:
            fh.write("x" * 300000)
        real = os.replace
        def blocked(a, b, **kw):
            raise PermissionError(5, "WinError 5 .old 被佔")
        launch.os.replace = blocked
        hw = self.mk_host()
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                hw.on_tick(None)                                # 事件寫入撞牆
                note = hw.on_tick(None)
        finally:
            launch.os.replace = real
        self.assertIn("事件紀錄:不可用", note)                   # 降級態(條款4)
        self.assertNotIn("已停用", note)                         # 不是自殺
        for _ in range(40):                                     # 重試帽節流後自癒
            note = hw.on_tick(None)
        self.assertEqual(note, "開")
        self.assertFalse(hw.w.log_broken)

    # ---- spawn 縫:do_start_core tally 分類;值守永不 assume_yes ----
    def test_spawn_seam_maps_tally_never_assume_yes(self):
        hw = self.mk_host()
        seen = {}
        def fake_core(cfg, now, assume_yes=False, emit=print, tally=None):
            seen["assume_yes"] = assume_yes
            if tally is not None:
                tally["outcome"] = "adopted"
            return 0
        launch.do_start_core = fake_core
        try:
            self.assertEqual(hw._spawn(), ("adopted", 0))
        finally:
            self.assertIs(seen["assume_yes"], False)            # D8'' 白文:值守零 assume_yes
        def fake2(cfg, now, assume_yes=False, emit=print, tally=None):
            if tally is not None:
                tally["outcome"] = "failed"
            return 2
        launch.do_start_core = fake2                            # tearDown 還原
        self.assertEqual(hw._spawn(), ("failed", 2))

    # ---- adopted 收尾(刀2 接線語意補齊刀1) ----
    def test_adopted_outcome_counts_and_stabilizes(self):
        t = [0.0]
        def now():
            return t[0]
        w = launch.Watch(self.CFG, 2.0, now=now)
        w.read_rec = lambda: {"pid": 424242, "created": 9,
                              "target": "127.0.0.1:9401"}
        w.matches = lambda rec: False
        w.halt_present = lambda: False
        w.spawn = lambda: ("adopted", 0)                        # 起了子但別人贏
        note = None
        for _ in range(4):
            t[0] += 2.0
            note = w.on_tick("refused")
        self.assertIn("重啟中", note)
        t[0] += 2.0
        w.on_tick("refused")
        self.assertEqual(w.attempts, 1)                         # 真 spawn 過 = 佔額
        for _ in range(301):                                    # 目標在跑 -> 穩定歸零可走
            t[0] += 2.0
            w.on_tick(None)
        self.assertEqual(w.attempts, 0)


class TestWatchdogKnife3(unittest.TestCase):
    """刀3:do_live(watch=None) 單鉤子 + 值守態 footer byte-lock(框+追加兩路)。
   比照 TestLiveFrameFlow 桩制:零 port、零真 console、零網路。"""

    CFG = {"host": "-", "port": 0, "mode": "friend", "names": {}, "interval": 0.5}
    FOOT_OFF = "q 離開 · r 立刻刷新 · 關窗就關窗(無值守承諾)"
    HEAD = "q 離開 · r 立刻刷新 · 窗開值守:"
    STATES = ["開", "重啟中1", "冷卻90s", "熔斷(q→[S])", "待機(他窗值守pid 4294967295)",
              "只提醒(收編;端口空時q→[S]以殼參數重啟)", "手動停機",
              "已停用(異常·已試2次)",              # L2-A/P3-4:D''9 快照版停用詞
              "事件紀錄:不可用"]

    class FakeWatch:
        def __init__(self, notes=None, raises=False, raises_after=None):
            self.notes = list(notes or ["開"])
            self.kinds = []
            self.cancelled = []
            self.raises = raises
            self.raises_after = raises_after    # 守過 n 拍後才炸(L2-B/P2-1:後段拍)
            self.ticks = 0

        def on_tick(self, kind):
            self.ticks += 1
            if self.raises or (self.raises_after is not None
                               and self.ticks > self.raises_after):
                raise RuntimeError("host boom")
            self.kinds.append(kind)
            return self.notes.pop(0) if self.notes else "開"

        def cancel_pending(self):
            self.cancelled.append(1)

    def setUp(self):
        self._old = {}
        for name in ("_snapshot_state", "_term_size", "_live_wait", "_frame_probe"):
            self._old[name] = getattr(rmon, name)
        self._old_env = os.environ.get("RMON_NO_FRAME")
        os.environ.pop("RMON_NO_FRAME", None)
        rmon._snapshot_state = lambda cfg: ({"boxes": []}, None, None)
        rmon._live_wait = lambda iv: "q"

    def tearDown(self):
        for name, val in self._old.items():
            setattr(rmon, name, val)
        if self._old_env is None:
            os.environ.pop("RMON_NO_FRAME", None)
        else:
            os.environ["RMON_NO_FRAME"] = self._old_env

    def _go(self, watch=None, probe=(False, False), size=(80, 24), waits=None,
            snapshot=None, color=False):
        rmon._frame_probe = lambda: probe
        rmon._term_size = lambda: size
        if snapshot is not None:
            rmon._snapshot_state = snapshot
        it = iter(waits or ["q"])
        rmon._live_wait = lambda iv: next(it)
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = rmon.do_live(self.CFG, 0.5, color, watch=watch)
        return rc, buf.getvalue(), err.getvalue()

    def test_watch_none_both_paths_byte_identical(self):
        # 未啟用逐字元教義:watch=None(含舊三參呼叫)兩條路一個位元不動
        rc, out, err = self._go(watch=None)
        expect = "".join(l + "\n" for l in
                         rmon.render({"boxes": []}, self.CFG, color=False, dead=None))
        expect += "\n" + self.FOOT_OFF + "\n"
        self.assertEqual(out, expect)
        rc, out, err = self._go(watch=None, probe=(True, True), size=(120, 40))
        self.assertIn(self.FOOT_OFF, out)
        self.assertNotIn(self.HEAD, out)

    def test_watched_footer_append_path_exact(self):
        rc, out, err = self._go(watch=self.FakeWatch(["開"]))
        self.assertIn("\n" + self.HEAD + "開\n", out)
        self.assertNotIn("關窗就關窗", out)          # 值守態不發無值守承諾

    def test_watched_footer_frame_path_locked(self):
        rc, out, err = self._go(watch=self.FakeWatch(["熔斷(q→[S])"]),
                                probe=(True, True), size=(120, 40))
        self.assertIn(self.HEAD + "熔斷(q→[S])", out)

    def test_dead_kind_feeds_watch(self):
        seq = [({"boxes": []}, None, None),
               (None, rmon.Dead("refused", "x"), None)]
        w = self.FakeWatch(["開", "開"])
        rc, out, err = self._go(watch=w, waits=["", "q"], snapshot=lambda cfg: seq.pop(0))
        self.assertEqual(w.kinds, [None, "refused"])     # 面板拍訊號=值守唯一探針(D7)

    def test_watched_state_sequence_both_lines(self):
        w = self.FakeWatch(["開", "重啟中1", "冷卻10s"])
        rc, out, err = self._go(watch=w, waits=["", "", "q"])
        for state in ("開", "重啟中1", "冷卻10s"):
            self.assertIn("\n" + self.HEAD + state + "\n", out)
        self.assertEqual(out.count(self.HEAD), 3)

    def test_q_calls_cancel_pending(self):
        w = self.FakeWatch()
        rc, out, err = self._go(watch=w, waits=["q"])
        self.assertEqual(w.cancelled, [1])               # 等待拍間 q=面板優先(D''1)
        self.assertEqual(rc, 0)

    def test_hook_exception_exits_watch_honestly(self):
        w = self.FakeWatch(raises=True)
        rc, out, err = self._go(watch=w, waits=["q"])
        self.assertEqual(rc, 0)                          # 面板照跑(F1)
        self.assertIn("值守鉤子異常", err)
        self.assertIn(self.FOOT_OFF, out)                # footer 退回未值守承諾=如實
        self.assertNotIn(self.HEAD, out)

    def test_hook_exception_on_later_tick_restores_footer(self):
        # L2-B/P2-1(存活 M23):先老實守兩拍、第 3 拍才炸 -- 此後的每一幀都必須
        # 退回未值守承諾。舊測只演第一拍就炸(彼時 foot 仍是初始未值守字串,
        # 重置行從未被需要);刪掉 rmon 的 foot 重置行後,面板從該拍起永久宣稱
        # 「窗開值守:開」而 watch 已是 None -- 宣稱跑在行為前面,腳本級查不出。
        w = self.FakeWatch(notes=["開", "開"], raises_after=2)
        rc, out, err = self._go(watch=w, waits=["", "", "q"])
        self.assertEqual(rc, 0)
        self.assertIn("值守鉤子異常", err)
        self.assertEqual(out.count(self.HEAD), 2)        # 值守 footer 只准存在於守著的那兩幀
        self.assertIn(self.FOOT_OFF, out)                # 炸後的幀如實退回未值守承諾

    def test_watched_footers_fit_80_display_cols(self):
        def width(s):
            wsum = 0
            for ch in s:
                wsum += 2 if unicodedata.east_asian_width(ch) in ("F", "W") else 1
            return wsum
        for state in self.STATES:                        # 條款8 定稿詞全態:最長 <80
            self.assertLessEqual(width(self.HEAD + state), 80, state)

    def test_watch_duck_surface_ast(self):
        """單鉤子紀律:rmon 對 watch 只准碰 on_tick/cancel_pending(刀2/刀4 換宿主
        不換介面;源碼鎖,比照 frame 源碼鎖先例)。"""
        src = open(os.path.join(rmon.my_dir(), "rmon.py"), encoding="utf-8").read()
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "do_live")
        touched = set()
        for n in ast.walk(fn):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                    and n.value.id == "watch":
                touched.add(n.attr)
        self.assertTrue(touched <= {"on_tick", "cancel_pending"}, touched)
        self.assertIn("on_tick", touched)


class TestWatchdogKnife4(unittest.TestCase):
    """刀4 接線面:run_console(go)把 make_watch 的產物餵給 do_live;非 tty 單拍
    物理不武裝;生產碼 assume_yes 零調用者白文鎖。"""

    CFG = {"host": "127.0.0.1", "port": 9401, "mode": "friend", "names": {},
           "interval": 0.5}

    def _patch_console(self, tty=True, make_watch_ret=None):
        undo = []
        box = {"start": 0, "live_watch": "未調用", "mk_calls": [], "once_args": []}

        def setp(obj, name, val):
            undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, val)

        setp(launch, "_cfg_or_default", lambda: dict(self.CFG))
        setp(launch, "healthz", lambda timeout=2.0: (True, "9.9.9", "http200"))
        setp(launch.rmon, "do_live",
             lambda cfg, interval, color, watch=None: box.__setitem__("live_watch", watch) or 0)
        setp(launch, "_stdin_tty", lambda: tty)
        setp(launch, "make_watch",
             lambda cfg, interval: box["mk_calls"].append((cfg["port"], interval))
             or make_watch_ret)
        setp(launch, "_run_rmon", lambda args: box["once_args"].append(list(args)))
        return undo, box

    def _run(self, undo):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = launch.run_console()
        for obj, name, val in reversed(undo):
            setattr(obj, name, val)
        return rc, buf.getvalue()

    def test_go_feeds_make_watch_into_do_live(self):
        sentinel = object()
        undo, box = self._patch_console(make_watch_ret=sentinel)
        rc, out = self._run(undo)
        self.assertEqual(rc, 0)
        self.assertEqual(box["mk_calls"], [(9401, 0.5)])      # 構造一次,吃 cfg 節拍
        self.assertIs(box["live_watch"], sentinel)            # 原物進面板,不得中途丟棄

    def test_non_tty_single_shot_never_arms(self):
        undo, box = self._patch_console(tty=False, make_watch_ret=object())
        rc, out = self._run(undo)
        self.assertEqual(box["mk_calls"], [])                 # 單拍物理不武裝(README 限界)
        self.assertEqual(box["once_args"], [["once"]])
        self.assertIn("不掛常駐面板", out)

    def test_production_code_zero_assume_yes_callers(self):
        """條款9 白文:生產路徑(do_start/do_start_core)零 assume_yes=True 調用者
        (tests 縫除外--本條只掃生產兩個源檔)。值守 spawn 縫更傳明文 False(D8'')。"""
        for fn in ("launch.py", "rmon.py"):
            src = open(os.path.join(rmon.my_dir(), fn), encoding="utf-8").read()
            hits = re.findall(r"do_start\w*\([^)\n]*assume_yes=True", src)
            self.assertEqual(hits, [], fn)


class TestWatchdogCanary(unittest.TestCase):
    """D10 三模式 canary + 雙程序 NBLCK(默認開,撞港誠實 skip 可見;桩自滅零 kill;
    真 kill 只走產品自己的 do_stop 三因子路徑;RUNTIME 帽;93xx 專屬,永不碰 9177-9199/生產)。"""

    PORTS = range(9311, 9319)

    def setUp(self):
        self.sock = None
        self.port = None
        for p in self.PORTS:
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", p))
                self.sock, self.port = s, p
                break
            except OSError:
                s.close()
        if self.port is None:
            self.skipTest("93xx 全佔:canary 跳過(可見 skip,D-P2-4)")
        self._old_env = {}
        self.state = tempfile.mkdtemp(prefix="wd-k4-")
        self.rdir = tempfile.mkdtemp(prefix="wd-k4-r-")
        for k, v in (("RMON_STATE_DIR", self.state), ("STRATA_ROUTER_DIR", self.rdir)):
            self._old_env[k] = os.environ.get(k)
            os.environ[k] = v

    def tearDown(self):
        if self.sock is not None:
            self.sock.close()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.state, ignore_errors=True)
        shutil.rmtree(self.rdir, ignore_errors=True)

    def cfg(self):
        return {"host": "127.0.0.1", "port": self.port, "mode": "friend",
                "names": {}, "interval": 0.5}

    def _stub_router(self, life):
        """真「router」桩:bind 本 port 回 /healthz;WD_STUB_LIFE 秒後自滅(零 kill)。"""
        with io.open(os.path.join(self.rdir, "router.py"), "w", encoding="utf-8") as fh:
            fh.write(
                "import http.server, json, os, threading\n"
                "class H(http.server.BaseHTTPRequestHandler):\n"
                "    def do_GET(self):\n"
                "        b = json.dumps({'version': '9.9.9-canary'}).encode()\n"
                "        self.send_response(200)\n"
                "        self.send_header('Content-Length', str(len(b)))\n"
                "        self.end_headers()\n"
                "        self.wfile.write(b)\n"
                "    def log_message(self, *a):\n"
                "        pass\n"
                "srv = http.server.HTTPServer(('127.0.0.1', int(os.environ['WD_STUB_PORT'])), H)\n"
                "life = float(os.environ.get('WD_STUB_LIFE', '0'))\n"
                "if life > 0:\n"
                "    threading.Timer(life, srv.shutdown).start()\n"
                "srv.serve_forever()\n")

    def test_canary_crash_full_chain_real_spawn(self):
        """crash 態全流程真相:死記錄+空端口 -> 兩段武裝 -> 真 spawn -> kernel 埠主
        蓋檔 -> 最後由產品自己的 [K] 三因子路徑收尾(零測試側 kill)。"""
        t_start = time.monotonic()
        self._stub_router(life=30)
        os.environ["WD_STUB_PORT"] = str(self.port)
        os.environ["WD_STUB_LIFE"] = "30"
        io.open(launch.pidfile(), "w", encoding="utf-8").write(
            json.dumps({"pid": 424242, "created": 1345678,
                        "target": "127.0.0.1:%d" % self.port}))       # 死的自家記錄
        if self.sock:
            self.sock.close()                       # 讓位給桩(綁定競爭由 RUNTIME 帽兜)
            self.sock = None
        hw = launch.HostWatch(self.cfg(), 0.5)
        err = io.StringIO()
        hw.out = err
        fake_t = [1000.0]                        # 拍鐘 fake(免真睡 6s);真 spawn 仍走真時鐘
        hw.w.now = lambda: fake_t[0]
        try:
            armed = False
            for _ in range(8):
                fake_t[0] += 2.0
                if "重啟中" in hw.on_tick("refused"):
                    armed = True
                    break
            self.assertTrue(armed, "武裝失敗:%s" % err.getvalue())
            self.assertEqual(launch.read_pid()["pid"], 424242)   # 觸發拍只畫不動(D'')
            fake_t[0] += 2.0
            hw.on_tick("refused")                 # N+1 入口:真 spawn
            self.assertLess(time.monotonic() - t_start, 20, "RUNTIME 帽")
            rec = launch.read_pid()
            self.assertIsNotNone(rec, "埠主==自家子應蓋檔:%s" % err.getvalue())
            self.assertEqual(rec["target"], "127.0.0.1:%d" % self.port)
            self.assertTrue(launch.pid_alive(rec["pid"]))
            self.assertEqual(launch.port_owner_pid(self.port), rec["pid"])  # kernel 身分
            self.assertEqual(hw.w.attempts, 1)
        finally:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = launch.do_stop(assume_yes=True)      # 產品收尾路徑(三因子+[K]教義)
            os.environ.pop("WD_STUB_PORT", None)
            os.environ.pop("WD_STUB_LIFE", None)
            launch._lock_release(hw.lock_fd)
        self.assertEqual(rc, 0)
        self.assertIsNone(launch.port_owner_pid(self.port))    # 端口真的空了
        self.assertLess(time.monotonic() - t_start, 25, "RUNTIME 帽")

    def _http_stub_thread(self, code, body=b'{"boxes": []}'):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", self.port), H)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        return srv, th

    def test_canary_squat_never_triggers(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        srv, _th = self._http_stub_thread(404)            # squat 者:任何 HTTP 都非 router
        try:
            _m, dead, _x = rmon._snapshot_state(self.cfg())
            self.assertIsNotNone(dead)                    # 面板真訊號(非我捏 kind)
            self.assertEqual(dead.kind, "http")           # D1(b) 地基石的真實落地
            io.open(launch.pidfile(), "w", encoding="utf-8").write(
                json.dumps({"pid": 424242, "created": 1345678,
                            "target": "127.0.0.1:%d" % self.port}))
            hw = launch.HostWatch(self.cfg(), 0.5)
            calls = []
            hw.w.spawn = lambda: (calls.append(1), ("spawned_ok", 0))[1]
            try:
                for _ in range(10):                       # 真 kind 餵拍:squat 永不入觸發集
                    self.assertNotIn("重啟中", hw.on_tick(dead.kind))
            finally:
                launch._lock_release(hw.lock_fd)
            self.assertEqual(calls, [])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_canary_alive_never_triggers(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        srv, _th = self._http_stub_thread(200)            # 活著(就算是桩)就不救
        try:
            model, dead, _x = rmon._snapshot_state(self.cfg())
            self.assertIsNone(dead)                       # 面板訊號:活
            io.open(launch.pidfile(), "w", encoding="utf-8").write(
                json.dumps({"pid": 424242, "created": 1345678,
                            "target": "127.0.0.1:%d" % self.port}))
            hw = launch.HostWatch(self.cfg(), 0.5)
            calls = []
            hw.w.spawn = lambda: (calls.append(1), ("spawned_ok", 0))[1]
            try:
                for _ in range(10):
                    self.assertNotIn("重啟中", hw.on_tick(None))
            finally:
                launch._lock_release(hw.lock_fd)
            self.assertEqual(calls, [])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_canary_two_process_nblck(self):
        """條款3/10:鎖紀律的雙程序真相(源碼鎖釘不了行為)--未釋放出「等」,
        釋放後下一拍接得上。子程序走 own handle,超時才動它(教義)。"""
        path = launch.watch_paths(self.cfg())["lock"]
        fd = launch._lock_acquire(path)
        self.assertIsNotNone(fd)
        child = ("import os,sys,time,msvcrt\n"
                 "p = sys.argv[1]\n"
                 "end = time.time() + 12\n"
                 "while time.time() < end:\n"
                 "    fd = os.open(p, os.O_RDWR | os.O_CREAT)\n"
                 "    try:\n"
                 "        os.lseek(fd, 0, os.SEEK_SET)\n"
                 "        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)\n"
                 "        print('GOT', flush=True)\n"
                 "        break\n"
                 "    except OSError:\n"
                 "        os.close(fd)\n"
                 "        print('WAIT', flush=True)\n"
                 "        time.sleep(0.2)\n")
        p = subprocess.Popen([sys.executable, "-c", child, path],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
        try:
            t0 = time.monotonic()
            first = p.stdout.readline().strip()          # 父持鎖中:孩子只能 WAIT
            self.assertEqual(first, "WAIT")
            time.sleep(0.4)
            launch._lock_release(fd)                     # 釋放 -> 孩子下拍接手
            line = ""
            while time.monotonic() - t0 < 14:
                line = p.stdout.readline().strip()
                if line == "GOT":
                    break
            self.assertEqual(line, "GOT", "釋放後接不上鎖 = 鎖語意破產")
            self.assertEqual(p.wait(timeout=10), 0)      # 子自滅(持鎖靠進程退出釋放)
        finally:
            if p.poll() is None:
                p.kill()                                 # own handle(教義允許的最後手段)
                p.wait(timeout=10)


class TestWatchdogL2A(unittest.TestCase):
    """L2 round-1 面A 採納項鎖測(修前紅/修後綠):
    P1-1 面板任何出口交還鎖([G] 同進程再武裝不餵幽魂鎖);
    P1-2 停用窗永不重搶鎖(餓死鏈堵點加閘);
    P2-1 埠主查詢異常=保守失敗(D''2「不寫+誠實失敗」);
    P2-2 重啟事件進 watchdog.log(尸檢媒體完整);
    P3-1 鎖元資料定寬(舊長 pid 不黏新短 pid);
    P3-2 穩定歸零要求連續 alive(死拍歸零,README「連續」兑现);
    P3-3 失敗保 streak(D''7 白文;成功才清);
    P3-4 停用 footer 快照 + 例外 diag 落檔 + [K] 停機意圖寫敗警告。"""

    CFG = {"host": "127.0.0.1", "port": 9401, "mode": "friend", "names": {},
           "interval": 0.5}

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="wd-l2a-")
        self.env_saved = {k: os.environ.get(k) for k in
                          ("RMON_STATE_DIR", "RMON_NO_WATCH")}
        os.environ["RMON_STATE_DIR"] = self.state
        os.environ.pop("RMON_NO_WATCH", None)
        self.saved = []
        self.fds = []
        self.hosts = []

    def tearDown(self):
        for fd in self.fds:
            launch._lock_release(fd)
        for hw in self.hosts:
            try:
                hw.release()
            except Exception:
                pass
        for obj, name, val in reversed(self.saved):
            setattr(obj, name, val)
        for k, v in self.env_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.state, ignore_errors=True)

    def setp(self, obj, name, val):
        self.saved.append((obj, name, getattr(obj, name)))
        setattr(obj, name, val)

    def _mk_host(self):
        hw = launch.make_watch(dict(self.CFG), 0.5)
        self.assertIsNotNone(hw)                              # loopback + 無 NO_WATCH
        self.hosts.append(hw)
        return hw

    # ------------------------------------------------ P1-1 出口交還鎖
    def test_panel_exit_releases_lock(self):
        hw = self._mk_host()
        self.assertIsNotNone(hw.lock_fd)
        path = launch.watch_paths(dict(self.CFG))["lock"]
        hw.release()                                          # 方法必須存在且冪等
        hw.release()
        fd = launch._lock_acquire(path)                       # 交還後立刻可再拿
        self.assertIsNotNone(fd, "release() 後鎖仍被持 -- [G] 再武裝會被幽魂鎖擋")
        self.fds.append(fd)

    def test_run_console_releases_watch_on_all_exits(self):
        class _Rec:
            def __init__(self):
                self.releases = 0
            def release(self):
                self.releases += 1
        for name, behavior in (
                ("q 正常返回", lambda cfg, interval, color, watch=None: 0),
                ("Ctrl+C", lambda cfg, interval, color, watch=None: (_ for _ in ()).throw(KeyboardInterrupt())),
                ("面板異常", lambda cfg, interval, color, watch=None: (_ for _ in ()).throw(ValueError("boom")))):
            with self.subTest(name):
                rec = _Rec()
                self.setp(launch, "_cfg_or_default", lambda: dict(self.CFG))
                self.setp(launch, "healthz", lambda timeout=2.0: (True, "9.9.9", "http200"))
                self.setp(launch, "_stdin_tty", lambda: True)
                self.setp(launch, "_run_rmon", lambda args: None)
                self.setp(launch, "make_watch", lambda cfg, interval: rec)
                self.setp(launch.rmon, "do_live", behavior)
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
                    rc = launch.run_console()
                self.assertEqual(rc, 0)
                self.assertEqual(rec.releases, 1,
                                 "出口 %r 未交還值守鎖(幽魂鎖擋死 [G] 再武裝)" % name)

    # ------------------------------------------------ P1-2 停用窗不重搶鎖
    def test_disabled_window_never_reacquires_lock(self):
        hw = self._mk_host()
        path = launch.watch_paths(dict(self.CFG))["lock"]

        def boom():
            raise PermissionError(13, "pidfile locked")        # 決策路異常 -> 停用+釋鎖
        hw.w.halt_present = boom
        self.assertIn("已停用", hw.on_tick("refused"))
        for _ in range(3):                                    # 停用後的拍不得重搶
            hw.on_tick("refused")
        fd = launch._lock_acquire(path)
        self.assertIsNotNone(fd, "已停用窗活持鎖 -- 餓死鏈堵點被每拍重試還魂")
        self.fds.append(fd)

    # ------------------------------------------------ P2-1 埠主查詢異常=保守
    def test_owner_query_failure_conservative(self):
        writes = []

        class _P:
            pid = 424242

        def fake_popen(*a, **k):
            return _P()
        rpy = os.path.join(self.state, "router.py")
        with open(rpy, "w") as fh:
            fh.write("# 存在即可(零執行)\n")
        self.setp(launch, "router_py", lambda: rpy)
        self.setp(launch, "router_dir", lambda: self.state)
        self.setp(launch, "healthz_at", lambda cfg, timeout=2.0: (False, None, "refused"))
        self.setp(launch.subprocess, "Popen", fake_popen)
        self.setp(launch.time, "sleep", lambda s: None)
        self.setp(launch, "healthz_local", lambda port, timeout=2.0: True)
        self.setp(launch, "pid_alive", lambda pid: True)
        self.setp(launch, "port_owner_pid", lambda port, *a, **k: None)  # kernel 表查無
        self.setp(launch, "write_pid", lambda pid, target=None: writes.append(pid))
        tally = {}
        rc = launch.do_start_core(dict(self.CFG), lambda: 0.0, assume_yes=True,
                                  emit=lambda s: None, tally=tally)
        self.assertEqual(rc, 2)
        self.assertEqual(tally.get("outcome"), "failed")
        self.assertEqual(writes, [], "埠主證明不了就寫 pid -- D''2 保守條款被違反")

    # ------------------------------------------------ P2-2 重啟事件進 log
    def test_restart_events_reach_watchdog_log(self):
        hw = self._mk_host()

        def fake_core(cfg, now, assume_yes=False, emit=None, tally=None):
            emit("已啟動 router(pid 424242),等本機 /healthz...")
            emit("上線了:v9.9.9")
            if tally is not None:
                tally["outcome"] = "spawned_ok"
            return 0
        self.setp(launch, "do_start_core", fake_core)
        self.assertEqual(hw._spawn(), ("spawned_ok", 0))
        with open(launch.watch_paths(dict(self.CFG))["log"], encoding="utf-8") as fh:
            blob = fh.read()
        self.assertIn("上線了:v9.9.9", blob,
                      "重啟細節只走 stderr,watchdog.log 尸檢媒體缺頁")

    # ------------------------------------------------ P3-1 鎖元資料定寬
    def test_lock_meta_padded_no_ghost_pid(self):
        path = launch.watch_paths(dict(self.CFG))["lock"]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:                          # 前一任「長 pid」的殘字
            fh.seek(launch.LOCK_META_OFF)
            fh.write(b"29388" * 4)
        fd = launch._lock_acquire(path)
        self.assertIsNotNone(fd)
        self.fds.append(fd)
        self.assertEqual(launch.lock_owner_pid(path), os.getpid(),
                         "新短 pid 與舊長 pid 殘字黏成幽魂 pid")

    # ------------------------------------------------ P3-2 穩定歸零要連續
    def test_stable_reset_requires_continuous_alive(self):
        t = [0.0]
        # interval 2.0:拍距 4.0s 必須走在正常分支 -- 0.5 的睡眠閘是 3.5s,
        # 全用它會整段滑進睡眠凍結支,累計根本不時不扣(牙空,teeth driver 實證)。
        w = launch.Watch(dict(self.CFG), 2.0, now=lambda: t[0])
        w.read_rec = lambda: {"pid": 1, "created": 1, "target": "127.0.0.1:9401"}
        w.matches = lambda rec: False
        w.halt_present = lambda: False
        w.spawn = lambda: ("failed", 2)
        w.attempts = 1
        w._stable = launch.WATCH_STABLE_RESET                 # 剛成功過,起算 600
        for _ in range(100):                                  # 400s 全活
            t[0] += 4.0
            w.on_tick(None)
        self.assertEqual(w._stable, 204.0)                    # 首拍 gap=None 不扣:99×4.0,
                                                              # 累計確實在扣(非睡眠凍結態)
        t[0] += 4.0
        w.on_tick("refused")                                  # 死了 4s(未熔斷)
        self.assertIsNone(w._stable,
                          "死拍必須歸零重攢(D''7「連續」;L2-A/P3-2),不準留殘值")
        for _ in range(60):                                   # 再活 240s:殘值 200 早該湊過 0
            t[0] += 4.0
            w.on_tick(None)
        self.assertEqual(w.attempts, 1,
                         "穿插死亡拍的距離也被算進「連續存活」-- 額度被準時歸零")

    # ------------------------------------------------ P3-3 失敗保 streak
    def test_failed_spawn_keeps_streak(self):
        t = [0.0]
        spawns = []
        w = launch.Watch(dict(self.CFG), 0.5, now=lambda: t[0])
        w.read_rec = lambda: {"pid": 1, "created": 1, "target": "127.0.0.1:9401"}
        w.matches = lambda rec: False
        w.halt_present = lambda: False

        def _sp():
            spawns.append(1)
            return ("failed", 2)
        w.spawn = _sp
        for _ in range(4):                                    # 3 票 + 跨度 6s -> 武裝
            t[0] += 2.0
            note = w.on_tick("refused")
        self.assertIn("重啟中", note)
        t[0] += 2.0
        note = w.on_tick("refused")                             # N+1:真 spawn(失敗)
        self.assertEqual(len(spawns), 1)
        self.assertEqual(w.attempts, 1)
        self.assertGreaterEqual(w._streak, 3,
                                "失敗把 streak 清光 -- D''7「失敗保 streak(冷卻末自然攢回)」")
        # 冷卻表第 1 格=0s:保住的 streak 在同一拍自然攢回、立刻再武裝(D''7 語意)
        self.assertIn("重啟中", note)
        t[0] += 2.0
        w.on_tick("refused")                                    # 第 2 次 spawn 執行(失敗)
        self.assertEqual(len(spawns), 2)
        self.assertEqual(w.attempts, 2)
        self.assertIn("冷卻", w.on_tick("refused"))               # 第 2 格 10s 壓住

    # ------------------------------------------------ P3-4 停用快照+diag+halt 寫敗
    def test_disable_footer_snapshot_and_diag(self):
        hw = self._mk_host()

        def boom():
            raise PermissionError(13, "pidfile locked")
        hw.w.halt_present = boom
        note = hw.on_tick("refused")
        self.assertIn("已停用", note)
        self.assertIn("已試", note, "D''9:停用態 footer 要帶一句快照摘要")
        with open(launch.watch_paths(dict(self.CFG))["log"], encoding="utf-8") as fh:
            blob = fh.read()
        self.assertIn("PermissionError", blob,
                      "停用只說「異常」不帶例外細節 -- 零 diagnostics 的停用無法排查")

    def test_stop_warns_when_halt_intent_write_fails(self):
        rec = {"pid": 424242, "created": 1.5, "target": "127.0.0.1:9401"}
        self.setp(launch, "read_pid", lambda: dict(rec))
        self.setp(launch, "pid_matches", lambda r: True)
        self.setp(launch, "_taskkill", lambda pid, force=False: True)
        self.setp(launch, "pid_alive", lambda pid: False)      # 殺後即死
        self.setp(launch.time, "sleep", lambda s: None)
        self.setp(launch, "clear_pid", lambda: None)
        self.setp(launch, "write_halt", lambda cfg, pid: False)  # 意圖落檔失敗
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = launch.do_stop(assume_yes=True)
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("已終端", out)
        self.assertIn("拉起", out,
                      "停機意圖寫敗必須警告(值守會把剛殺的拉起來),靜默=背叛 [K]")


class TestWatchdogL2B(unittest.TestCase):
    """L2 round-1 面B 採納項鎖測(突變存活者 -> 逐條補牙,一條牙對一個存活者):
    M09b disable() 冪等(on_disable 恰一次,重複呼叫不重複釋鎖/落檔);
    M11b kept(遠端答 n)不清 halt(D5' 不對稱的另一半);
    M11c already 捷徑清 halt(已在應也是成功 do_start);
    M24  觸發點自判 loopback(雙閘並存的第二閘,不再只是宣稱);
    M44  冷卻剩餘採進位(誠實:剩 0.2s 不許說「冷卻0s」);
    M45  watchdog.log 只在狀態遷移落行(不逐拍刷 Noise);
    M56  三因子第三因子:映像檔非 python* 照拒殺(活+建立時間全對也救不回来);
    M58  make_watch 構造炸=棄權不重試、面板必須說話(F1);
    M63  宿主真 halt 檔接線(README「手動停機最大」的載體)。"""

    CFG = {"host": "127.0.0.1", "port": 9401, "mode": "friend", "names": {},
           "interval": 0.5}

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="wd-l2b-")
        self.env_saved = {k: os.environ.get(k) for k in
                          ("RMON_STATE_DIR", "RMON_NO_WATCH")}
        os.environ["RMON_STATE_DIR"] = self.state
        os.environ.pop("RMON_NO_WATCH", None)
        self.saved = []
        self.hosts = []

    def tearDown(self):
        for hw in self.hosts:
            try:
                hw.release()
            except Exception:
                pass
        for obj, name, val in reversed(self.saved):
            setattr(obj, name, val)
        for k, v in self.env_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.state, ignore_errors=True)

    def setp(self, obj, name, val):
        self.saved.append((obj, name, getattr(obj, name)))
        setattr(obj, name, val)

    # ------------------------------------------------ M09b disable 冪等
    def test_disable_is_idempotent(self):
        w = launch.Watch(dict(self.CFG), 0.5, now=lambda: 0.0)
        calls = []
        w.on_disable = lambda: calls.append(1)
        w.disable()
        w.disable()
        w.disable()
        self.assertEqual(calls, [1])    # 「恰一次」:重複 disable 不重複釋鎖/落檔/stderr

    # ------------------------------------------------ M11c already 清 halt
    def test_already_shortcut_clears_halt(self):
        cfg = dict(self.CFG)
        launch.write_halt(cfg, 424242)
        paths = launch.watch_paths(cfg)
        self.assertTrue(os.path.exists(paths["halt"]))
        self.setp(launch, "router_py", lambda: __file__)   # 存在性閘:給個真存在的檔
        self.setp(launch, "healthz_at", lambda c: (True, "9.9.9", "http"))
        tally = {}
        rc = launch.do_start_core(cfg, lambda: 0.0, emit=lambda s: None, tally=tally)
        self.assertEqual((rc, tally.get("outcome")), (0, "already"))
        # halt 無 TTL(D5' 定案),唯一清檔點=任何成功 do_start -- 已在應捷徑也是。
        # 此路一斷,[G] 永遠清不掉意圖,值守被永久抑制且 footer 恆示「手動停機」。
        self.assertFalse(os.path.exists(paths["halt"]))

    # ------------------------------------------------ M11b kept 保留 halt
    def test_kept_keeps_halt_untouched(self):
        cfg = dict(self.CFG)
        cfg["host"] = "10.0.0.1"                 # 遠端目標:kept 語意的現場
        launch.write_halt(cfg, 424242)
        paths = launch.watch_paths(cfg)
        self.assertTrue(os.path.exists(paths["halt"]))
        self.setp(launch, "router_py", lambda: __file__)
        self.setp(launch, "healthz_at", lambda c: (False, None, "refused"))
        self.setp(launch, "_ask", lambda prompt: "n")
        tally = {}
        rc = launch.do_start_core(cfg, lambda: 0.0, assume_yes=False,
                                  emit=lambda s: None, tally=tally)
        self.assertEqual((rc, tally.get("outcome")), (0, "kept"))
        # 保留原樣 != 成功:不清 halt、不餵穩定累計(D5' 不對稱;碼註白寫,今日無牙)
        self.assertTrue(os.path.exists(paths["halt"]))

    # ------------------------------------------------ M24 雙閘第二閘
    def test_trigger_point_loopback_second_gate(self):
        # C-P2-1「雙閘並存」:構造閘先擋遠端,刀1 的遠端案例實為 target 不符擋的。
        # 本測讓其餘閘全開(血統俱備、target 相符、進程已死、無 halt、未熔斷、
        # 持鎖、冷卻過),唯一还能擋下觸發的只剩觸發點自判 loopback。
        fires = []
        t = [0.0]
        cfg = dict(self.CFG)
        cfg["host"] = "10.0.0.1"
        w = launch.Watch(cfg, 0.5, now=lambda: t[0])
        self.assertFalse(w.loopback)
        w.read_rec = lambda: {"pid": 1, "created": 1, "target": "10.0.0.1:9401"}
        w.matches = lambda rec: False            # 記錄進程已死:佐證俱備准救
        w.spawn = lambda: (fires.append(1), ("spawned_ok", 0))[1]
        for _ in range(4):                       # 3 死拍武裝 + 第 4 拍執行點
            w.on_tick("refused")
            t[0] += 3.0                          # 6s 跨度尺用 3s/拍湊滿(不踩睡眠閘)
        self.assertEqual(fires, [])              # 遠端永不自動 spawn:第二閘有牙

    # ------------------------------------------------ M44 冷卻進位
    def test_cooldown_note_ceils_never_zero(self):
        t = [100.0]
        w = launch.Watch(dict(self.CFG), 0.5, now=lambda: t[0])
        w.attempts = 1
        w._cooldown_until = 109.5                # 剩 9.5s
        self.assertEqual(w.on_tick("refused"), "冷卻10s")   # 進位不截斷
        t[0] = 109.8
        w._cooldown_until = 110.0                # 剩 0.2s
        self.assertEqual(w.on_tick("refused"), "冷卻1s")    # 誠實:絕不說「冷卻0s」

    # ------------------------------------------------ M45 log 只落遷移
    def test_log_writes_only_on_note_change(self):
        hw = launch.HostWatch(dict(self.CFG), 0.5, out=io.StringIO())
        self.hosts.append(hw)
        log = hw.paths["log"]
        for _ in range(3):
            self.assertEqual(hw.on_tick(None), "開")
        with open(log, encoding="utf-8") as fh:
            lines = [l for l in fh if l.strip()]
        self.assertEqual(len(lines), 2)          # 武裝句 + 遷移「開」一行,不逐拍刷
        launch.write_halt(dict(self.CFG), 424242)
        self.assertEqual(hw.on_tick("refused"), "手動停機")
        with open(log, encoding="utf-8") as fh:
            self.assertEqual(len([l for l in fh if l.strip()]), 3)   # 遷移才落行

    # ------------------------------------------------ M56 三因子映像檔腿
    def test_third_kill_factor_is_image(self):
        # 三因子=活+建立時間+映像 python*:前兩因子全過、映像非 python 也照拒殺。
        # 走縫比照刀1 教義(副作用都走縫),零真子程序;README 資安紅線宣稱
        # 「有測試把關」從此刻起對這半條腿也成立。
        rec = {"pid": 4242, "created": 12345, "target": "127.0.0.1:9401"}
        self.setp(launch, "pid_alive", lambda pid: True)
        self.setp(launch, "get_created", lambda pid: 12345)
        self.setp(launch, "image_name", lambda pid: "C:\\Windows\\System32\\cmd.exe")
        self.assertFalse(launch.pid_matches(rec))
        self.setp(launch, "image_name", lambda pid: "C:\\Python313\\PYTHON.EXE")
        self.assertTrue(launch.pid_matches(rec))    # python* 大小寫不論

    # ------------------------------------------------ M58 構造棄權
    def test_make_watch_abstains_on_construction_failure(self):
        # F1:值守可以缺席,面板必須說話。構造面炸(磁碟/權限級 OSError)->
        # None + stderr 一句,絕不上拋殺面板。注:_lock_acquire 自己吞 OSError
        # (拿不到鎖=待機窗,不是崩潰),所以「構造炸」只能從更外層注入 ——
        # 用縫模擬 HostWatch 构造期拋異常,這正是 make_watch docstring 點名的場景。
        def boom(path):
            raise OSError(22, "disk gone (injected)")
        self.setp(launch, "_lock_acquire", boom)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertIsNone(launch.make_watch(dict(self.CFG), 0.5))
        self.assertIn("值守無法武裝", err.getvalue())

    # ------------------------------------------------ M63 真 halt 檔接線
    def test_real_halt_file_suppresses_host(self):
        # knife-1 用假縫測過「halt → 手動停機」;真檔 ↔ 真路徑這一段(README
        # 「手動停機最大」的載體)由本測鎖住:HostWatch 的 halt_present 若斷線,
        # [K] 之後值守會若無其事地把剛殺的 router 拉回來。
        hw = launch.HostWatch(dict(self.CFG), 0.5, out=io.StringIO())
        self.hosts.append(hw)
        launch.write_halt(dict(self.CFG), 424242)
        self.assertEqual(hw.on_tick(None), "手動停機")
        self.assertEqual(hw.on_tick("refused"), "手動停機")


class TestWatchdogR2B(unittest.TestCase):
    """round-2 面B(WD-B2)採納項鎖測:每條對一個它證明的突變存活者。
    N1/N2 冷卻表逐格行為鎖(0/10/30 + 熔斷;第 4 格行为不可達=常数鎖);
    N3/N3b decode 必入硬重置(投票腿+穩定腿);
    N4/N5 宿主接線身分(spawn/read_rec/matches 指錯=值守永遠救不了/永遠收編);
    N6 already 清 streak;N7 睡眠閘邊界公式 3*interval+2;
    N8 重啟事件 stderr+log 雙腿;N9 停用 diag stderr+log 雙腿。"""

    CFG = {"host": "127.0.0.1", "port": 9401, "mode": "friend", "names": {},
           "interval": 0.5}

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="wd-r2b-")
        self.env_saved = {k: os.environ.get(k) for k in
                          ("RMON_STATE_DIR", "RMON_NO_WATCH")}
        os.environ["RMON_STATE_DIR"] = self.state
        os.environ.pop("RMON_NO_WATCH", None)
        self.saved = []
        self.hosts = []

    def tearDown(self):
        for hw in self.hosts:
            try:
                hw.release()
            except Exception:
                pass
        for obj, name, val in reversed(self.saved):
            setattr(obj, name, val)
        for k, v in self.env_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.state, ignore_errors=True)

    def setp(self, obj, name, val):
        self.saved.append((obj, name, getattr(obj, name)))
        setattr(obj, name, val)

    def _bare(self, interval=2.0):
        # interval 2.0:拍距 4.0s 走在正常支(睡眠閘=8.0s),別再踩 R2 前的空牙坑
        t = [0.0]
        w = launch.Watch(dict(self.CFG), interval, now=lambda: t[0])
        w.halt_present = lambda: False
        w.read_rec = lambda: {"pid": 1, "created": 1, "target": "127.0.0.1:9401"}
        w.matches = lambda rec: False            # 血統俱備且已死:觸發閘全開
        w.spawn = lambda: ("failed", 2)
        return t, w

    # ------------------------------------------------ N1/N2 冷卻表逐格
    def test_cooldown_table_walk_exact_seconds(self):
        # README「第 k 次重啟後冷卻 0/10/30/90 秒」逐格走一遍:同拍語義下
        # spawn 當拍的 note 恰是該格全額(左端=表值,進位不改整數)。
        self.assertEqual(launch.WATCH_COOLDOWN, (0.0, 10.0, 30.0, 90.0))
        # 第 4 格行為不可達(熔斷詞壓前)——表本身由這條常數鎖兜住(誠實標注)。
        t, w = self._bare()
        for step in (4.0, 8.0, 12.0):          # 3 死拍 + 8s 跨度 -> t=12 武裝
            t[0] = step
            note = w.on_tick("refused")
        self.assertEqual(note, "重啟中1")
        t[0] = 16.0
        self.assertEqual(w.on_tick("refused"), "重啟中2")   # #1 失敗同拍攢回(0s 格)
        t[0] = 20.0
        self.assertEqual(w.on_tick("refused"), "冷卻10s")   # 第 2 格 = 10(全額在場)
        t[0] = 24.0
        self.assertEqual(w.on_tick("refused"), "冷卻6s")    # 拍距 4.0:誠實倒數
        t[0] = 32.0
        self.assertEqual(w.on_tick("refused"), "重啟中3")   # 冷卻盡,立刻再武裝
        t[0] = 36.0
        self.assertEqual(w.on_tick("refused"), "冷卻30s")   # 第 3 格 = 30(殺 12/10 變體)
        for step in (68.0, 72.0, 76.0):        # 冷卻盡後重攢(68 拍距 32>8 觸睡眠閘)
            t[0] = step
            note = w.on_tick("refused")
        self.assertEqual(note, "重啟中4")
        t[0] = 80.0
        self.assertEqual(w.on_tick("refused"), "熔斷(q→[S])")   # 第 4 次即封頂
        self.assertEqual(w.attempts, 4)

    # ------------------------------------------------ N3 decode 硬重置
    def test_decode_hard_resets_streak(self):
        # 先驗穩定腿(獨立小场景):decode 拍歸零重攢,不是凍結(N3b)
        t, w = self._bare()
        w._stable = launch.WATCH_STABLE_RESET
        t[0] = 4.0
        w.on_tick("refused")                   # gap=None 拍不扣穩定
        t[0] = 8.0
        w.on_tick("decode")
        self.assertIsNone(w._stable)           # decode 在硬重置集內(D1'(b))
        # 再驗投票腿:refused,refused,DECODE,refused... 跨度必自 decode 重計
        t, w = self._bare()
        spawns = []
        w.spawn = lambda: (spawns.append(1), ("failed", 2))[1]
        for step, kind in ((4.0, "refused"), (8.0, "refused"), (12.0, "decode"),
                           (16.0, "refused"), (20.0, "refused")):
            t[0] = step
            w.on_tick(kind)
        self.assertEqual(w._streak, 2)         # decode 歸零後從 t=16 重數
        t[0] = 24.0
        self.assertEqual(w.on_tick("refused"), "重啟中1")   # 武裝只許發生在這拍
        self.assertEqual(spawns, [])           # decode 前湊死的拍沒偷跑 spawn

    # ------------------------------------------------ N4/N5 宿主接線身分
    def test_host_wiring_identity(self):
        # 「Watch 狀態機 + HostWatch 接線」兩層分開測過,但接線本身指錯人
        # (spawn=None / read_rec=預設 None)全套+閘門都照綠 -- canary 一跳過,
        # 值守就永遠救不了或永遠收編。零 port 的身分鎖一條關死。
        hw = launch.HostWatch(dict(self.CFG), 0.5, out=io.StringIO())
        self.hosts.append(hw)
        self.assertIs(hw.w.spawn.__func__, launch.HostWatch._spawn)
        self.assertIs(hw.w.spawn.__self__, hw)
        self.assertIs(hw.w.read_rec, launch.read_pid)
        self.assertIs(hw.w.matches, launch.pid_matches)

    # ------------------------------------------------ N6 already 清 streak
    def test_already_clears_streak_not_counts(self):
        t, w = self._bare()
        w.spawn = lambda: ("already", 0)
        for step in (4.0, 8.0, 12.0):
            t[0] = step
            w.on_tick("refused")               # 武裝
        t[0] = 16.0
        w.on_tick("refused")                   # 執行:已在應 = 目標活著
        # 成功類清 streak 後本拍照樣投票(死訊已過時=重新數起):1,非舊 streak+1
        self.assertEqual(w._streak, 1)         # N6 變體(不清)在此=5
        self.assertEqual(w._first_t, 16.0)     # 錨點重釘
        self.assertEqual(w.attempts, 0)        # 不計不燒(D''7)
        self.assertEqual(w._stable, launch.WATCH_STABLE_RESET)

    # ------------------------------------------------ N7 睡眠閘邊界
    def test_sleep_gate_boundary_formula(self):
        t, w = self._bare()                    # interval 2.0 -> 邊界 3*2+2=8
        t[0] = 4.0
        w.on_tick("refused")                   # streak 1
        t[0] = 12.5                            # gap 8.5 > 8:睡眠閘觸發後本拍重數
        w.on_tick("refused")
        self.assertEqual(w._streak, 1)         # 10x interval 變體在此=2(舊帳沒清)
        self.assertEqual(w._first_t, 12.5)     # 錨點重釘在現拍
        t[0] = 16.5                            # gap 4.0 < 8:正常續票
        w.on_tick("refused")
        self.assertEqual(w._streak, 2)         # 「逢拍必歸零」變體在此=1

    # ------------------------------------------------ N8 重啟事件雙腿
    def test_restart_events_reach_stderr_and_log(self):
        # L2-A 鎖了 log 腿;stderr 腿(看板上看得見)也要鎖:重啟敘事兩邊都得在。
        hw = launch.HostWatch(dict(self.CFG), 0.5, out=io.StringIO())
        self.hosts.append(hw)

        def fake_core(cfg, now, assume_yes=False, emit=print, tally=None):
            emit("已啟動 router(pid 1),等本機 /healthz...")
            tally["outcome"] = "spawned_ok"
            return 0
        self.setp(launch, "do_start_core", fake_core)
        self.assertEqual(hw.w.spawn(), ("spawned_ok", 0))
        err = hw.out.getvalue()
        log = open(hw.paths["log"], encoding="utf-8").read()
        self.assertIn("等本機 /healthz", err)
        self.assertIn("等本機 /healthz", log)

    # ------------------------------------------------ N9 停用 diag 雙腿
    def test_disable_diag_reaches_stderr_and_log(self):
        # README 已停用條目白寫「stderr 也打一行」:log-only 變體必須紅。
        hw = launch.HostWatch(dict(self.CFG), 0.5, out=io.StringIO())
        self.hosts.append(hw)

        def boom():
            raise RuntimeError("halt boom")
        hw.w.halt_present = boom
        note = hw.on_tick(None)
        self.assertIn("已停用", note)
        err = hw.out.getvalue()
        log = open(hw.paths["log"], encoding="utf-8").read()
        self.assertIn("值守已停用(決策路異常)", err)
        self.assertIn("halt boom", err)
        self.assertIn("halt boom", log)


class TestWatchdogR2A(unittest.TestCase):
    """round-2 面A(WD-A2)採納項鎖測(修前紅=親自復現):
    P1-1 router.log 被他程序佔用 = 副作用路,降級不停用(D''4 白文「占用同理
         不殺重啟動作」;修法=DEVNULL 降級 + 誠實 emit 行);
    P2-2 封鎖期間該落檔的行積壓(帽 64,丟最舊),恢復後「延補:」補寫(D''4
         「累積重試帽≤N 行記憶體」);
    P2-3 spawn 的 ~27s 阻塞 = 已知阻塞非睡眠:拍距就地重錨,否則睡眠閘隔拍
         抹掉剛保住的 streak,D''7「冷卻末自然攢回」只在真時序下conditionally。"""

    CFG = {"host": "127.0.0.1", "port": 9401, "mode": "friend", "names": {},
           "interval": 0.5}

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="wd-r2a-")
        self.env_saved = {k: os.environ.get(k) for k in
                          ("RMON_STATE_DIR", "RMON_NO_WATCH")}
        os.environ["RMON_STATE_DIR"] = self.state
        os.environ.pop("RMON_NO_WATCH", None)
        self.saved = []
        self.hosts = []

    def tearDown(self):
        for hw in self.hosts:
            try:
                hw.release()
            except Exception:
                pass
        for obj, name, val in reversed(self.saved):
            setattr(obj, name, val)
        for k, v in self.env_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.state, ignore_errors=True)

    def setp(self, obj, name, val):
        self.saved.append((obj, name, getattr(obj, name)))
        setattr(obj, name, val)

    # ------------------------------------------------ P2-3 慢 spawn 不觸睡眠閘
    def test_slow_spawn_block_is_not_sleep(self):
        t = [0.0]
        w = launch.Watch(dict(self.CFG), 2.0, now=lambda: t[0])
        w.halt_present = lambda: False
        w.read_rec = lambda: {"pid": 1, "created": 1, "target": "127.0.0.1:9401"}
        w.matches = lambda rec: False
        spawns = []

        def slow_spawn():
            spawns.append(t[0])
            t[0] += 27.0                       # real:等待圈+探針零頭 ≈27s 阻塞
            return ("failed", 2)
        w.spawn = slow_spawn
        for step in (4.0, 8.0, 12.0):
            t[0] = step
            w.on_tick("refused")               # 武裝
        t[0] = 16.0
        w.on_tick("refused")                   # spawn #1(返回於 t=43),同拍再武裝
        self.assertEqual(w._streak, 4)
        t[0] = 47.0
        w.on_tick("refused")                   # spawn #2(返回於 74),冷卻 10s 起算
        for step in (78.0, 82.0):              # 冷卻已盡:streak 若被睡眠閘抹掉,這裡現形
            t[0] = step
            w.on_tick("refused")
        self.assertEqual(len(spawns), 3)       # 「冷卻末自然攢回」必須在真時序下成立

    # ------------------------------------------------ P1-1 佔 log 停用是背叛
    def test_router_log_held_degrades_not_disables(self):
        # Notepad 開 router.log(share=READ)是用戶照 README 除錯的常態動作;
        # 值守恰好在最需要救機的瞬間被一本記事本殺死 = D''4 白文違反(實測
        # PermissionError 13 -> disable+release,修前本測紅在此)。
        hw = launch.HostWatch(dict(self.CFG), 2.0, out=io.StringIO())   # 拍距 4s 走在正常支
        self.hosts.append(hw)
        lp = launch.logfile()
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        open(lp, "a").close()
        k32 = ctypes.windll.kernel32
        h = k32.CreateFileW(lp, 0x80000000, 0x1, None, 3, 0x0, None)  # GENERIC_READ|SHARE_READ
        self.assertNotEqual(h, -1)
        try:
            state = []

            def healthz_seq(c, timeout=2.0):
                state.append(1)
                return (False, None, "refused") if len(state) == 1 else (True, "9.9.9", "http")

            class DummyProc:
                pid = 424242
            self.setp(launch, "router_py", lambda: __file__)
            self.setp(launch, "healthz_at", healthz_seq)
            self.setp(launch.subprocess, "Popen", lambda *a, **k: DummyProc())
            self.setp(launch, "port_owner_pid", lambda port: None)   # 證不了埠主:保守不釘檔
            hw.w.read_rec = lambda: {"pid": 4242, "created": 1,
                                     "target": "127.0.0.1:9401"}     # 血統俱備(已死)
            hw.w.matches = lambda rec: False
            tt = [0.0]
            hw.w.now = lambda: tt[0]
            note = ""
            for step in (4.0, 8.0, 12.0, 16.0):
                tt[0] = step
                note = hw.on_tick("refused")   # t=16 真走 do_start_core(撞被佔的 log)
            self.assertNotIn("已停用", note)                     # 決策路不得自殺
            self.assertFalse(hw.w._disabled)
            self.assertIsNotNone(hw.lock_fd)                    # 鎖還在手,值守繼續
            self.assertIn("重啟中", note)                        # 降級後節奏照走
            self.assertIn("router.log 暫時開不了", hw.out.getvalue())  # 誠實宣告
        finally:
            k32.CloseHandle(h)

    # ------------------------------------------------ P2-2 封鎖積壓 + 延補
    def test_blocked_log_backfills_after_recovery(self):
        hw = launch.HostWatch(dict(self.CFG), 0.5, out=io.StringIO())
        self.hosts.append(hw)
        logp = hw.paths["log"]
        hw.on_tick(None)                       # 正常首拍:武裝句+「開」落檔
        os.replace(logp, logp + ".seed")       # 把既有 log 移開(其內容非本測主角)
        os.mkdir(logp)                         # 任何佔用:路徑變目錄,寫入必敗
        launch.write_halt(dict(self.CFG), 4242)
        self.assertEqual(hw.on_tick("refused"), "手動停機")      # 決策路無感
        launch.clear_halt(dict(self.CFG))
        self.assertIn("事件紀錄:不可用", hw.on_tick(None))        # 降級如實宣告
        os.rmdir(logp)                         # 佔用解除
        for _ in range(20):                    # 節流試探自癒(%16),不等人工
            note = hw.on_tick(None)
        with open(logp, encoding="utf-8") as fh:
            log = fh.read()
        self.assertIn("事件紀錄恢復", log)
        self.assertIn("延補: 手動停機", log)                     # D''4 累積重試帽
        self.assertIn("延補: 事件紀錄:不可用", log)
        self.assertNotIn("不可用", hw.on_tick(None))             # footer 隨即清乾淨


if __name__ == "__main__":
    try:
        _res = unittest.main(verbosity=2, exit=False).result
    finally:
        tearDownModule()
    # M3-A/P1-N2:紅套必須紅著退出 -- run_all_tests 的 rc 閘是朋友唯一的警報,
    # exit=False 原樣回 shell 等於把紅測認證成綠(passed-count 過 floor 更救不了)。
    sys.exit(0 if _res.wasSuccessful() else 1)
