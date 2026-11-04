#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tests_rmon.py -- monitor v0.1.4 驗收(tests first red line:全部 temp dir、零真實 port)。

跑法:python tests_rmon.py -v
涵蓋:3.8 相容(AST+compile 雙閘)、結構性零 POST、清洗(含 R1 換行偽造/Cf/代理字元)、
寬度、設定紅線(含植樁清洗/巢狀拒絕)、presence 降級、tok/s 估算、帳目三態、禮讓閘三態、
借用估計、replay 管線、diagnose 去識別化(含 target 遮罩)、HTML 逃脫、
launch(探活不炸/pid 三因子/EOF 誠實/金鑰零讀取)、bat 純 ASCII+CRLF、零 ESC 金絲雀。
"""
import ast
import builtins
import contextlib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
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
        launch.write_pid(os.getpid())
        rec = launch.read_pid()
        self.assertIsInstance(rec, dict)
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
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = launch.do_start(assume_yes=True)
            out = buf.getvalue()
        finally:
            launch.subprocess, launch.healthz, launch.healthz_local = real
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

        def fake_live(cfg, interval, color):
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


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2, exit=False)
    finally:
        tearDownModule()
