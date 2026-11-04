#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""launch.py -- Strata 操作殼(整套裡唯一准「起停進程」的地方)。

紅線(與 rmon.py 對稱):
  * 永不 import router,也不 import 任何 router 模組 -- router.py 只以子程序起。
  * 永不讀取金鑰檔(*keys*.json)與 router.json 的內容 -- 只看「存在與大小」。
    金鑰進出的唯一門是 router.py --set-key(在它自己的程序裡)。
  * 無任何 HTTP 寫入:操作全是進程級(subprocess / taskkill);探活復用 rmon 的
    http_get_safe(結構上只發 GET,且任何底層炸點都收斂成 Dead,不吐 traceback)。
  * 殺無赦禁令:pid 檔帶「pid + 進程建立時間」雙因子;[K] 殺前必須 pid 活、
    建立時間對得上、映像檔名是 python*.exe 三者全中才動手,否則視為過期拒殺
    (消滅 PID 複用誤殺,R1-A/F2 + R1-B/F7,spec §5.2)。
  * 本殼被 kill 不拖垮 router(子程序是 DETACHED,自成生命;也因此「優雅停」
    對殼起的 router 物理上送不到 -- 誠實宣告,不裝死路為生路,R1-A/F3)。

命令:launch.py [go|start|stop|status|menu]  (無參數 = go:一條龍 服務+同窗面板)
"""
import ctypes
import ctypes.wintypes   # FILETIME/DWORD 屬子模組,只 import ctypes 拿不到(R1 自審latent)
import glob
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rmon  # noqa: E402  (借用 state_dir/http_get_safe/clean/控制台小工具;無 POST)

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
_PROCESS_QUERY_LIMITED = 0x1000
_STILL_ACTIVE = 259


def router_dir():
    d = os.environ.get("STRATA_ROUTER_DIR")
    if d:
        return d
    parent = os.path.dirname(rmon.my_dir())
    # merge-1: inside the monorepo the router lives in the sibling package
    # ../router -- but the legacy standalone sibling (strata-router) stays a
    # live fallback: an operator mid-cutover keeps BOTH layouts working, and
    # only STRATA_ROUTER_DIR above them both decides otherwise.
    for cand in ("router", "strata-router"):
        if os.path.exists(os.path.join(parent, cand, "router.py")):
            return os.path.join(parent, cand)
    return os.path.join(parent, "strata-router")   # neither found: legacy hint


def router_py():
    return os.path.join(router_dir(), "router.py")


def pidfile():
    return os.path.join(rmon.state_dir(), "router.pid.json")


def logfile():
    return os.path.join(rmon.state_dir(), "router.log")


_cfg_default_warned = False


def _cfg_or_default():
    """monitor.json 缺失/損壞時的兜底。R3-P3-4:內建預設 port 恰是生產常見 port,
    無言 fallback 等於讓「未配置」狀態直連生產而不宣告 -- 首次觸發必須宣告,
    不假裝設定一直都在(與 rmon「不去猜」教義對齊)。"""
    global _cfg_default_warned
    try:
        return rmon.load_cfg()
    except rmon.ConfigError as exc:
        if not _cfg_default_warned:
            _cfg_default_warned = True
            print("! monitor.json 缺失/損壞(%s) -- 本殼暫以內建預設 127.0.0.1:8088 行事;"
                  "請由 monitor.json.example 複製一份 monitor.json。"
                  % rmon.clean(str(exc)).replace("\n", " ")[:140])
        return {"host": "127.0.0.1", "port": 8088, "mode": "friend", "names": {},
                "interval": rmon.INTERVAL_DEF}


def _stdin_tty():
    try:
        return bool(sys.stdin) and sys.stdin.isatty()
    except Exception:
        return False

# ---------------------------------------------------------------- 進程事實
# 本檔 ctypes 只做三件事:GetProcessTimes(建立時間)、QueryFullProcessImageNameW
# (映像檔身分)、OpenProcess 存活判定。全為殺無辜防護與狀態事實,無網路。

def _open_process(pid):
    try:
        return ctypes.windll.kernel32.OpenProcess(_PROCESS_QUERY_LIMITED, False, int(pid)) or None
    except Exception:
        return None


def pid_alive(pid):
    if not isinstance(pid, int) or pid <= 0:
        return False
    h = _open_process(pid)
    if not h:
        return False
    try:
        code = ctypes.c_ulong()
        if not ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code)):
            return False
        return code.value == _STILL_ACTIVE
    except Exception:
        return False
    finally:
        try:
            ctypes.windll.kernel32.CloseHandle(h)
        except Exception:
            pass


def get_created(pid):
    """進程建立時間(FILETIME int);拿不到回 None(舊格式兼容用)。"""
    if not isinstance(pid, int) or pid <= 0:
        return None
    h = _open_process(pid)
    if not h:
        return None
    try:
        k32 = ctypes.windll.kernel32
        c = ctypes.wintypes.FILETIME()
        e = ctypes.wintypes.FILETIME()
        k = ctypes.wintypes.FILETIME()
        u = ctypes.wintypes.FILETIME()
        if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            return None
        return (c.dwHighDateTime << 32) | c.dwLowDateTime
    except Exception:
        return None
    finally:
        try:
            k32.CloseHandle(h)
        except Exception:
            pass


def image_name(pid):
    if not isinstance(pid, int) or pid <= 0:
        return None
    h = _open_process(pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = ctypes.wintypes.DWORD(len(buf))
        if ctypes.windll.kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    except Exception:
        return None
    finally:
        try:
            ctypes.windll.kernel32.CloseHandle(h)
        except Exception:
            pass


def pid_matches(rec):
    """rec = {"pid":N,"created":FILETIME|null} -> 是否仍是「我們記錄的那個進程」。
    三因子:活著 + 建立時間相符 + 映像檔是 python*。任何一环缺/不符 => False(拒殺)。"""
    if not isinstance(rec, dict):
        return False
    pid, created = rec.get("pid"), rec.get("created")
    if not isinstance(pid, int) or pid <= 0 or not isinstance(created, int):
        return False
    if not pid_alive(pid):
        return False
    if get_created(pid) != created:
        return False
    img = (image_name(pid) or "").lower()
    return os.path.basename(img).startswith("python") if img else False


def read_pid():
    try:
        with open(pidfile(), "r", encoding="utf-8") as fh:
            rec = json.load(fh)
        if isinstance(rec, dict) and isinstance(rec.get("pid"), int):
            return rec
    except Exception:
        pass
    return None


def write_pid(pid):
    rec = {"pid": pid, "created": get_created(pid)}
    os.makedirs(rmon.state_dir(), exist_ok=True)
    with open(pidfile(), "w", encoding="utf-8") as fh:
        json.dump(rec, fh)


def clear_pid():
    try:
        os.remove(pidfile())
    except OSError:
        pass

# ---------------------------------------------------------------- 探活

def healthz(timeout=2.0):
    """回 (alive, version|None, kind|None)。503=活著但全盒 DOWN,仍算活。
    任何底層炸點都吃下(F1:router 沒跑時本殼必須还能說話,不能 traceback)。"""
    cfg = _cfg_or_default()
    try:
        st, body = rmon.http_get_safe(cfg["host"], cfg["port"], "/healthz", timeout)
    except rmon.Dead as d:
        return False, None, d.kind
    try:
        ver = rmon.clean(str(json.loads(body.decode("utf-8", "replace")).get("version") or ""))
    except Exception:
        ver = None
    return True, ver or "?", ("http503" if st == 503 else "http200")


def healthz_local(port, timeout=2.0):
    """[S] 的上線確認只看本機(loopback 上的這個 port),不去摸 monitor.json
    可能指向的遠端 -- 遠端摸不到不代表本機沒起來(R1-A/F10)。"""
    try:
        st, _ = rmon.http_get_safe("127.0.0.1", port, "/healthz", timeout)
        return st in (200, 503)
    except rmon.Dead:
        return False


def status_lines():
    out = []
    cfg = _cfg_or_default()
    rp = router_py()
    out.append("router 目錄:%s  (%s)" % (router_dir(), "在" if os.path.exists(rp) else "找不到 router.py!"))
    if not os.path.exists(rp):
        out.append("  要換位置:設環境變數 STRATA_ROUTER_DIR。")
    out.append("監控目標:%s:%s(%s)" % (cfg["host"], cfg["port"],
                                       "本機" if rmon._is_loopback_host(cfg["host"]) else "遠端"))
    alive, ver, kind = healthz()
    rec = read_pid()
    matched = pid_matches(rec)
    out.append("/healthz:%s%s" % (("活(v%s)" % ver) if alive else ("不回應(%s)" % kind),
                                   " -- 注意:全盒 DOWN 時也回 503,仍是活" if kind == "http503" else ""))
    if rec is None:
        out.append("pid 檔:無(本殼沒起過 router,或已清)。")
    elif matched:
        out.append("pid 檔:%d -- 建立時間與映像檔身分相符(本殼記錄的 router)。" % rec["pid"])
    elif pid_alive(rec.get("pid")):
        out.append("pid 檔:%d -- 該 pid 有東西在,但身分不符(PID 已被回收重用?)視為過期,[K] 會拒殺它。" % rec["pid"])
    else:
        out.append("pid 檔:%d -- 進程已不在(檔過期)。" % rec["pid"])
    if alive and matched:
        out.append("判定:執行中(pid %d 由本殼記錄且身分相符)。" % rec["pid"])
    elif alive:
        out.append("判定:有人在應,但不是本殼記錄的那個進程 -- 可能手動起的或別的機器。"
                   "[K] 不會動它(不殺不認識的進程)。")
    elif (not alive) and rec is not None and pid_alive(rec.get("pid")) and not matched:
        out.append("判定:pid 檔過期(進程沒在應或已被重用),按 [S] 可重新起一台。")
    elif (not alive) and matched:
        out.append("判定:進程在但 /healthz 不回應 -- 可能在啟動中或卡死。等 10 秒再看;"
                   "仍不回應可用 [K](強停,記憶體帳目會消失)。")
    else:
        out.append("判定:沒在跑。按 [S] 啟動。")
    out.append("router 輸出紀錄:%s" % logfile())
    return out

# ---------------------------------------------------------------- start / stop

def _ask(prompt):
    try:
        return input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):   # 管線/排程/Ctrl+C 一律視為「不」(R1-A/F9)
        return "n"


def do_start(assume_yes=False):
    if not os.path.exists(router_py()):
        print("找不到 %s -- 先設 STRATA_ROUTER_DIR,或把 router 放在本目錄的姊妹資料夾"
              "(monorepo 的 router/,或獨立的 strata-router/)。" % router_py())
        return 2
    cfg = _cfg_or_default()
    alive, ver, kind = healthz()
    if alive:
        print("/healthz 已在應(v%s,目標 %s:%s),不重複啟動。" % (ver, cfg["host"], cfg["port"]))
        return 0
    if not rmon._is_loopback_host(cfg["host"]) and not assume_yes:
        print("注意:監控目標指向 %s:%s(遠端),但 [S] 會在「本機」起一個 router。" % (cfg["host"], cfg["port"]))
        if _ask("要在本機起 router 嗎? y/N: ") != "y":
            print("保留原樣,沒起。")
            return 0
    os.makedirs(rmon.state_dir(), exist_ok=True)
    log = open(logfile(), "ab")
    # 與手動啟動對齊(2026-11-04 切版前實測發現):router 的 --config 沒有預設值,
    # 生产中是帶 --config router.json 跑的。殼起時若 router.py 旁有 router.json 就
    # 帶上(只看存在,內容零讀取);金鑰檔會跟著 --config 同目錄規則,與現行一致。
    cmd = [sys.executable, router_py()]
    cfgj = os.path.join(router_dir(), "router.json")
    if os.path.exists(cfgj):
        cmd += ["--config", cfgj]
    try:
        p = subprocess.Popen(cmd, cwd=router_dir(),
                             stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                             creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
    except OSError as exc:
        print("起動失敗:%s" % exc)
        return 2
    finally:
        log.close()
    write_pid(p.pid)
    print("已啟動 router(pid %d),等本機 /healthz..." % p.pid)
    t0 = time.time()
    deadline = t0 + 20.0
    while time.time() < deadline:
        time.sleep(0.5)
        if healthz_local(cfg["port"]):
            print("上線了:v%s(本機 port %d;輸出導向 %s)" % (healthz()[1], cfg["port"], logfile()))
            return 0
        if not pid_alive(p.pid):
            break
    spent = int(time.time() - t0)
    if not pid_alive(p.pid):
        print("進程已退出(%.0fs)-- 看 %s 前幾行(常見:port 被佔、router.json 格式)。" % (spent, logfile()))
        return 2
    print("進程還在但本機 /healthz %.0fs 沒回應 -- 看 %s;可用 [K] 停掉重試。" % (spent, logfile()))
    return 2


def _taskkill(pid, force=False):
    cmd = ["taskkill", "/PID", str(pid)] + (["/F"] if force else [])
    return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def do_stop(assume_yes=False):
    rec = read_pid()
    if rec is None:
        alive, ver, kind = healthz()
        if alive:
            print("有人在應(v%s)但不是本殼起的 -- 本殼不殺不認識的進程。去它本機停。" % ver)
            return 2
        print("本來就沒在跑(本殼範圍內)。")
        return 0
    if not pid_matches(rec):
        if pid_alive(rec.get("pid")):
            print("pid %d 活著但身分不符(建立時間/映像檔對不上)-- PID 可能被回收重用,"
                  "本殼拒殺(不誤傷無辜)。確認後可自行刪除 %s 再操作。" % (rec["pid"], pidfile()))
            return 2
        clear_pid()
        print("pid 檔過期,已清掉;本來就沒在跑(本殼範圍內)。")
        return 0
    # 殼起的 router 是 DETACHED:無控制台可收關閉事件,taskkill 不帶 /F 必敗
    # (R1-A/F3 實測)。不演「優雅停」的假象,直接說清楚再問。
    print("本殼起的 router 沒有控制台,「優雅停」物理上送不到 -- 只能強制終端。")
    print("後果:記憶體中的帳目/黏性表即刻消失(金鑰與設定在盤上,不受影響)。")
    ans = "y" if assume_yes else _ask("強制終端 pid %d? y/N: " % rec["pid"])
    if ans != "y":
        print("保留原樣,沒動它。")
        return 0
    _taskkill(rec["pid"], force=True)
    for _ in range(8):
        time.sleep(0.5)
        if not pid_alive(rec["pid"]):
            break
    if not pid_alive(rec["pid"]):
        clear_pid()
        print("已終端(pid %d)。" % rec["pid"])
        return 0
    print("連 /F 都殺不掉?查工作管理員。")
    return 2

# ---------------------------------------------------------------- [R] 進程樹 / [C] 檢查

def py_procs():
    """[R]:列本機 python 進程與命令行。PowerShell 只讀。"""
    ps = ("Get-CimInstance Win32_Process -Filter \"Name='python.exe' or Name='pythonw.exe'\" | "
          "Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=20)
        data = json.loads(r.stdout.decode("utf-8", "replace").strip() or "[]")
    except Exception:
        return None
    if isinstance(data, dict):
        data = [data]
    return data or []


def show_procs():
    procs = py_procs()
    if procs is None:
        print("查不到(PowerShell 不可用?)。改看 %s 與工作管理員。" % logfile())
        return
    rec = read_pid()
    known = rec.get("pid") if isinstance(rec, dict) else None
    matched = pid_matches(rec)                 # [R] 與 [1] 用同一把三因子尺,不打臉(R2-C)
    for p in procs:
        cmd = rmon.clean((p.get("CommandLine") or "")).strip()
        tag = ""
        if p.get("ProcessId") == known:
            tag = ("  <-- 本殼記錄的 router" if matched
                   else "  <-- pid 檔記載,但身分未核可(過期/被重用?)")
        elif "router.py" in cmd:
            tag = "  <-- 別的 router 進程(不是本殼起的)"
        elif "rmon.py" in cmd:
            tag = "  (監控面板)"
        print("pid %-8s 父 %-8s %s%s" % (p.get("ProcessId"), p.get("ParentProcessId"),
                                         (cmd[:110] or "(命令行拿不到)"), tag))
    if not procs:
        print("沒有任何 python 進程。")


def check_cfg():
    """[C]:只查存在/大小/可解析,永不打印內容;金鑰檔與 router.json 零讀取。"""
    print("== 設定檢查(零內容讀取:金鑰檔/router.json 只看存在) ==")
    print("router.py       : %s" % ("在" if os.path.exists(router_py()) else "缺!設 STRATA_ROUTER_DIR"))
    if os.path.exists(router_py()):
        m = None
        with open(router_py(), "r", encoding="utf-8") as fh:
            for _ in range(400):
                ln = fh.readline()
                if not ln:
                    break
                m = re.match(r'^VERSION\s*=\s*["\x27]([^"\x27]+)', ln)
                if m:
                    break
        print("router 原始碼版本: %s" % (m.group(1) if m else "?"))
    rd = router_dir()
    p = os.path.join(rd, "router.json")
    if os.path.exists(p):
        print("%-15s: 在(%d bytes;內容未讀,紅線)" % ("router.json", os.path.getsize(p)))
    else:
        print("%-15s: 不存在 -- router 會用預設/參數啟動" % "router.json")
    for p in sorted(glob.glob(os.path.join(rd, "*.keys.json"))):
        print("%-15s: 在(%d bytes;內容未讀,紅線)" % (os.path.basename(p), os.path.getsize(p)))
    try:
        cfg = rmon.load_cfg()
        print("monitor.json    : OK -> %s:%s(mode=%s[文檔性,當前無行為差], interval=%ss)"
              % (cfg["host"], cfg["port"], cfg["mode"], cfg["interval"]))
    except rmon.ConfigError as exc:
        print("monitor.json    : %s" % str(exc).replace("\n", "\n                "))
    rec = read_pid()
    print("pid 檔          : %s" % ("無" if rec is None else
          ("pid %s,%s" % (rec["pid"], "身分相符" if pid_matches(rec) else "過期/身分不符"))))

# ---------------------------------------------------------------- menu

MENU = """
  [G] 服務+面板(自動確認上線,同窗立刻看面板)
  [1] 狀態      [S] 啟動 router   [K] 停止 router
  [3] 診斷 diagnose(去識別化)
  [R] python 進程樹            [C] 設定檢查(零內容讀取)
  [q] 離開(關窗不拖垮 router)"""


def run_console():
    """[G] / go:一個 terminal 一整套服務(R2 使用者指示)——先確認 router 上線
    (本機目標且找得到 router.py 才自動起;遠端只掛面板),然後同窗直接進 live。
    面板 q 回選單;router 的生命週期仍只歸 [S]/[K] 管,殼/窗死了服務不死。
    非互動 stdin(管線/排程/CI)不掛常駐面板 -- 面板的 q 只出得自真終端,
    管線下會永不結束(R3-P2-2,違反本殼「管線一律視為不」教義);降單拍後走選單。"""
    cfg = _cfg_or_default()
    try:
        alive, ver, kind = healthz()
        if not alive:
            if not rmon._is_loopback_host(cfg["host"]):
                print("監控目標是遠端 %s:%s -- [G] 不在本機起 router,直接掛面板(摸不到會說原因)。"
                      % (cfg["host"], cfg["port"]))
            elif not os.path.exists(router_py()):
                print("找不到 %s -- 面板照掛;要這殼代管服務請設 STRATA_ROUTER_DIR。" % router_py())
            else:
                do_start()                        # 本機目標:自動起+等上線(自己會報進度)
    except KeyboardInterrupt:                     # 等上線 20s 期間 Ctrl+C 不許裸 traceback(R3-P3-5)
        print("\n(啟動等待被中斷 -- 服務未受影響;可選單 [G]/[S] 重試。)")
        return 0
    print("\nStrata 一條龍:目標 %s:%s · q 回選單 · 面板只讀(零 POST)\n"
          % (cfg["host"], cfg["port"]))
    if not _stdin_tty():
        print("(偵測到非互動 stdin:不掛常駐面板,只印單拍;常駐面板請在真終端視窗看。)")
        _run_rmon(["once"])
    else:
        try:
            rmon.do_live(cfg, cfg["interval"], rmon._term_ok(False))
        except KeyboardInterrupt:
            pass
        except Exception as exc:                  # 面板再怎么壞,不拖垮服務與殼(R2 整合紅線)
            print("面板出了意外:%s -- 服務不受影響;可跑 [C] 自檢。" % rmon.clean(str(exc))[:120])
    alive, ver, kind = healthz()
    print("(面板結束:router %s。[G] 再看面板 · [K] 停服務 · [q] 離開視窗而服務繼續跑。)"
          % (("在線 v%s" % ver) if alive else ("不回應(%s)" % kind)))
    return 0


def _run_rmon(args):
    print("")
    try:
        sys.stdout.flush()      # 子程序直接寫 fd;先衝掉父程序緩衝,重導向時順序才對(R3-b)
    except Exception:
        pass
    subprocess.call([sys.executable, os.path.join(rmon.my_dir(), "rmon.py")] + args)


def menu():
    rmon._console_nice(True)   # 本殼也怕快速編輯凍窗(B3-O6)
    try:
        while True:
            print("\nStrata 操作殼  --  rmon 唯讀、本殼管進程;金鑰只進 router.py --set-key")
            print(MENU)
            try:
                c = input("> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return 0
            try:
                if c in ("1", "status"):
                    for ln in status_lines():
                        print(ln)
                elif c == "s":
                    do_start()
                elif c == "k":
                    do_stop()
                elif c == "g":
                    run_console()
                elif c == "3":
                    _run_rmon(["diagnose"])
                elif c == "2":
                    print("[2] 已升級為 [G](同窗一條龍:自動確認上線+面板)。")
                elif c == "r":
                    show_procs()
                elif c == "c":
                    check_cfg()
                elif c in ("q", "quit", "exit"):
                    return 0
                else:
                    print("不認識的選項。q 離開。")
            except KeyboardInterrupt:
                print("(中斷,回到選單)")
            except Exception as exc:      # 選單韌性:單項壞了不拖垮整顆殼(R1-A/F1)
                print("這步出了意外:%s -- 選單還在,可先跑 [C] 自檢。" % rmon.clean(str(exc))[:120])
    finally:
        rmon._console_nice(False)


def main(argv=None):
    try:                     # 同 rmon:小編碼終端不許崩潰(真實事故:cp950 遇 ≈)
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    cmd = (argv or sys.argv[1:] or ["go"])[0]
    if cmd == "start":
        return do_start()
    if cmd == "stop":
        return do_stop()
    if cmd == "status":
        for ln in status_lines():
            print(ln)
        return 0
    if cmd == "go":            # 預設:服務+面板同窗,然後停在選單
        run_console()
        return menu()
    if cmd == "menu":
        return menu()
    print("用法:launch.py [go|start|stop|status|menu]")
    return 2


if __name__ == "__main__":
    sys.exit(main())
