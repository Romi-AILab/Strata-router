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
import collections     # deque:watchdog.log 封鎖期積壓帽(D''4 累積重試,R2A/P2-2)
import glob
import hashlib
import json
import msvcrt
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


# M2-B/P3-4:同一句「兩條出路」在 status/[S]/[G]/[C] 四處共用 -- 朋友不該在
# 任何一處看到只提環境變數的死路,另一條(姊妹目錄)同样是正路。
_NO_ROUTER_HINT = ("先設環境變數 STRATA_ROUTER_DIR,或把 router 放在本目錄的姊妹資料夾"
                   "(monorepo 的 router/,或獨立的 strata-router/)。")


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


def _console_input_attached():
    """stdin 是真的 console 輸入柄才算數。NUL 字元裝置能過 isatty()(CPython
    只認 GetFileType==CHAR),但它沒有 console mode、msvcrt 讀不到 q -- 常駐面板
    會永不結束(M3-B/P2-1:`go < /dev/null`/`<nul`/部分排程壳踩中)。"""
    try:
        mode = ctypes.c_ulong()
        return bool(ctypes.windll.kernel32.GetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-10), ctypes.byref(mode)))
    except Exception:
        return False


def _stdin_tty():
    try:
        if not (sys.stdin and sys.stdin.isatty()):
            return False
    except Exception:
        return False
    return _console_input_attached()

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


def write_pid(pid, target=None):
    """血統記錄:pid+created(+target,刀0 契約)。原子寫(F-P2-5:值守每拍
    read_pid,不得見到空檔/半檔);tmp+os.replace 比照 router 金鑰檔先例。"""
    rec = {"pid": pid, "created": get_created(pid)}
    if target:
        rec["target"] = target
    os.makedirs(rmon.state_dir(), exist_ok=True)
    tmp = pidfile() + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        os.replace(tmp, pidfile())
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def rec_shape_ok(rec):
    """記錄是否具血統佐證價值(D4''/D5''):pid+created+target 三者俱備;
    畸形 -> 值守視同無記錄(收編態),[K] 死分支可清(零佐證價值)。"""
    return (isinstance(rec, dict) and isinstance(rec.get("pid"), int)
            and isinstance(rec.get("created"), int)
            and isinstance(rec.get("target"), str))


def clear_pid():
    try:
        os.remove(pidfile())
    except OSError:
        pass

# ---------------------------------------------------------------- 探活

def healthz_at(cfg, timeout=2.0):
    """回 (alive, version|None, kind|None)。503=活著但全盒 DOWN,仍算活。
    任何底層炸點都吃下(F1:router 沒跑時本殼必須还能說話,不能 traceback)。
    cfg 由呼叫方注入 -- do_start_core 不得重讀 monitor.json(E-P2-1)。"""
    try:
        st, body = rmon.http_get_safe(cfg["host"], cfg["port"], "/healthz", timeout)
    except rmon.Dead as d:
        return False, None, d.kind
    try:
        ver = rmon.clean(str(json.loads(body.decode("utf-8", "replace")).get("version") or ""))
    except Exception:
        ver = None
    return True, ver or "?", ("http503" if st == 503 else "http200")


def healthz(timeout=2.0):
    return healthz_at(_cfg_or_default(), timeout)


def healthz_local(port, timeout=2.0):
    """[S] 的上線確認只看本機(loopback 上的這個 port),不去摸 monitor.json
    可能指向的遠端 -- 遠端摸不到不代表本機沒起來(R1-A/F10)。"""
    try:
        st, _ = rmon.http_get_safe("127.0.0.1", port, "/healthz", timeout)
        return st in (200, 503)
    except rmon.Dead:
        return False


def port_owner_pid(port, _af_inet=2, _tbl_owner_all=3, _listen=2):
    """port 的 TCP LISTEN 持有者 pid -- kernel 事實,蓋檔唯一 oracle(D8'')。
    GetExtendedTcpTable 唯讀列舉:零 connect、零 bind;查無/任何異常 -> None。
    (時間窗启发式已被 round-2 面 F PoC 推翻:輸家 import 慢一點照樣 clobber,
    唯有埠主身分是零競態的;探針實證 owner==self 於自 bind 的 93xx 回真值。)"""
    try:
        class _Row(ctypes.Structure):
            _fields_ = [("state", ctypes.c_uint32), ("laddr", ctypes.c_uint32),
                        ("lport", ctypes.c_uint32), ("raddr", ctypes.c_uint32),
                        ("rport", ctypes.c_uint32), ("owner", ctypes.c_uint32)]
        size = ctypes.c_uint32(0)
        iph = ctypes.windll.iphlpapi
        iph.GetExtendedTcpTable(None, ctypes.byref(size), 0, _af_inet, _tbl_owner_all, 0)
        if not size.value:
            return None
        buf = ctypes.create_string_buffer(size.value)
        if iph.GetExtendedTcpTable(buf, ctypes.byref(size), 0, _af_inet, _tbl_owner_all, 0) != 0:
            return None
        n = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32)).contents.value
        for i in range(n):
            row = ctypes.cast(ctypes.addressof(buf) + 4 + i * 24,
                              ctypes.POINTER(_Row)).contents
            lport = ((row.lport >> 8) & 0xFF) | ((row.lport & 0xFF) << 8)
            if row.state == _listen and lport == int(port) and row.owner:
                return int(row.owner)
        return None
    except Exception:
        return None


def status_lines():
    out = []
    cfg = _cfg_or_default()
    rp = router_py()
    out.append("router 目錄:%s  (%s)" % (router_dir(), "在" if os.path.exists(rp) else "找不到 router.py!"))
    if not os.path.exists(rp):
        out.append("  要換位置:%s" % _NO_ROUTER_HINT)
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


def do_start_core(cfg, now, assume_yes=False, emit=print, tally=None):
    """[S]/值守共用的啟動核心(D8''/E-P2-1/F-P2-7):
    cfg = 呼叫方注入快照 -- 核心零重讀 monitor.json(值守凍幀期間藏不起 input());
    now = 注入時鐘(值守給 time.monotonic,時鐘跳變不製造無界凍窗/假失敗);
    emit = 展示參數化(選單 print;值守 stderr+log,零 stdout 教義)。
    蓋檔=kernel 埠主 oracle(D8''):只有 port 的 LISTEN 持有者確認是自家子才釘
    pidfile;查詢異常/表查無=證明不了,保守不寫+誠實失敗(D''2 條款 2,L2-A/P2-1
    修正本檔舊註的寬鬆版) -- 雙窗競態(E6)任何時序變量都別想
    再把死 pid/別人贏家釘進血統檔。值守路徑永不 assume_yes(D8''白文)。
    tally = 結果出參載體(刀2):HostWatch 用它把結局分成 already(不計不燒)/
    spawned_ok/adopted/kept/failed 餵給 Watch._spawn_now;選單呼叫者不傳,零感。"""
    def _done(rc, outcome):
        if tally is not None:
            tally["outcome"] = outcome
        return rc
    if not os.path.exists(router_py()):
        emit("找不到 %s -- %s" % (router_py(), _NO_ROUTER_HINT))
        return _done(2, "failed")
    alive, ver, kind = healthz_at(cfg)
    if alive:
        clear_halt(cfg)                # D5':任何成功 do_start(含已在應捷徑=go 預路徑)清 halt
        emit("/healthz 已在應(v%s,目標 %s:%s),不重複啟動。" % (ver, cfg["host"], cfg["port"]))
        return _done(0, "already")
    if not rmon._is_loopback_host(cfg["host"]) and not assume_yes:
        emit("注意:監控目標指向 %s:%s(遠端),但 [S] 會在「本機」起一個 router。" % (cfg["host"], cfg["port"]))
        if _ask("要在本機起 router 嗎? y/N: ") != "y":
            emit("保留原樣,沒起。")
            return _done(0, "kept")    # 保留原樣 != 成功:不清 halt、不餵穩定累計
    log = None                        # 副作用路(D''4 末句「router.log 占用同理不殺重啟動作」):
    try:                              # 本機 log 被他程序佔用(Notepad 開 router.log 除錯
        os.makedirs(rmon.state_dir(), exist_ok=True)   # 是用戶常態,R2A/P1-1);實測
        log = open(logfile(), "ab")                    # PermissionError 13 會殺死整個值守
    except OSError as exc:                             # -- 降級:log=None,子程序改 DEVNULL
        emit("router.log 暫時開不了(%s):本次啟動改用 DEVNULL 輸出,"   # 敘事行照走 emit 進
             "值守事件仍記 watchdog.log。" % rmon.clean(str(exc))[:120])  # watchdog.log
    logfh = log if log is not None else subprocess.DEVNULL   # Popen 落點:真檔或 DEVNULL;
                                                             # DEVNULL 是 int(-3)無 .close(),
                                                             # 故 close 只認 log 不認 logfh
    # 與手動啟動對齊(2026-11-04 切版前實測發現):router 的 --config 沒有預設值,
    # 生产中是帶 --config router.json 跑的。殼起時若 router.py 旁有 router.json 就
    # 帶上(只看存在,內容零讀取);金鑰檔會跟著 --config 同目錄規則,與現行一致。
    cmd = [sys.executable, router_py()]
    cfgj = os.path.join(router_dir(), "router.json")
    if os.path.exists(cfgj):
        cmd += ["--config", cfgj]
    try:
        p = subprocess.Popen(cmd, cwd=router_dir(),
                             stdout=logfh, stderr=logfh, stdin=subprocess.DEVNULL,
                             creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
    except OSError as exc:
        emit("起動失敗:%s" % exc)
        return _done(2, "failed")
    finally:
        if log is not None:           # 子程序已繼承自己的複製,父端真檔可關;
            log.close()               # DEVNULL 分支 log=None,無檔可關(修 R2A 紅)
    target = "%s:%s" % (cfg["host"], cfg["port"])
    emit("已啟動 router(pid %d),等本機 /healthz..." % p.pid)
    t0 = now()
    deadline = t0 + 20.0
    while now() < deadline:
        time.sleep(0.5)
        if healthz_local(cfg["port"]):
            if not pid_alive(p.pid):
                # E-P3-1 第三文案:不是「贏家收編」,是自家子上線後自己崩了
                emit("自家子上線後退出了(port 已無人應):視同崩潰,未記 pid -- 看 %s。" % logfile())
                return _done(2, "failed")
            owner = port_owner_pid(cfg["port"])
            if owner is None:
                # D''2 條款2(L2-A/P2-1):埠主證明不了就不寫血統、不宣稱上線 --
                # 保守失敗;服務多半其實活,下一次 [S]/面板會認成「已在應」自癒。
                emit("本機 /healthz 已在應,但 kernel 埠主查詢失敗(無法證明埠歸誰):"
                     "不寫 pid、不宣稱上線(保守);先看日誌或 [C] 自檢,再 [S] 一次"
                     "通常會直接認成「已在應」。")
                return _done(2, "failed")
            if owner != p.pid:
                emit("port %d 由 pid %s 持有(非本殼子進程):收編 -- 本殼不殺它、"
                     "也不會對它自動重啟;要本殼管它請先停掉真正持有者再 [S]。" % (cfg["port"], owner))
                clear_halt(cfg)
                return _done(0, "adopted")
            write_pid(p.pid, target=target)
            emit("上線了:v%s(本機 port %d;輸出導向 %s)"
                 % (healthz_at(cfg)[1] or "?", cfg["port"], logfile()))
            clear_halt(cfg)
            return _done(0, "spawned_ok")
        if not pid_alive(p.pid):
            break
    spent = int(now() - t0)
    if not pid_alive(p.pid):
        emit("進程已退出(%.0fs)-- 看 %s 前幾行(常見:port 被佔、router.json 格式)。" % (spent, logfile()))
        return _done(2, "failed")
    write_pid(p.pid, target=target)   # 子仍在=身分事實,[K] 必須reachable(此檔三因子恆真)
    emit("進程還在但本機 /healthz %.0fs 沒回應 -- 看 %s;可用 [K] 停掉重試。" % (spent, logfile()))
    return _done(2, "failed")


def do_start(assume_yes=False):
    # 選單路徑維持 time.time 語意不動(F-P2-7 界線);值守直調 do_start_core+monotonic。
    return do_start_core(_cfg_or_default(), time.time, assume_yes=assume_yes)


def _taskkill(pid, force=False):
    cmd = ["taskkill", "/PID", str(pid)] + (["/F"] if force else [])
    return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


WATCH_STREAK_MIN = 3        # D1'(b):空端口 >=3 拍
WATCH_STREAK_SPAN = 6.0     # ...且首拍至今跨度 >=6s(白文語意,鎖測罩)
WATCH_BUDGET = 4            # D6:4 次重啟額度,熔斷後仍守不再觸發
WATCH_COOLDOWN = (0.0, 10.0, 30.0, 90.0)   # 第 k 次嘗試後的固定冷卻表(可審計、可鎖測)
WATCH_STABLE_RESET = 600.0  # 成功後連續觀察滿 10 分鐘穩定才歸零額度


class Watch:
    """值守狀態機(刀1)。純拍輸入(面板快照的 Dead kind 或 None=活),純 note 輸出
    (footer 片段;rmon 端最終 byte-lock 是刀3 的事,條款8 詞彙表)。
    D''1 兩段式觸發:第 N 拍武裝只回「重啟中 n」(此幀如實畫出),真 spawn 推遲到
    下一拍入口執行 -- 阻塞期螢幕凍的正是這幀;cancel_pending()=等待拍間的使用者
    姿態優先。所有副作用走縫(read_rec/matches/halt_present/other_lock_pid/spawn/
    on_disable),刀2 接檔與鎖;測試把縫全部 fake 化。
    D''4 scope 兩分:決策路(佐證/halt/冷卻/spawn)異常 -> 停用+on_disable 釋鎖
    (恰一次,不重試復活);副作用路(事件紀錄)降級只認 log_broken 旗標(刀2 置)。"""

    def __init__(self, cfg, interval, now=None):
        self.cfg = cfg
        self.target = "%s:%s" % (cfg["host"], cfg["port"])
        self.interval = float(interval)
        self.now = now or time.monotonic
        self.loopback = rmon._is_loopback_host(cfg["host"])
        self.read_rec = read_pid                 # 縫:每拍讀 pidfile 事實(收編口徑 D')
        self.matches = pid_matches               # 縫:三因子身分(與殺教義同尺)
        self.halt_present = lambda: False        # 縫:刀2 接 watch-<tag>.halt
        self.other_lock_pid = lambda: None       # 縫:刀2 接鎖元資料(offset 1024)
        self.spawn = None                        # 縫 -> ("spawned_ok"|"already"|"failed", rc)
        self.on_disable = None                   # 縫:刀2 在此釋放鎖(條款3 餓死鏈)
        self.holds_lock = True
        self.log_broken = False                  # 刀2 的降級態旗標(條款4)
        self.attempts = 0
        self._streak = 0
        self._first_t = None
        self._last_t = None
        self._cooldown_until = 0.0
        self._pending = False
        self._stable = None
        self._disabled = False
        self.disable_exc = None                  # 停用例外 diag(L2-A/P3-4b):給 HostWatch 落檔
        self._disable_note = None                # 停用 footer 快照(D''9 條款9)

    def cancel_pending(self):
        """等待拍間按 q:明確離上面板優先(D''1),投票一併重來。"""
        self._pending = False
        self._streak, self._first_t = 0, None

    def disable(self):
        """決策路終止態(D12):不重試復活;on_disable 恰一次(刀2 釋鎖)。"""
        if not self._disabled:
            self._disabled = True
            self._pending = False
            if self.on_disable:
                try:
                    self.on_disable()
                except Exception:
                    pass

    def _rescue_ok(self):
        """條件(c)+ D''5 shape 先行:缺檔/畸形/target 不符 -> 無佐證(收編態);
        佐證俱備但三因子為真(卡死/還活)同屬不准救,但不是收編。"""
        rec = self.read_rec()
        if not rec_shape_ok(rec) or rec.get("target") != self.target:
            return None, False
        return rec, self.matches(rec)

    def _suppressed(self, t):
        """(a) 觸發點自判 loopback(雙閘,不靠構造點)+(d) 抑制表。"""
        if not self.loopback:
            return True
        if self.halt_present():
            return True
        if self.attempts >= WATCH_BUDGET:
            return True                          # 熔斷 != 停用:仍值守仍持鎖
        if not self.holds_lock:
            return True
        if t < self._cooldown_until:
            return True
        rec, alive_rec = self._rescue_ok()
        return rec is None or alive_rec

    def _spawn_now(self, t):
        outcome, _rc = self.spawn() if self.spawn else ("failed", 2)
        self._last_t = self.now()   # spawn 阻塞(~27s)=已知阻塞不是睡眠:拍距就地重錨,
                                    # 否則下一拍睡眠閘抹掉剛保住的 streak(R2A/P2-3),
                                    # D''7「冷卻末自然攢回」就只在假時序測試裡成立
        if outcome == "already":
            self._streak, self._first_t = 0, None    # 恢復=成功類:清 streak
            self._stable = WATCH_STABLE_RESET        # 「已在應」不計不燒(D''7)
            return
        self.attempts += 1                           # 真 spawn 起點計額度+起冷卻鐘(D''7)
        self._cooldown_until = t + WATCH_COOLDOWN[self.attempts - 1]
        if outcome in ("spawned_ok", "adopted"):
            self._streak, self._first_t = 0, None    # 成功 -> 清 streak+起穩定歸零(D''7)
            self._stable = WATCH_STABLE_RESET        # adopted=目標在跑(只是非自家子),穩定照走
        # 失敗:保 streak(D''7「失敗保 streak(冷卻閘壓住,冷卻末自然攢回)」,
        # L2-A/P3-3 修正舊版誤實裝的清零) -- 冷卻一過,下一死拍立刻再武裝。

    def _vote(self, kind, t):
        if kind is None or kind in ("http", "decode"):
            self._streak, self._first_t = 0, None    # 活/http/decode(squat)=硬重置
            return
        if kind in ("dns", "reset"):
            return                                   # 不投票也不清零(D1'(b) 聯集代數)
        if kind in ("refused", "timeout"):
            if self._streak == 0:
                self._first_t = t                    # 6s 帽=首拍至今,非滑窗
            self._streak += 1                        # refused/timeout 交替不清零

    def _note(self, t):
        """條款8 優先序:已停用 > 手動停機 > 熔斷 > 重啟中 > 冷卻 > 待機 > 收編 > 降級 > 開。
        (已停用由 on_tick 首行攔;「非目標(遠端)」死詞已刪 -- 構造閘在刀2,此處不回執。)"""
        if self.halt_present():
            return "手動停機"
        if self.attempts >= WATCH_BUDGET:
            return "熔斷(q→[S])"
        if self._pending:
            return "重啟中%d" % (self.attempts + 1)
        left = self._cooldown_until - t
        if left > 0:
            return "冷卻%ds" % (int(left) + (1 if left > int(left) else 0))
        if not self.holds_lock:
            return "待機(他窗值守pid %s)" % (self.other_lock_pid() or "?")
        rec, _alive = self._rescue_ok()
        if rec is None and self._streak > 0:
            return "只提醒(收編;端口空時q→[S]以殼參數重啟)"
        if self.log_broken:
            return "事件紀錄:不可用"
        return "開"

    def on_tick(self, kind):
        if self._disabled:
            return self._disable_note or "已停用(異常)"
        try:
            t = self.now()
            gap = None if self._last_t is None else t - self._last_t
            self._last_t = t
            if self._pending:
                self._pending = False
                if not self._suppressed(t):          # spawn 前復檢抑制態(D''7)
                    self._spawn_now(t)
            elif gap is not None and gap > 3 * self.interval + 2:
                self._streak, self._first_t = 0, None    # 睡眠閘:歸零;穩定累計凍結不动
            elif gap is not None and self._stable is not None:
                if kind is None:
                    self._stable -= gap                  # 只算觀察到的 alive 拍距(F-P3-8)
                    if self._stable <= 0:
                        self.attempts, self._stable = 0, None
                elif kind in ("refused", "timeout", "http", "decode"):
                    self._stable = None                  # 「連續」的兑现(L2-A/P3-2):
                # dns/reset=凍結不計(與投票同口徑)    #   死拍歸零重攢,不準湊距離
            self._vote(kind, t)
            if not self._pending and self._streak >= WATCH_STREAK_MIN \
                    and self._first_t is not None \
                    and t - self._first_t >= WATCH_STREAK_SPAN \
                    and not self._suppressed(t):
                self._pending = True
            return self._note(t)
        except Exception as exc:
            self.disable_exc = rmon.clean(repr(exc))[:160]   # diag 落檔載體(P3-4b)
            self.disable()                                   # 決策路異常=停用+釋鎖(D''4;副作用路不經此)
            self._disable_note = "已停用(異常·已試%d次)" % self.attempts  # D''9 快照
            return self._disable_note


WATCH_LOG = "watchdog.log"
LOCK_META_OFF = 1024


def watch_tag(cfg):
    """目標防指紋(sha1[:12],與 rmon cache 先例同構):鎖/halt 各掛 own target,
    多目標各守各的對(日誌單檔共用 -- README 限界條款9)。"""
    return hashlib.sha1(("%s:%s" % (cfg["host"], cfg["port"])).encode("utf-8")).hexdigest()[:12]


def watch_paths(cfg):
    d = rmon.state_dir()
    tag = watch_tag(cfg)
    return {"lock": os.path.join(d, "watch-%s.lock" % tag),
            "halt": os.path.join(d, "watch-%s.halt" % tag),
            "log": os.path.join(d, WATCH_LOG)}


def _lock_acquire(path):
    """值守單例鎖(D4'/條款3;語義三面全親測):seek(0) 鎖 byte0 用 LK_NBLCK
    -- 非阻塞(拒采 LK_LOCK:病態探針未復現,且待機每拍重試制下非阻塞語意已足),
    被搶 OSError(13) -> None。鎖到手才把元資料 pid 寫 offset 1024
    (E1「先寫後鎖鎖錯位」陷阱:紀律 seek(0)->lock->seek(1024)->write,AST 鎖測罩)。
    鎖區僅 1 byte:offset 1024 在鎖外,待機窗可直接讀「他窗值守 pid N」(探針 B)。
    close 即 OS 自動釋放(探針 C'),故無殭屍清理器。"""
    fd = None
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_BINARY, 0o644)
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        os.lseek(fd, LOCK_META_OFF, os.SEEK_SET)
        os.write(fd, ("%-24d" % os.getpid())[:24].encode("ascii"))  # 定寬(L2-A/P3-1):舊長 pid 殘字不許與新短 pid 黏成幽魂
        return fd
    except OSError:
        if fd is not None:
            try:
                os.close(fd)        # 沒鎖到=空手關檔,下拍重試乾淨
            except OSError:
                pass
        return None


def _lock_release(fd):
    if fd is None:
        return
    try:
        os.lseek(fd, 0, os.SEEK_SET)   # 解鎖必回鎖點(探針 C:位點 1024 直接 UNLCK -> Errno13)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    except OSError:
        pass
    try:
        os.close(fd)                   # close 亦讓 OS 自動釋放,雙保險
    except OSError:
        pass


def lock_owner_pid(path):
    """待機詞「他窗值守 pid N」:讀 offset 1024(鎖區外,探針 B 實測可讀);
    任何問題 -> None(footer 顯 'pid ?')。"""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_BINARY)
        try:
            os.lseek(fd, LOCK_META_OFF, os.SEEK_SET)
            blob = os.read(fd, 16)
        finally:
            os.close(fd)
        pid = int(blob.split()[0])
        return pid if pid > 0 else None
    except (OSError, ValueError, IndexError):
        return None


def write_halt(cfg, pid):
    """[K] 真殺成功 -> 停機意圖落檔(D5':無 TTL,只有成功 do_start 清)。
    原子寫(比照 pidfile F-P2-5:值守每拍都在看這個檔)。"""
    path = watch_paths(cfg)["halt"]
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"pid": int(pid), "ts": int(time.time()),
                       "target": "%s:%s" % (cfg["host"], cfg["port"])}, fh)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def clear_halt(cfg):
    """成功 do_start 清 halt(D5');清不動靜默 -- halt 是雙保險+意圖展示載體,
    失敗不得反咬「啟動成功」主路徑(副作用路語意)。"""
    try:
        os.remove(watch_paths(cfg)["halt"])
    except OSError:
        pass


WD_LOG_MAX = 256 * 1024
WD_RETRY_EVERY = 16      # 降級態重試帽(條款4):每 16 拍贖一回,不逐拍撞牆


class HostWatch:
    """值守宿主(刀2):把 Watch 接到真檔案 -- 鎖(條款3:待機每拍重試、停用必釋鎖)、
    halt(D5' 停機意圖)、watchdog.log(stderr+log 零 stdout;256KB os.replace 輪轉;
    副作用路異常 -> 降級非停用,條款4 節流自癒),以及 spawn 縫接 do_start_core
    (tally 出參分類,值守路徑永不 assume_yes D8''白文)。
    rmon 只認 on_tick/cancel_pending 兩個方法(刀3 單鉤子),餘皆這裡私事。"""

    def __init__(self, cfg, interval, out=None):
        self.cfg = cfg
        self.paths = watch_paths(cfg)
        self.out = out if out is not None else sys.stderr
        self.lock_fd = _lock_acquire(self.paths["lock"])
        self.w = Watch(cfg, interval)
        self.w.holds_lock = self.lock_fd is not None
        self.w.halt_present = lambda: os.path.exists(self.paths["halt"])
        self.w.other_lock_pid = lambda: lock_owner_pid(self.paths["lock"])
        self.w.spawn = self._spawn
        self.w.on_disable = self._on_disable
        self._last_note = None
        self._tick_no = 0
        self._armed = False
        self._pend = collections.deque(maxlen=64)   # D''4 累積重試帽:封鎖期 ≤64 行,
                                                    # 滿則丟最舊(誠實限界,非無界記憶體)

    def cancel_pending(self):
        """等待拍間 q=使用者明確離上面板優先(D''1;刀3 接鍵)。"""
        self.w.cancel_pending()

    def _out(self, line):
        try:
            self.out.write(line + "\n")
            self.out.flush()
        except Exception:
            pass                          # 通知流死不能拖垮決策路(面板要活著說話)

    def _write_log(self, line):
        path = self.paths["log"]
        try:
            d = os.path.dirname(path)
            if d:
                os.makedirs(d, exist_ok=True)
            if os.path.exists(path) and os.path.getsize(path) > WD_LOG_MAX:
                # 必用 replace(D-P3-4:os.rename 遇既存 .old 在 Windows 拋錯 ->
                # 第二次輪轉變自殺);.old 被 Notepad 佔 -> 本拍降級,稍後自癒
                os.replace(path, path + ".old")
            with open(path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), line))
            return True
        except OSError:
            return False                  # 副作用路:降級(條款4),絕不殺決策

    def _notify(self, line):
        self._out(line)
        self._log(line)

    def _log(self, line):
        """log 腿統一落點(R2A/P2-2+P3-4):失敗 -> 積壓入帽、只降級從不停用;
        成功 -> 清降級旗標(不等 %16 節流)並把積壓按最舊優先補寫(加「延補:」前綴,
        尸檢媒體因此不丟章)。停用窗的積壓隨窗終結 —— 帽有界,誠實交代過。"""
        if not self._write_log(line):
            self.w.log_broken = True
            self._pend.append(line)
            return False
        if self.w.log_broken:
            self.w.log_broken = False
        while self._pend:
            old = self._pend.popleft()
            if not self._write_log("延補: " + old):
                self._pend.appendleft(old)
                self.w.log_broken = True
                return True
        return True

    def _spawn(self):
        tally = {}
        rc = do_start_core(self.cfg, time.monotonic, assume_yes=False,
                           emit=self._notify,   # 重啟事件 stderr+log 雙寫(L2-A/P2-2):
                           tally=tally)         #   watchdog.log 是尸檢媒體,缺頁不得
        outcome = tally.get("outcome", "failed")
        if outcome in ("spawned_ok", "adopted", "already"):
            return outcome, rc
        return "failed", rc

    def _on_disable(self):
        _lock_release(self.lock_fd)       # 條款3:停用必釋鎖(活持鎖者停用餓死鏈堵點)
        self.lock_fd = None
        self.w.holds_lock = False
        diag = (" -- " + self.w.disable_exc) if getattr(self.w, "disable_exc", None) else ""
        self._notify("值守已停用(決策路異常)%s:鎖已釋放,其他窗可接手。" % diag)

    def release(self):
        """面板任何出口(q/Ctrl+C/異常)交還鎖(L2-A/P1-1):[G] 同進程再武裝
        絕不能被自己的幽魂鎖擋死(footer 還會謊稱「他窗值守pid <自己>」)。冪等。"""
        _lock_release(self.lock_fd)
        self.lock_fd = None
        self.w.holds_lock = False

    def on_tick(self, kind):
        self._tick_no += 1
        if self.lock_fd is None and not self.w._disabled:   # 待機窗每拍重試接手(條款3);
            self.lock_fd = _lock_acquire(self.paths["lock"])  # 已停用窗永不再搶(L2-A/P1-2),
            self.w.holds_lock = self.lock_fd is not None      #   否則「停用釋鎖」被自己還魂
        if self.w.log_broken and self._tick_no % WD_RETRY_EVERY == 0:
            self._log("事件紀錄恢復")        # 節流試探:_log 成功即清旗標+補積壓
        note = self.w.on_tick(kind)
        if not self._armed and self.w.holds_lock:
            self._armed = True            # D9':首次武裝逃生門句(stderr+log 各一)
            self._notify("窗開值守已武裝:只守 %s。不想值守:Set RMON_NO_WATCH=1 "
                         "後重開窗(q→[G] 無效)。" % self.w.target)
        if note != self._last_note:       # 狀態遷移才落一行(不逐拍刷 Noise)
            self._log(note)
        self._last_note = note
        return note


def make_watch(cfg, interval):
    """值守構造閘(arm 雙閘之一;觸發點另有自判,D'):None=本窗今夜無值守,面板照樣。
    僅兩個理由:非 loopback(紅線)、RMON_NO_WATCH(逃生門,重開窗生效)。
    構造本身炸(磁碟/權限)-> None + stderr 一句:值守可以缺席,面板必須說話(F1)。"""
    if not rmon._is_loopback_host(cfg["host"]):
        return None
    flag = (os.environ.get("RMON_NO_WATCH") or "").strip().lower()
    if flag not in ("", "0", "false", "no"):
        return None
    try:
        return HostWatch(cfg, interval)
    except Exception as exc:
        try:
            sys.stderr.write("值守無法武裝(棄權不重試,面板不受影響):%s\n" % exc)
        except Exception:
            pass
        return None


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
        if rec_shape_ok(rec):
            # D5'':死而完整的記錄=值守血統佐證([S] 覆寫重釘;停機意圖由 halt 檔
            # 載體),刪除會讓「准救目標」無聲降成收編態 -- 保留。
            print("pid 記錄屬本殼過去 router(進程已退出):保留作值守佐證,"
                  "[S] 重啟會覆寫它;確定要清除請手動刪 %s。" % pidfile())
            return 0
        clear_pid()
        print("pid 檔為舊/畸形格式(無佐證價值),已清掉;本來就沒在跑(本殼範圍內)。")
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
        halt_ok = write_halt(_cfg_or_default(), rec["pid"])  # D5':[K] 真殺成功=停機意圖落檔(無 TTL)
        print("已終端(pid %d)。" % rec["pid"])
        if not halt_ok:
            print("! 停機意圖未能落檔:本機值守窗可能把剛殺的 router 自動拉起 -- "
                  "不想被拉起:Set RMON_NO_WATCH=1 後重開窗,或關掉值守窗。")
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
    print("router.py       : %s" % ("在" if os.path.exists(router_py())
                                    else "缺!%s" % _NO_ROUTER_HINT))
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
    管線下會永不結束(R3-P2-2,違反本殼「管線一律視為不」教義);降單拍後走選單。
    「真終端」以 console 輸入柄為準:NUL 字元裝置過得了 isatty,過不了這道雙卡
    (M3-B/P2-1)。"""
    cfg = _cfg_or_default()
    try:
        alive, ver, kind = healthz()
        if not alive:
            if not rmon._is_loopback_host(cfg["host"]):
                print("監控目標是遠端 %s:%s -- [G] 不在本機起 router,直接掛面板(摸不到會說原因)。"
                      % (cfg["host"], cfg["port"]))
            elif not os.path.exists(router_py()):
                print("找不到 %s -- 面板照掛;要這殼代管服務:%s" % (router_py(), _NO_ROUTER_HINT))
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
        # 值守接線(刀4):構造閘產物直掛面板;None=本窗不守(遠端/NO_WATCH/構造敗)
        watch = make_watch(cfg, cfg["interval"])
        try:
            rmon.do_live(cfg, cfg["interval"], rmon._term_ok(False), watch=watch)
        except KeyboardInterrupt:
            pass
        except Exception as exc:                  # 面板再怎么壞,不拖垮服務與殼(R2 整合紅線)
            print("面板出了意外:%s -- 服務不受影響;可跑 [C] 自檢。" % rmon.clean(str(exc))[:120])
        finally:
            if watch is not None:                 # 出口必交鎖(L2-A/P1-1):[G] 同進程再武裝的命脈
                try:
                    watch.release()
                except Exception:
                    pass
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
