# Strata —— router + monitor 單 repo 雙包

同一個 repo 裡的**兩個平級包裝**,仍是**兩支獨立程序、各自版本**:

| 目錄 | 是什麼 | 版本來源 | 說明 |
|---|---|---|---|
| [`router/`](router/README.md) | OpenAI/Anthropic 反代 + 智慧分流(`router.py`) | `router.py` 的 `VERSION`(發行標籤 `v*`) | [router/README.md](router/README.md) |
| [`monitor/`](monitor/README.md) | 一條龍 terminal 監控面板(`rmon.py` + `launch.py`) | `rmon.py` 的 `VERSION` | [monitor/README.md](monitor/README.md) |

**repo 合併 ≠ 程序合併,這是不可退讓的界線**:面板絕不進 router 進程——
router 過載的時刻正是最需要「另一支程序」讀數的時刻,rmon 的檔案級零 POST
保證與終端限定零網頁教義也都靠「分開」才成立。兩包之間唯一的縫是
`launch.py` 找到 router 目錄(本 repo 的姊妹目錄 `../router` 預設,
舊的獨立 `strata-router` 姊妹目錄仍 fallback,`STRATA_ROUTER_DIR` 可覆寫)。

## 驗證一切(朋友與審查者都用這條)

```
python run_all_tests.py
```

先跑**打包紅線閘**(`audit_package.py`:追蹤檔白名單集合等式+盤上存在性、
機密 grep **worktree/index/HEAD 三道視圖**、機器-local 設定必被 ignore、
`--selftest` 合成 canary 自證閘仍有牙),再依序跑 router 的 smoke 與 monitor 的測試,
並對每套測試的**條數下限**把關——紅線測「消失」比紅測更危險,所以少一條就 fail。
全套對 ANSI 代碼頁(cp950/Big5)fail-safe:紅測只准印成 mojibake,不准在 verdict 前炸掉儀表板。

## 資安紅線(整個 repo 的結構性約束)

- **機器-local 永不進 git**:`router/router.json`(真實箱位)、`*.keys.json`
  (DPAPI 金鑰)、`monitor/monitor.json`(監控目標座標)、`*.log`。
  `.gitignore` 把它們全擋,`audit_package.py` 每次驗「擋著的事實」。範本用
  `router/router.remote.example.json` 與 `monitor/monitor.json.example`。
- 金鑰進出的唯一門是 `router/router.py --set-key`(DPAPI 加密落盤)。
- 朋友鏡像應得的檔案集合 = `audit_package.py` 的白名單,**集合等式**,不多不少。
- **行尾**:`.gitattributes` 把 `!-start.bat` 鎖定為 checkout 必 CRLF(cmd 的硬要求)、
  `.py` 必 LF——朋友拿到什麼形態是 repo 的性質,不取決於各人机器的 `core.autocrlf`。

## 版本與發行列車

- router 升級:`router/router.py` 的 `VERSION` → tag `vX.Y.Z`(既有歷史,不改寫)。
- monitor 升級:`monitor/rmon.py` 的 `VERSION` → tag `rmon-X.Y.Z`(`v*` 序列是 router 專用,
  兩包各自發車互不撞號);router 帳目終態增減時同步
  `rmon.py` 的 `TERMS` 與 `SCHEMA_KNOWN_MAX`(見 monitor README 的同步儀式)。
- 合併前歷史完整保留(`git log --follow router/router.py` 追得回去)。

## 給朋友(鏡像/自用)

需要 Python 3.8+,純 stdlib。clone 後:`router/` 照
[router/README.md](router/README.md) 快速開始;整組一條龍就雙擊** repo 根目錄的
`!-start.bat`**(統一入口,委派 `monitor/launch.py go`;`monitor/!-start.bat` 保留,
兩者等價)。兩包同一棵樹時面板自動找到 router;
只要其中一包,複製那個子資料夾走也照常單獨運作。
