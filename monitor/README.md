# Strata Monitor(rmon v0.2.0)

Strata router 的**一條龍終端**:雙擊啟動 → 服務自動上線 → **同一個視窗**即時顯示
遠端閒不閒置、算力夠不夠、兩台混合每秒實際吐多少 token。體驗基準是 cc-switch /
Strata 原生監控:**即時、無打扰、全在 terminal**。這是儀表板,**不是告警哨兵**——
沒有通知、沒有值守承諾;也不開網頁(v0.1.1 起 HTML 介面已整套移除)。

搭配 [Strata-router](https://github.com/Romi-AILab/Strata-router) v1.2.17 使用
(舊版 router 也能看——v1.2.13 缺的欄位會誠實標註口徑,不會假裝有)。

## 快速開始(朋友版)

1. 需要 Python 3.8+(純 stdlib,無任何第三方套件、無監聽 port)。
2. 把這個資料夾整個複製到你電腦任何位置。
3. 複製 `monitor.json.example` 為 `monitor.json`,填 router 的 `host` 與 `port`
   (跨機用 Tailscale IP;你的機器只要看得到 router 的 HTTP 口就夠,**不需要**任何金鑰)。
   `mode` 欄是文檔性標記(記「這台是誰的機器」),無行為差異。
4. 雙擊 `!-start.bat`:本機目標會**自動起 router(若沒跑)並立刻同窗顯示 live 面板**;
   遠端目標只掛面板。`q` 回操作選單;`[K]` 停服務;關窗不拖垮服務(detached)。
   管線/排程/CI 等**非互動環境**下,`go` 不會掛常駐面板(那會永不結束)——自動改印
   單拍後進選單,選單遇 EOF 自行退出,任何腳本環境都不會在這裡掛死。

## 檔案

| 檔案 | 角色 |
|---|---|
| `rmon.py` | 監控面板本體。**結構性零 POST**(只用 http.client 發 GET),唯讀 |
| `launch.py` | 操作殼 + 一條龍入口 `go`:起停 router 只准在這裡,只准子程序/taskkill(永不 import router);router.py 旁有 `router.json` 時自動帶 `--config`(router 該參數無預設值;只驗存在,內容零讀取);`[K]` 有「三因子身分核可、殺無赦禁令」 |
| `monitor.json` | 你的目標設定(host/port/顯示名)。**這裡不准出現金鑰**——欄名含 key/token/secret 會被直接拒絕(含 `names` 的鍵);`names` 只收純字串,巢狀物件直接拒絕 |
| `monitor.json.example` | 範本 |
| `!-start.bat` | 雙擊入口(= `launch.py go`;repo 根目錄的 `!-start.bat` 是等價統一入口,委派到這裡) |
| `tests_rmon.py` | 測試:`python tests_rmon.py`(全綠才算装好) |

## 命令(一切都在 terminal 裡,本專案不開網頁)

```
python launch.py go          # 一條龍:確認服務上線 + 同窗 live 面板 + 選單(bat 同此)
python launch.py menu        # 只開選單
python rmon.py               # once:看一眼就走(跨次執行會接上一次的速率快取)
python rmon.py live          # 儀表板常駐(2s 刷新;q 離開)
python rmon.py diagnose      # 去識別化 JSON(box-A/box-B,實址與目標座標一律剝除)
python rmon.py --replay FILE # 回放拍序列(JSON 單拍或 JSONL),不碰網路
```

求助流程也是 terminal 原生:跑 `python rmon.py diagnose` 把輸出文字直接貼给对方
(預設已去識別化,連監控目標都不出現;`--full` 才出實址,公開發文前想清楚)。

`live` 期間快速編輯游標會自動關掉(選文字不會凍住畫面),退出全部還原。

**v0.2.0 起 `live` 是固定框原地重繪**:每一拍在螢幕同一塊區域覆寫(游標絕對歸位,
永不發「上移 N 行」那類相對移動——錯誤不累積,每拍自我修復),scrollback 不再成長。
框上不上線**以讀回驗證為準**(GetConsoleMode 讀回 VT 位,不信「設定呼叫成功了」):
驗證不到的終端(輸出被重導、管線、怪異舊 conhost)降回 v0.1.4 的逐拍追加,輸出
逐字元相同;降級宣告走 stderr,`live > log` 存檔的 stdout 一個位元都不多。
不想要框:`set RMON_NO_FRAME=1` 即刻得 v0.1.4 體驗(不需改碼或發版)。
視窗太矮放不下整框:該拍自動退回追加並說明,拉高視窗即回復(下拍自癒)——
寧可退化成會滾,不截掉帳目燈。
顏色只在 Windows Terminal 自動開(設了 `NO_COLOR` 環境變數則連 WT 也不自動開);
legacy cmd 用素色,要色加 `--color`(真的會開該終端的 VT 輸出位並**讀回確認**——
讀回成功才有真色,讀回失敗會宣告「色彩強制關閉」改素色,不賭裸 escape;退出還原)。

## 面板上每個數字的口徑(誠實教義)

| 顯示 | 來源 | 口徑 |
|---|---|---|
| `≈N tok/s(估算:字節/4,近 Xs)` | router 逐盒 `stats.bytes_out` 相鄰兩拍差分 ÷4 | **估算**,與 Strata 前端同口径;永不冒充實測;跨度 >3 分鐘不計算。「本窗轉發 +N」走同一把時間尺。舊 router 無 bytes_out 欄時直說「無估算腿」,不會永遠「預熱中」 |
| `生成 N tok/s(盒實測)` / `上一單 N tok/s(盒實測,現空置)` / `最近實測 N(忙閒未知)` | 盒 `/v1/status` 的 `last_timings.predicted_per_second`(llama.cpp 實測解碼速率) | 是**上一個請求**的實測值;盒空置時自動改標殘值,不裝現況;盒連 `serving` 都缺欄時標「忙閒未知」,None 不准冒充「在忙」 |
| `近期首字 avg/p95(近 n 筆)` | router 逐盒最近 30 個完成請求的 TTFB 環 | 按請求取樣;舊 router 無此欄時退回終身均值並**標明含探測** |
| `禮讓閘:關/開/盲/從未證明空閒/問不到` | 首訊號是 router 自己的 `accepting`(它到底放不放行),再看 `reported_age_s` vs `status_interval`(盲窗 = max(3×間隔,5s)) | fail-closed:**unknown 永遠不是 idle**;「開」只在 router 確實在放行且狀態新鮮時出現(缺 si 欄時標「間隔假設1.0s」);拒放時原因(`ext_streak`)**直接附在閘行**,遠端盒沒有借用者行也看得到「為什麼」 |
| `盒上有非經本 router 的流量(估計)` | `ext_streak>=2` ∧ 狀態新鮮 ∧ 本機盒 | 估計,不點名來源;單拍證據只標「未確認」 |
| 帳目燈 `●OK/○運動中/!!失配/○灰` | router 十終態恆等式 `requests == Σ`:首拍灰(無基準),靜止 2 拍仍候補,連續 **3 拍**相同且 Σ 合才轉綠 | 缺欄=**永灰=預設行為**,不是故障;型別反裝如實標「型別不符」;比 rmon 新的 router 失配 → 灰但措辭是「**無法區分新增欄位與真失配**」,不替新版辯護 |
| `≥N 個請求在飛(M 盒未知)` | 逐盒 `inflight` 求和 | 任一盒缺 `inflight` 欄就只宣稱「至少」,不把未知當 0 |

**None 不編 0**:拿不到的數顯示 `—`/「預熱中」/「從未回報」/「未知」,絕不顯示假數字。

## 資安紅線(整套代碼的結構性約束,有測試把關)

- `rmon.py` 永不分派 POST;`launch.py` 的操作全是進程級(subprocess/taskkill),也無 HTTP 寫入。
- 金鑰不進這套系統:不讀 `*.keys.json`、不讀 `router.json` 內容(`[C]` 只看存在與大小)、
  `monitor.json` 拒絕金鑰形狀的欄位名。金鑰進出的唯一門是 `router.py --set-key`(DPAPI 加密落盤;
  坦白講:同身分的其他程序仍能解密——DPAPI 防的是檔案被掃走/備份外流,不防你機器上的同用戶惡意程序)。
- `diagnose` 預設去識別化:盒改號 box-A/B、URL 不出現、**連監控目標本身也不印**(只出
  `target_kind: loopback/remote`);`--full` 才出實址與真實盒名。
- `/stats` 回來的任何字串先過清洗才准進畫面:換行/Tab 轉**可見**形態(`\n`,防整行偽造),
  escape/C0/C1/不可見格式化字元(Cf)/半代字元剝除,超長截斷標 `[截斷]`。面板渲染路徑端對端零 ESC。
- `[K]` 停 router 採**殺無赦禁令**:pid 檔記「pid+進程建立時間」,殺前還要映像檔名是 `python*`
  三因子全中才動手;對不上(「pid 被回收重用」)一律拒殺。殼起的 router 是 DETACHED 無控制台,
  「優雅停」物理上送不到——選單會直說只能強制終端,不演假象。
- 零網頁:`webbrowser`/`html` 出現在 rmon/launch 會直接測試紅。

## 疑難

- **六種死法,六種開藥**(面板每種給一行指引):
  `refused`=沒人監聽這個埠(router 沒起 → 一條龍會自動起,或選單 `[S]`);`timeout`=可能在應但太慢(慢客戶端塞滿線程之類,去 router 端查);
  `dns`=主機名解析不了(VPN 斷了?改名了?先修網路);`reset`=連線中途被切(VPN 抖動/router 重啟瞬間/Windows 偶發 10053,會自動重試);
  `http`=那個埠回話了但不是 router 協定(port 填錯?被別的程序佔了?);`decode`=HTTP 200 但內容不是合法 JSON(跑 `diagnose` 看)。
- 面板顯示「偵測到 router 實例更換」= 計數倒退、版本改變**或 `started_at` 跳變>5s**(同版本重啟也抓得到,
  但容忍小漂移——「以 now−uptime 現算」的相容伺服器不會被誤判成天天重啟)。→ 速率與視窗從頭預熱,正常。
- 啟動時若印 `! monitor.json 缺失/損壞`:代表你**還沒建立設定**,本殼只是暫時拿內建預設
  (`127.0.0.1:8088`)探活並會明確宣告——這不是 router 壞了,由 `monitor.json.example`
  複製一份 `monitor.json` 改好就好(未配置的程式不會假裝知道你要看哪台)。
- 状態檔在 `%LOCALAPPDATA%\strata-monitor\`(速率快取**按目標分流檔**、多機切換互不覆蓋、
  90 天沒再用的舊目標快取自動回收、`router.pid.json`、router.log)。
- 環境變數(進階,一般不用設):`RMON_CONFIG` 指定 monitor.json 路徑;`RMON_STATE_DIR`
  指定狀態目錄(測試/多-instance 用);`RMON_NO_FRAME=1` 關掉固定框(退回 v0.1.4 追加);
  `NO_COLOR` 依慣例關掉自動開色(顯式 `--color` 仍可越過);`STRATA_ROUTER_DIR`
  告訴操作殼 router 在哪。
  未設時依序找姊妹目錄 `../router`(monorepo 同樹)→ 舊的 `../strata-router`
  (獨立佈局,切换期間兩邊都認),都找不到就看選單 `[S]`/`[C]` 的指示。
- **router 升級後的同步儀式**:`router.py` 的 `VERSION` 超過 rmon 的 `SCHEMA_KNOWN_MAX` 時,
  帳目燈對新版失配只能宣稱「未知」(灰)。發新版請順手把 `SCHEMA_KNOWN_MAX` 抬高,router 的
  帳目終端增減時並同步 `TERMS`(v1.2.16 起第 11 項為 `passthrough_gets`),然後重跑
  `tests_rmon.py`——這是 rmon 唯一需要人工維護的常量。

## 給審查者

`python tests_rmon.py -v` 全綠;紅線(零 POST、零金鑰讀取、零網頁、3.8 相容)都寫成了一條條測試。
本包對 `:8088` 與真實機器零假設:測試全部走 temp dir 與記憶體資料,不佔任何 port。
測試亦**不賴佈局**:把這個資料夾單獨拷到任何地方,`tests_rmon.py` 照全綠
(M2-B/P2-1 修掉了唯一一條暗賴 monorepo `../router` 存在的測)。
