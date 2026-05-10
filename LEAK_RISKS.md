# CLIProxyAPI 洩漏風險清單（fork-local）

> 本檔針對本 fork（基於 router-for-me/CLIProxyAPI v6 / `01171742` 起頭）羅列「上游 LLM 服務商可用以辨識號池或 proxy」的特徵洩漏點。每條包含：嚴重度、機制、原始碼位置、修復方向、是否已 patch。
>
> 對應通用 audit 框架見：`/home/ubu/lp/llm-proxy-fingerprint-checklist.md`

---

## 嚴重度分級
- 🔴 **決定性**：對上游構成「直接的池化證據」，可單條判定
- 🟠 **高**：強指紋，配合其它訊號很容易被歸類
- 🟡 **中**：弱指紋或時序特徵，對個人小規模使用影響低
- 🟢 **低**：僅在特定情境洩漏

Patch 狀態：`[ ]` 未動 / `[~]` 部分修 / `[x]` 已修

---

## 🔴 L1：`Session_id` 跨 OAuth 帳號延續（決定性池化證據）

**嚴重度**：🔴 決定性
**狀態**：`[x]` 已修（2026-05-10，per-auth re-derive）
**對應 checklist**：F9

### 機制
CLIProxyAPI 對所有翻成 Codex 上游格式的請求都會在出站 header 帶 `Session_id`，但這個 ID 的計算**完全與 auth/account 無關**：

| Incoming `from` | `Session_id` 來源 | 鎖定條件 |
|---|---|---|
| Codex CLI 直連 | gin header 原樣轉發 | Codex CLI 自己的 session 一致 |
| `from=="claude"` | `helps.GetCodexCache(model + "-" + metadata.user_id)` 的 UUID（1h TTL） | 同 model + 同 Claude session |
| `from=="openai"` | `uuid.NewSHA1("cli-proxy-api:codex:prompt-cache:" + apiKey)` | **deterministic** — 同入站 apiKey 永遠同 ID |
| `from=="openai-response"` | caller 送的 `prompt_cache_key` 原樣使用 | 由 caller 控制 |

`SessionAffinitySelector` 雖然會「儘量讓同 session 待在同一 auth」，但只要綁定的 auth 進入 unavailable / `InvalidateAuth`（rate-limit、token 撤銷、設定變更⋯⋯）就 fallback 重選下一帳號，**`Session_id` 不會回頭被改寫**，於是上游觀測到：

```
session_id=X  Authorization=Bearer <A 的 token>  Chatgpt-Account-Id=A
session_id=X  Authorization=Bearer <B 的 token>  Chatgpt-Account-Id=B   ← 池化指紋鐵證
```

OpenAI 隨時可以對歷史日誌跑「同一 session_id 下出現 ≥2 個 account_id」的批次查詢，一網打盡。

### 程式碼位置
- `internal/runtime/executor/codex_executor.go:733-770`（`cacheHelper`）
- `internal/runtime/executor/codex_executor.go:791`（`misc.EnsureHeader(... "Session_id" ...)` — 直連路徑原樣轉發）
- `internal/runtime/executor/codex_websockets_executor.go:787-821`（`applyCodexPromptCacheHeaders`）
- `internal/runtime/executor/codex_websockets_executor.go:858-861`（websocket 直連路徑）
- `internal/runtime/executor/helps/cache_helpers.go:13-18`（`codexCacheMap` 不含 auth 維度）
- `sdk/cliproxy/auth/selector.go:484-537`（cache miss / auth unavailable 都會切 auth）
- `sdk/cliproxy/auth/selector.go:566-570`（`InvalidateAuth`）

### 修復方向
**核心**：當實際選中的 auth 不是「session 第一次綁定的 auth」時，必須重新生成 `Session_id`。

具體選擇任一：
1. **per-auth derive**：在出站前用 `uuid.NewSHA1(NameSpaceOID, []byte(originalSessionID + ":" + auth.ID))` 重寫 `Session_id`（同帳號內仍可命中 prompt cache、跨帳號自動 miss）
2. **fail-fast**：affinity 綁定的 auth 不可用時直接回 5xx，不無聲切；犧牲可用性換指紋乾淨
3. **rewrite + body align**：同步覆寫 body 的 `prompt_cache_key`（websocket 還要覆寫 `Conversation_id`）

選 (1) 對使用者體驗影響最小，且不會降低 prompt cache 命中率（cache 本來就是 per-account）。

### 已採用方案（fork-local patch）
**(1) per-auth derive + v7 mimic + 雙 stream（session_id / thread_id 獨立）**，覆蓋 HTTP / websocket 兩條路徑的所有 `from` 分支與直連 Codex CLI：

- 新增 `internal/runtime/executor/codex_session_id.go` — 兩個 derive helper，把 `(originalID, auth.ID)` 衍生成兩個**獨立、看起來像真實 Codex CLI session id 的 UUIDv7**：
  - `derivedSessionID(originalID, auth)` — 給 upstream 的 `Session_id` / `session_id` headers（`Session-id` 也走同一條）
  - `derivedThreadID(originalID, auth)` — 給 `Thread_id` / `thread_id` / `X-Client-Request-Id` headers AND body 的 `prompt_cache_key`（real Codex CLI 用 thread_id 字串當 prompt_cache_key，**不是 session_id**）
  - 兩個函式內部用不同 namespace（`...:session_id:v7` vs `...:thread_id:v7`），所以**對任何 (originalID, auth.ID) 都保證 derivedSessionID ≠ derivedThreadID**——避免「Session_id == prompt_cache_key」這個 real Codex CLI 永不會出現的 fingerprint
  - 兩個輸出都是合法 UUIDv7：第 14 位永遠是 `7`、第 19 位是 RFC4122 variant、前 48 bit timestamp（codex 直連借用 client 的 v7 timestamp；其他路徑用 in-memory cache 各自獨立 pin）
  - 其餘 80 bit (rand_a + rand_b) = `SHA1(namespace + ":" + originalID + ":" + auth.ID)`，cross-auth 一定不同
  - `auth` 為 nil 或 `auth.ID` 為空時 no-op（測試友善）
- `cacheHelper`（`codex_executor.go`）改 signature 接 `auth`，並在 codex 直連路徑分別讀 inbound `Session_id` 與 `Thread_id` 兩個 header（real Codex CLI 兩個都送）；非 codex 路徑用同一個 cache.ID 餵兩個 stream（namespace 隔離保證輸出不同）。寫出三筆對齊的值：body `prompt_cache_key = threadDerived`、header `Session_id = sessionDerived`、header `Thread_id = X-Client-Request-Id = threadDerived`。
- `applyCodexHeaders` 的 `Session_id` / `Thread_id` / `X-Client-Request-Id` 後處理都改成「target 已有就不動」，避免 `misc.EnsureHeader` 的 source-first 行為把 cacheHelper 已 derive 過的值用 ginHeaders 原值覆蓋回去。
- `applyCodexPromptCacheHeaders`（websocket 路徑）做同樣處理：兩個 stream + 兩條 ginHeaders 讀取（lowercase `session_id` / `thread_id`）+ **移除 `Conversation_id` header**（real Codex CLI 從不送這個 header，是上游 fork 自己加的）。
- `applyCodexWebsocketHeaders` 也加 `thread_id` 的 fallback case-preserved 處理 + gate `x-client-request-id` 的 EnsureHeader 不蓋掉 derived 值。
- 三個 HTTP `cacheHelper` callsite 與兩個 websocket callsite 同步傳 `auth`。
- 單元測試 `codex_session_id_test.go`：14 個測試 §1 Determinism / §2 Auth-switching round-trip / §3 Timestamp correctness / §4 Cross-input distinctness / §5 **Cross-stream distinctness（derivedSessionID ≠ derivedThreadID）** / §6 Edge cases / §7 Structural validity / §8 Concurrency safety
- `codex_executor_cache_test.go` 的三個整合測試 + `codex_websockets_executor_test.go` 的兩個 websocket 測試都改寫成新雙 stream 斷言（包含「Session_id 必不等於 prompt_cache_key」、「Thread_id == X-Client-Request-Id == prompt_cache_key」、「Conversation_id 必不存在」）。
- **回歸測試**：`codex_fingerprint_regression_test.go` 對四種 inbound client 格式各跑兩個 auth，驗證：
  1. cross-auth：`Session_id` / `Thread_id` / `X-Client-Request-Id` / `prompt_cache_key` / `previous_response_id` 必須不同
  2. **`Session_id ≠ prompt_cache_key`**（real Codex CLI 不會等於）
  3. **`Thread_id == X-Client-Request-Id == prompt_cache_key`**（real Codex CLI 三個都用 state.thread_id）
  4. **`Conversation_id` 必須不存在**（real Codex CLI 不送這個 header）
  5. 每個 outbound `Session_id` / `Thread_id` / `prompt_cache_key` 必須通過 `assertCodexV7Mimic`：合法 v7 UUID + variant 對 + timestamp 落在最近 30 天
  6. 通用掃描所有 header 與 body top-level key，跨 auth 同值的非預期欄位用 `t.Logf` 標出供 review

每次新增功能或修改 Codex 路徑後跑這個測試可立刻看出新引入的 fingerprint 通道。

**未涵蓋**：Claude / Antigravity / Gemini / Kimi 後端。Codex/OpenAI 後端是這次 fork 的 patch 範圍。

### F + G — installation_id 與 x-codex-window-id（雙修，2026-05-11）

延續 L1 的「每個 outbound 值都要 per-auth 不同 + 看起來像真的」框架，補完兩個 real Codex CLI 永遠送、原版 fork 完全沒處理的欄位：

- **F: `client_metadata.x-codex-installation-id` (body)**
  - Real Codex CLI 在 `<codex_home>/installation_id` 存一個 UUIDv4，per install 永不變。
  - Fork 改在 `auth.Metadata["installation_id"]` 持久化 per OAuth account 的 v4 UUID，跨 auth 各自獨立、單 auth 跨重啟一致——避免「許多 OAuth 都帶同一個 installation_id」這個「同機器多帳號」的池化指紋。
  - 新檔 `internal/runtime/executor/codex_installation_id.go`：`codexInstallationIDForAuth(auth)` 讀；`ensureCodexInstallationID(auth)` 缺值就 `uuid.New()` 寫。從不覆寫已存在的值。
  - 種值點：`sdk/auth/codex_device.go:buildAuthRecord` OAuth 登入時 + `internal/runtime/executor/codex_executor.go:Refresh` 成功後（後者只 ensure，不覆蓋）。
  - 注入點：cacheHelper / applyCodexPromptCacheHeaders 把值寫到 body `client_metadata.x-codex-installation-id`；compact path 額外加 `X-Codex-Installation-Id` header。

- **G: `x-codex-window-id` (header)**
  - Real Codex CLI 送 `format!("{thread_id}:{window_generation}")`，generation 起始 0、websocket session reset 時 +1。
  - Fork 用已 derive 的 `threadDerived` 拼 `"{threadDerived}:{generation}"`：codex 直連路徑解 inbound `X-Codex-Window-Id` 抽 generation；非 codex 路徑固定 0。
  - 自然 cross-auth distinct（threadDerived 已 per-auth）+ 看起來真（thread 部分合法 v7 + colon + integer）。
  - 注入點：cacheHelper / applyCodexPromptCacheHeaders 寫到 `X-Codex-Window-Id` 兩條 path；WS body 的 `client_metadata.x-codex-window-id` 也補。

- 測試：`codex_installation_id_test.go`（13 個 case）+ regression test 加 4 條斷言（body 必有 v4 installation_id、header 必有 `{uuid}:{int}` 形狀 window_id、thread 部分必須等於 Thread_id、cross-auth 全不同）。`crossAuthLeakFields` 加上 `X-Codex-Window-Id` 與 `client_metadata.x-codex-installation-id`。

---

## 🟠 L2：Codex `User-Agent` 寫死 macOS / arm64

**嚴重度**：🟠 高（搭配 Linux/Windows 主機 IP 時 OS-mismatch）
**狀態**：`[ ]`
**對應 checklist**：F1, F3

### 機制
```go
// internal/runtime/executor/codex_executor.go:33
const codexUserAgent = "codex_cli_rs/0.118.0 (Mac OS 26.3.1; arm64) iTerm.app/3.6.9"
```

當部署在 Linux / Windows / amd64 主機（多數 VPS 場景）：
- TCP/TLS 層暴露的 OS 訊號（如 TCP timestamp、TLS extension 順序）跟 UA 自稱的 macOS 不符
- 多帳號從同一機器出去 → 全部都自稱 macOS arm64 + iTerm.app，但實際拓撲不可能這樣
- 寫死 `iTerm.app/3.6.9` 也是強指紋（真實 Codex CLI 的 terminal 段會跟使用者實際終端機一致）

### 程式碼位置
- `internal/runtime/executor/codex_executor.go:33`（const）
- `internal/runtime/executor/codex_executor.go:788`（apply 處）
- `internal/runtime/executor/codex_websockets_executor.go:847,866`（websocket apply）
- `internal/runtime/executor/codex_executor.go:790-792` 對 Mac OS 子字串敏感（決定要不要塞隨機 `Session_id`）

### 修復方向
1. 用 `runtime.GOOS` / `runtime.GOARCH` 動態組 UA（mapping `darwin → "Mac OS X.Y"`、`linux → "Linux X.Y"`、`windows → "Windows X.Y"`）
2. 拿掉 terminal segment（`iTerm.app/3.6.9`）或讀環境變數 `TERM_PROGRAM` / `TERM`
3. 同步調整 line 790 的「Mac OS 子字串檢查」邏輯（避免 macOS host 才生 Session_id 的隱性分支）
4. 配合 config `codex-header-defaults.user-agent` 的 override（已存在）

---

## 🟠 L3：Antigravity / Claude / Kimi 預設 OS 指紋寫死

**嚴重度**：🟠 高（同上邏輯）
**狀態**：`[ ]`
**對應 checklist**：F1

### 機制
- **Antigravity**：`AntigravityUserAgent()` 一律回 `antigravity/X.Y.Z darwin/arm64`（`internal/misc/antigravity_version.go:110`）
- **Claude device profile 預設**：`MacOS / arm64`（`internal/runtime/executor/helps/claude_device_profile.go:22-23`）。實際使用上，真實 Claude Code 的 incoming UA 會 override，但「非 Claude Code 客戶端打 Claude 後端」時會走預設。
- **Kimi device_id fallback**：`cli-proxy-api-device`（`internal/runtime/executor/kimi_executor.go:693,713`）—— 多個 proxy 部署如果都沒有 kimi-cli 的 device_id 檔案，會共用同一 device_id 字串，等於把所有用戶綁成同一台設備。

### 修復方向
- Antigravity UA：用 `runtime.GOOS`/`runtime.GOARCH` 動態組
- Kimi device_id fallback：改成「每個 auth 派生一個 stable UUID 並寫進 metadata」，而不是常數字串

---

## 🟡 L4：Codex 5 天 / Claude 4 小時 proactive refresh lead

**嚴重度**：🟡 中（時序指紋）
**狀態**：`[~]` Codex 已修（2026-05-10），Claude 未動（fork 範圍外）
**對應 checklist**：A2, A4

### 機制
- `sdk/auth/codex.go:34` — `CodexAuthenticator.RefreshLead()` 回 `5 * 24 * time.Hour`：access token 過期前 5 天就主動 refresh
- `sdk/auth/claude.go:34` — `ClaudeAuthenticator.RefreshLead()` 回 `4 * time.Hour`：過期前 4 小時就主動 refresh
- `sdk/cliproxy/auth/auto_refresh_loop.go` — min-heap 排程，到時就觸發 `manager.refreshAuth(ctx, authID)`

效果：在 chat 流量完全沒發生的時候，proxy 會孤立地對 OAuth refresh endpoint 發起請求。真實 Codex / Claude CLI 是 lazy refresh（用到才 refresh，refresh 緊跟 chat），所以「半夜三點突然只有一個 refresh、前後幾天沒有 chat」是強時序指紋。

對比：Antigravity 5min、Kimi 5min、Gemini nil（lazy）—— 後三者都符合真人 CLI 行為。

### 程式碼位置
- `sdk/auth/codex.go:34`
- `sdk/auth/claude.go:34`
- `sdk/cliproxy/auth/auto_refresh_loop.go:78-91`（worker 觸發）
- `sdk/cliproxy/auth/auto_refresh_loop.go:340-411`（`nextRefreshCheckAt` 計算下一次時點）

### 修復方向
1. **保守**：把 Codex lead 縮到 1h、Claude 縮到 30min；至少時點與 chat 流量重疊機率變高
2. **激進**：直接改成 lazy（return nil），讓 refresh 只在請求即將出去前才發生
3. 若保留 proactive，加 jitter（lead ± random%）避免多帳號同時點對齊

選 (2) 最乾淨，但對「token 接近 expiry 時碰到批量請求」的瞬間延遲略增（單次 refresh 幾百 ms）。

### 已採用方案（fork-local patch，僅 Codex）

**(3) jitter + persistence**：保留 proactive 模式，每個 cycle roll 一個 [3d, 7d] 的隨機 lead，並把 roll 結果 persist 到 auth metadata，避免重啟 re-roll 收斂到 maxLead。

- 新增 `internal/auth/codex/refresh_lead.go` — `NextRefreshLead()` 回 `[RefreshLeadMin=3d, RefreshLeadMax=7d)` 內的隨機 `time.Duration`。
- `sdk/auth/codex.go` 的 `CodexAuthenticator.RefreshLead()` 改用 helper：每次呼叫 roll 一次。
- `sdk/auth/codex_device.go` 的 `buildAuthRecord` 在 OAuth 登入完成時就把首個 roll 寫進 `auth.Metadata["refresh_interval_seconds"]`，新登入憑證從第一秒就有 persisted 值。
- `internal/runtime/executor/codex_executor.go` 的 `Refresh()` 成功後 roll 並寫新值到同一個 metadata key，下個 cycle 用新 roll、cycle 之間獨立。
- SDK 已存在的 `authPreferredInterval`（`sdk/cliproxy/auth/conductor.go:3328`）會優先讀 `Metadata["refresh_interval_seconds"]`，不需要改 SDK 排程邏輯。
- **Startup burst jitter**（同時解 docker pull/up burst 與「升級過渡期」的 burst）：`sdk/cliproxy/auth/auto_refresh_loop.go` 加 `jitteredNow()` helper 並把 `nextRefreshCheckAt` 內 6 個 `return now, true` 改為 `return jitteredNow(now), true`，把任何「立刻到期」的決策散到 0~30min 內。
- 測試：`internal/auth/codex/refresh_lead_test.go`（範圍 + variance）、`sdk/auth/codex_refresh_lead_test.go`（CodexAuthenticator 委派 + re-roll）、`sdk/cliproxy/auth/jitter_test.go`（jitter 範圍 + 均勻分佈）。

**對 web 前端**：完全相容。`refresh_interval_seconds` 是 SDK 既有欄位（不是 fork 自己發明的），管理 UI 即使把 metadata 全部展示出來也只是多一個整數欄位，不影響功能。

**對 config**：完全不動 config schema，所有設定值都在 metadata 裡。

**未涵蓋**：Claude 4h proactive refresh（`sdk/auth/claude.go:34`）—— 非 Codex/OpenAI，按 fork 範圍跳過。

### 過渡 / 遷移情境（舊 auth 檔在新 fork 上的行為）

`refresh_interval_seconds` 只在兩條路徑被 write：
1. OAuth 新 login（`sdk/auth/codex_device.go:buildAuthRecord`）
2. Token refresh 成功（`internal/runtime/executor/codex_executor.go:Refresh`）

**舊 auth 檔（沒有此欄位）的三個常見情境**：

| 情境 | 何時欄位才會出現 | 過渡期排程行為 |
|---|---|---|
| **(1a) 啟動前 disabled，啟動後啟用** | 啟用後該 auth 進入排程；當下次 Refresh 成功時寫入。如果啟用瞬間 auth 已在 refresh window 內，jitter 會在 0–30min 內觸發 Refresh，欄位很快寫入。若不在 window，要等到 `expiry - random_lead` 自然到達 | 排程使用 `RefreshLead()` 即時 roll，仍是 [3d, 7d) 隨機；只是「跨重啟穩定」缺失 |
| **(1b) 啟動前就 enabled** | 啟動後 auto-refresh loop 立刻把 auth 排進 heap；Refresh 觸發時寫入。同上：在 window 內 → jitter 後即觸發；不在 → 等到 `expiry - random_lead` | 同 (1a) |
| **(2) 從 management API 上傳 / import** | 上傳 handler 只把 bytes 原樣寫到磁碟，不修 metadata。之後同 (1b)：第一次 Refresh 才寫入 | 同 (1a) |

三個情境都有同一個事實：**指紋保護從那個 auth 進入排程的第一秒就生效**（因為 `RefreshLead()` 隨機是 SDK 排程器主動呼叫的），**只是還沒持久化到 metadata 而已**。對「平常使用」沒影響；對「頻繁 docker pull/restart」場景才會在過渡期碰到 re-roll 收斂問題（每次重啟 re-roll，多次重啟後值傾向 maxLead）。

**緊迫場景的手動補種**（一次性 jq 腳本，給「import 一大批舊 auth 後想立刻穩定」的使用情境）：

```bash
cd path/to/auths
for f in *.json; do
  type=$(jq -r '.type // ""' "$f")
  has=$(jq -e 'has("refresh_interval_seconds")' "$f" >/dev/null 2>&1 && echo yes || echo no)
  if [ "$type" = "codex" ] && [ "$has" = "no" ]; then
    rand=$(awk 'BEGIN{srand(); printf "%d", 259200 + int(rand() * (604800 - 259200))}')
    jq ". + {refresh_interval_seconds: $rand}" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    echo "seeded $f with $rand seconds"
  fi
done
# 跑完後重啟 proxy 讓 manager 重讀
```

跑完每個 codex auth 都有 [3d, 7d) 內穩定的隨機 lead，跨重啟也不會 re-roll 直到下次 Refresh 才換新值。**重啟 proxy 才會生效**（讓 manager 重讀 metadata）。

---

## 🟡 L5：TLS 偽裝只覆蓋 Anthropic，Codex/Gemini 裸奔

**嚴重度**：🟡 中（長期）
**狀態**：`[ ]` (架構性，難 patch)
**對應 checklist**：G2

### 機制
- `internal/runtime/executor/helps/utls_client.go:131-150` — `anthropicHosts` 只列 `api.anthropic.com`，其餘走標準 Go `crypto/tls`
- `internal/auth/claude/utls_transport.go` — 同樣只用於 Anthropic 認證流程

對 Codex (`chatgpt.com` / `api.openai.com`) / Gemini (`cloudcode-pa.googleapis.com`) 等上游，TLS ClientHello / JA4 是 Go 標準庫指紋，跟真實 Rust 寫的 Codex CLI、Node.js 寫的 Gemini CLI 都不同。

### 修復方向
擴充 `anthropicHosts` 到一個更通用的「需 utls 的 host 集合」並對 Codex / Gemini hostname 加進去。不過 utls Chrome fingerprint 跟「Codex CLI 真實 TLS（Rust + rustls 風格）」也不會一致，理想需要不同 profile。屬於長期工程問題。

---

## 🟢 L6：`Originator` 寫死 `codex_cli_rs`

**嚴重度**：🟢 低（與真實 Codex CLI 一致，且 incoming header 可 override）
**狀態**：`[ ]` 不需動

### 機制
```go
// internal/runtime/executor/codex_executor.go:34
const codexOriginator = "codex_cli_rs"
```

值與真實 Codex CLI 相同，所以本身不是異常。但在「incoming 不帶 originator」的情境下，OpenAI 會看到「originator=codex_cli_rs 但 UA / TLS 跟真實 codex_cli_rs 不符」的內部矛盾——這是 L2/L5 派生的問題，修了 L2/L5 就改善。

---

## 🟢 L7：`prompt_cache_key` 命名空間 `cli-proxy-api:codex:prompt-cache:`

**嚴重度**：🟢 低（單獨無害，與 L1 合併才有意義）
**狀態**：`[ ]` 不需單獨修，併入 L1 patch

### 機制
```go
// internal/runtime/executor/codex_executor.go:755
cache.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:"+apiKey)).String()
```

雖然出站只是 UUID 字串，但因為固定命名空間 + 入站 apiKey，UUID 是 deterministic 的。對單一帳號上游看不出差異，但配合 L1（auth 切換時 session 不變）會變成強訊號。

L1 patch 完成（per-auth re-derive）後，命名空間是否暴露字面意義就不重要。

---

## 📋 Patch 順序建議

| 順序 | 對象 | 預期工程 | 風險/影響 |
|---|---|---|---|
| 1 | **L1**：session_id per-auth re-derive | 中（碰 cacheHelper、apply\*Headers、selector callsite） | 對 prompt cache 中性（cache 本就 per-account） |
| 2 | **L2**：Codex UA 動態組 | 小（const → func） | 需校準 OS string 形式以模擬真實 codex_cli_rs |
| 3 | **L3**：Antigravity / Kimi device_id | 小 | 同上 |
| 4 | **L4**：refresh lead 縮短或改 lazy | 小（兩個 return value 改數字 / nil） | 改 lazy 會讓 token 接近 expiry 時的首個請求略慢 |
| 5 | **L5**：擴充 utls 適用 host | 大（多上游驗證） | 長期 |

---

## 📝 維護筆記

- **建立**：2026-05-10
- **base commit**：`01171742 fix(amp): proxy thread actors route`
- **原始上游**：`github.com/router-for-me/CLIProxyAPI` v6
