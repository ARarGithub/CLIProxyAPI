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
**(1) per-auth derive**，覆蓋 HTTP / websocket 兩條路徑的所有 `from` 分支與直連 Codex CLI：

- 新增 `internal/runtime/executor/codex_session_id.go` — `derivePerAuthSessionID(originalID, auth)` 用 `uuid.NewSHA1(NameSpaceOID, []byte(originalID+":"+auth.ID))` 生成 per-auth UUID；`auth` 為 nil 或 `auth.ID` 為空時 no-op（測試友善）。
- `cacheHelper`（`internal/runtime/executor/codex_executor.go`）改 signature 接 `auth`，並在原本 claude/openai/openai-response 三條分支沒推導出 cache.ID 時，從 body `prompt_cache_key` / gin header `Session_id` 折回（涵蓋 Codex CLI 直連），最後一律 derive。Body `prompt_cache_key` 與 header `Session_id` 同步覆寫。
- `applyCodexHeaders`（`codex_executor.go:810-819`）的 `Session_id` 後處理改成「target 已有就不動」，避免 `misc.EnsureHeader` source-first 行為把 cacheHelper 已 derive 過的值用 ginHeaders 原值覆蓋回去。
- `applyCodexPromptCacheHeaders`（`internal/runtime/executor/codex_websockets_executor.go`）做同樣處理，涵蓋 websocket 路徑；`Conversation_id` 也同步覆寫。
- 三個 HTTP `cacheHelper` callsite 與兩個 websocket callsite 同步傳 `auth`。
- 單元測試：`codex_executor_cache_test.go` 補了 `TestCodexExecutorCacheHelper_PerAuthSessionIDDiffersAcrossAuths` 與 `TestCodexExecutorCacheHelper_DirectCodexInheritsAndDerivesGinSessionID`；`codex_websockets_executor_test.go` 補 `TestApplyCodexPromptCacheHeadersDerivesSessionIDPerAuth`。
- **回歸測試**：`internal/runtime/executor/codex_fingerprint_regression_test.go` — `TestCodexUpstreamFingerprintRegression_NoCrossAuthCorrelation`。透過 `httptest.Server` 模擬 Codex 上游，對四種 inbound client 格式（codex direct / openai-response / openai chat / claude）各跑兩個 auth，驗證上游收到的 `Session_id` / `prompt_cache_key` / `Conversation_id` / `previous_response_id` 在跨 auth 時必須不同；同時通用掃描所有 header 與 body top-level key，把任何「跨 auth 同值」的非預期欄位以 `t.Logf` 標出來供 review。每次新增功能或修改 Codex 路徑後跑這個測試可立刻看出新引入的 fingerprint 通道。

**未涵蓋**：Claude / Antigravity / Gemini / Kimi 後端。Codex/OpenAI 後端是這次 fork 的 patch 範圍。

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
