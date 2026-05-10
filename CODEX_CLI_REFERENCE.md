# Codex CLI Reference — fingerprint-relevant findings

> 本檔記錄真實 OpenAI Codex CLI（`github.com/openai/codex` 的 Rust 實作 `codex-rs/`）的三個 session-correlation 欄位的產生方式 + 上游 `router-for-me/CLIProxyAPI` 對應的處理方式。
>
> **用途**：未來 Codex CLI 升級時，照「§ 升級後快速重驗清單」走一遍，確認假設仍然成立；不成立就回頭修 fork-local L1 patch + 對應測試。
>
> **本次 source 驗證日期**：2026-05-10（main HEAD，之後升版時記得再確認）。

---

## 1. 三個欄位是什麼 + 在 wire 上的位置

| 欄位 | 在哪 | 真實 Codex CLI 送什麼值 |
|---|---|---|
| `session_id` / `Session_id` | request header | UUIDv7 — `state.session_id` |
| `session-id` (連字號版) | request header | 同 `session_id` |
| `thread_id` / `Thread_id` | request header | UUIDv7 — `state.thread_id`（與 session_id **獨立**） |
| `thread-id` (連字號版) | request header | 同 `thread_id` |
| `x-client-request-id` | request header | **= thread_id**（不是另一個值） |
| `prompt_cache_key` | request **body** | **= thread_id**（不是 session_id） |
| `Conversation_id` | WS request header | **未驗證**（要找 WS 路徑的 build code） |
| `client_metadata.x-codex-installation-id` | request body 內的 metadata map | UUID — `state.installation_id`（client 安裝時產一次，per 安裝固定） |

關鍵不變式：

- **`session_id ≠ thread_id`**（兩個獨立的 v7）
- **`prompt_cache_key == thread_id`**（不是 session_id）
- **`x-client-request-id == thread_id`**

L1 patch 寫成 `prompt_cache_key == Session_id` 是錯的，要拆開。

---

## 2. 真實 Codex CLI 怎麼產這三個 v7

兩個 ID 都是純 client-side `Uuid::now_v7()`，**跟上游回應無關**（沒有雞生蛋問題）：

```rust
// codex-rs/protocol/src/session_id.rs
impl SessionId {
    pub fn new() -> Self { Self { uuid: Uuid::now_v7() } }
}

// codex-rs/protocol/src/thread_id.rs
impl ThreadId {
    pub fn new() -> Self { Self { uuid: Uuid::now_v7() } }
}
```

**含義對 mimic 的影響**：

1. session_id 跟 thread_id 兩個 v7 在 **時間上極接近**——通常差幾毫秒甚至相同毫秒（同一段 init code 內兩次 `now_v7()` 呼叫）。我們 derive 時兩個 timestamp 應該也要接近。
2. 兩個的 **隨機部分（rand_a + rand_b）獨立隨機**——所以即使 timestamp 相同，UUID 字串也不同。
3. `prompt_cache_key` 跟 `thread_id` **是同一個 string** 完全一樣的 36 字元——上游可以直接 `header.thread_id == body.prompt_cache_key` 比對驗證。

對應 fork-local 修法：
- 目前 L1 derive 一個值寫兩處 → 要拆成兩個 stream
- session-derived 跟 thread-derived 兩個 timestamp 應該**設成同一個值**或差個幾毫秒（避免「session 1980 / thread 2030」的笑話）
- thread-derived 字串要完整 reuse 在 thread_id / thread-id / x-client-request-id / prompt_cache_key 四個地方（**完全相同 string**）

---

## 3. 真實 Codex CLI 還有哪些 fingerprint-relevant 訊號

從 `codex-rs/core/src/client.rs` 的 build request / build headers 路徑掃出來的：

### Headers
| Header | 值 | 重要性 |
|---|---|---|
| `User-Agent` | `codex_cli_rs/X.Y.Z (OS; arch) terminal/X.Y.Z` 動態組 | 高（fork 已知問題 L2，靠 config 蓋掉預設） |
| `Originator` | `codex_cli_rs` | 中（fork 已對齊） |
| `OpenAI-Beta` | `responses=v1`（HTTP）或 `responses_websockets=v2;...`（WS） | 中（fork 已對齊） |
| `Authorization` | `Bearer <access_token>` | 必須（每帳號不同） |
| `Chatgpt-Account-Id` | account_id from JWT | 必須（每帳號不同） |
| `Version` | Codex CLI 版本號（與 UA 內版本一致） | 中（fork 從 ginHeaders 繼承，可能有不一致風險） |
| `X-Codex-Turn-State` | turn 狀態 | 中 |
| `X-Codex-Turn-Metadata` | turn metadata | 中 |
| `X-Codex-Beta-Features` | beta feature flag | 低 |
| `X-Responsesapi-Include-Timing-Metrics` | 是否要 timing 資訊 | 低 |
| `Accept` / `Content-Type` / `Connection` | 標準 HTTP | 透明 |
| `X-OAI-Attestation` | 設備驗證簽章（特定 provider 才有） | 高（如果有的話）|

### Body
| 欄位 | 值 |
|---|---|
| `prompt_cache_key` | = thread_id（前述） |
| `client_metadata.x-codex-installation-id` | installation_id |
| `service_tier` | per-user tier (free / plus / pro / team) |
| `instructions` | system prompt 字串 |
| `input` | conversation messages array |
| `tools` | tool definition array |
| `tool_choice` | `"auto"` 預設 |
| `parallel_tool_calls` | bool |
| `reasoning` | reasoning config |
| `store` | bool（azure 才設） |
| `stream` | true |
| `include` | array |
| `text` | text params |

### 其它層
- **HTTP/2 ALPN 與 header 順序**：Rust hyper / reqwest 的 client 跟 Go net/http 的 header 順序、 frame 順序不同
- **TLS ClientHello / JA4**：Rust rustls vs Go crypto/tls 不同（fork 對 Anthropic 已用 utls，Codex 還沒）
- **Header 大小寫**：Rust 預設 lowercase，Go http.Header canonicalize 大寫——已對齊（fork 用 `setHeaderCasePreserved` 強制）

---

## 4. 上游 `router-for-me/CLIProxyAPI` 怎麼處理三欄位

> 以下是 **fork patch 之前** 的原版行為，分 inbound client 種類記錄。

### 4.1 Codex CLI 直連 (`from == "codex"`)

`cacheHelper` 走完所有 `if/else if from == ...` 分支都不命中，`cache.ID` 留空。

| Outbound | 來源 | 結果 |
|---|---|---|
| header `Session_id` | `applyCodexHeaders` 走 `misc.EnsureHeader(... ginHeaders ...)`，把 client 送的 `Session_id` 原樣轉發 | 正確（mirror real client）|
| body `prompt_cache_key` | client 送的原樣 forward（cacheHelper 沒覆蓋） | 正確（mirror real client，值 = real thread_id） |
| header `thread_id` / `thread-id` | `applyCodexHeaders` **沒有** `EnsureHeader` 這幾個 key | **被丟掉** ← fingerprint 風險，real client 有送 |
| header `x-client-request-id` | `misc.EnsureHeader(r.Header, ginHeaders, "X-Client-Request-Id", "")` | 正確（mirror real client） |
| WS `Conversation_id` | `applyCodexWebsocketHeaders` 沒處理（除非 ginHeaders 有原樣轉） | **未驗證** real client 是否送這個 |

### 4.2 Claude → Codex (`from == "claude"`)

```go
key := fmt.Sprintf("%s-%s", req.Model, userIDResult.String())
if cache, ok := helps.GetCodexCache(key); !ok {
    cache = helps.CodexCache{ID: uuid.New().String(), Expire: time.Now().Add(1 * time.Hour)}
    helps.SetCodexCache(key, cache)
}
```

`cache.ID` = v4 UUID（`uuid.New()`），per `(model, user_id)` 1h TTL。

| Outbound | 值 |
|---|---|
| header `Session_id` | `cache.ID` |
| body `prompt_cache_key` | **`cache.ID`（= Session_id）** ← fingerprint 風險（real client 不會等於）|
| header `thread_id` | 不送 |
| header `x-client-request-id` | 沒設（gin 也沒有）|

### 4.3 OpenAI Chat → Codex (`from == "openai"`)

```go
cache.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:"+apiKey)).String()
```

`cache.ID` = v5 UUID（**deterministic from inbound apiKey**），所以多 agent 同 apiKey 共用 cache.ID。

| Outbound | 值 |
|---|---|
| header `Session_id` | `cache.ID`（**v5，第 14 位是 5**——立刻露餡）|
| body `prompt_cache_key` | `cache.ID`（同上，且 = Session_id） |
| header `thread_id` | 不送 |
| header `x-client-request-id` | 沒設 |

### 4.4 OpenAI Responses → Codex (`from == "openai-response"`)

```go
promptCacheKey := gjson.GetBytes(req.Payload, "prompt_cache_key")
if promptCacheKey.Exists() {
    cache.ID = promptCacheKey.String()
}
```

`cache.ID` = caller 送的 `prompt_cache_key`（任何格式），可能是 v4 UUID、可能是 v5、可能是任意字串。

| Outbound | 值 |
|---|---|
| header `Session_id` | `cache.ID` |
| body `prompt_cache_key` | `cache.ID`（同上，且 = Session_id）|
| header `thread_id` | 不送 |
| header `x-client-request-id` | 沒設 |

### 4.5 上游 4 種情境的問題彙總

| 情境 | 問題 |
|---|---|
| Codex direct | `thread_id` header 沒被 forward |
| Claude / OpenAI Chat / OpenAI Responses | `prompt_cache_key == Session_id`（real client 不會） |
| OpenAI Chat | 多了一條：`Session_id` 是 v5（real client 是 v7） |
| 全部非 codex 路徑 | `thread_id` header 沒送 + `x-client-request-id` 沒送 + `prompt_cache_key` 跟 `Session_id` 同值 |

---

## 5. 我們 fork 目前（post-L1）的處理

| 情境 | derive 後 outbound |
|---|---|
| 全部 4 種 | `Session_id` header = `prompt_cache_key` body = `derive(cache.ID, auth)` —— **修了「上游 4.5」的 v5 / cross-auth 兩個問題**，但**沒修「Session_id == prompt_cache_key」這個真實 client 不會等於的問題**，也沒處理 `thread_id` header 的缺漏 |

## 6. 還沒做的事

A. **驗證 WS path `Conversation_id` real Codex CLI 送什麼**（從 `codex-rs/core/src/client.rs` line 904 附近的 `headers.insert("x-client-request-id", ...)` 看出 HTTP path 的處理；WS path 的對應位置要在 codex-rs 找 `responses_websockets` 或 `Codex Websocket session` 相關 build code）

B. **驗證 `client_metadata.x-codex-installation-id`**：
- real client 一定送嗎？
- 我們 codex direct 是否原樣 forward？非 codex 路徑 synthesize 的 body 有沒有？

C. **掃 `codex-rs/core/src/client.rs` 完整檢查還有沒有其它 fingerprint header**

D. **修 L1 patch 拆兩個 stream**（session-derived + thread-derived）+ 加 `thread_id` / `thread-id` / `x-client-request-id` header 注入（thread-derived）+ `prompt_cache_key` body 改用 thread-derived

E. 對應 doc 更新（LEAK_RISKS L1、SESSION_ID_BEHAVIOR、MERGE_GUIDE 不變式表、fingerprint regression test 新增 assertion：`Session_id != prompt_cache_key` 必須成立）

---

## 7. 升級後快速重驗清單

當 Codex CLI 出新 release（不論是 v7.X.Y → v7.Z.W 的 minor，或 v8 大改）：

1. **檢查 SessionId / ThreadId 還是 v7 嗎**？
   - `https://github.com/openai/codex/blob/main/codex-rs/protocol/src/session_id.rs`
   - `https://github.com/openai/codex/blob/main/codex-rs/protocol/src/thread_id.rs`
   - 如果改成別的版本（例如 v8），fork 的 derive function 要跟著改 version bits

2. **檢查 prompt_cache_key 還是 = thread_id 嗎**？
   - `codex-rs/core/src/client.rs` 內 `let prompt_cache_key = ...` 的賦值
   - grep `prompt_cache_key` 找所有 binding

3. **檢查 build_session_headers 還是同樣四個 header (`session_id`、`session-id`、`thread_id`、`thread-id`) 嗎**？
   - `codex-rs/codex-api/src/requests/headers.rs` 的 `build_session_headers` 函式
   - 如果新增了 header，fork 也要跟著加

4. **檢查 x-client-request-id 還是 = thread_id 嗎**？
   - `codex-rs/core/src/client.rs` 內 `headers.insert("x-client-request-id", ...)` 的值

5. **檢查有沒有新增 fingerprint-relevant 欄位**：
   - 比對 `codex-rs/core/src/client.rs` 的 build_request 的所有 body 欄位
   - 比對 `codex-rs/codex-api/src/requests/headers.rs` 的所有 insert_header
   - 任何新欄位都要評估是否要在 fork 對應處理

6. **跑 fingerprint regression test**：
   ```bash
   go test ./internal/runtime/executor/ -run 'TestCodexUpstreamFingerprintRegression' -v
   ```
   如果 upstream 新增 header 而我們沒對應，regression test 的 generic scan 應該會用 `t.Logf` 報出來。

7. **更新本檔的「本次 source 驗證日期」**

---

## 8. 一鍵 grep 命令（給未來的自己）

從 `https://raw.githubusercontent.com/openai/codex/main/` 抓重要檔案：

```bash
# 抓 client.rs 看 request build 邏輯
curl -s 'https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/src/client.rs' \
  -o /tmp/codex_client.rs

# 找三個 ID 的所有出現
grep -n 'session_id\|thread_id\|prompt_cache_key\|conversation_id' /tmp/codex_client.rs

# 找新增的 header
grep -n 'headers.insert\|insert_header' /tmp/codex_client.rs

# 找新增的 body 欄位
grep -n 'ResponsesApiRequest\|client_metadata' /tmp/codex_client.rs

# Headers crate
curl -s 'https://raw.githubusercontent.com/openai/codex/main/codex-rs/codex-api/src/requests/headers.rs' \
  -o /tmp/codex_headers.rs && cat /tmp/codex_headers.rs

# SessionId / ThreadId 的版本確認
curl -s 'https://raw.githubusercontent.com/openai/codex/main/codex-rs/protocol/src/session_id.rs' | grep 'now_v[0-9]'
curl -s 'https://raw.githubusercontent.com/openai/codex/main/codex-rs/protocol/src/thread_id.rs'  | grep 'now_v[0-9]'
```

---

## 9. 相關文件

- `LEAK_RISKS.md` L1 — 為什麼要做 cross-auth derive
- `SESSION_ID_BEHAVIOR.md` — derive 行為對照表
- `MERGE_GUIDE.md` §6 — Session ID 測試套件
- `internal/runtime/executor/codex_session_id.go` — derive 函式
- `internal/runtime/executor/codex_fingerprint_regression_test.go` — fingerprint 回歸測試

## 10. 維護紀錄

| 日期 | 事件 | Codex CLI commit / tag |
|---|---|---|
| 2026-05-10 | 初次寫此檔。確認 SessionId/ThreadId 都是 v7、prompt_cache_key = thread_id、build_session_headers 四個 header。未驗證 Conversation_id WS、installation_id 處理。 | main HEAD（commit 未記錄；建議下次更新時補上 short hash） |
