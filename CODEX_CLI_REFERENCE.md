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
| `x-codex-window-id` | request header | UUID — `state.current_window_id()`（per UI window 一個，總是會送） |
| `x-codex-installation-id` | request body 內 `client_metadata`（standard responses）；**也是** request header（compact path） | UUID — `state.installation_id`（client 安裝時產一次，per 安裝固定） |
| `x-codex-parent-thread-id` | request header | thread_id of parent（**只在 subagent flow 才有**） |
| `x-openai-subagent` | request header | subagent 標籤字串（**只在 subagent flow 才有**） |
| `x-oai-attestation` | request header | 設備驗證簽章（**只在 attestation provider 啟用時才有**） |
| `prompt_cache_key` | request **body** | **= thread_id**（不是 session_id） |
| ~~`Conversation_id`~~ | ~~request header~~ | **不存在** — CLIProxyAPI 上游程式碼自己發明的 header，real Codex CLI WS / HTTP 都不送這個 |

關鍵不變式：

- **`session_id ≠ thread_id`**（兩個獨立的 v7）
- **`prompt_cache_key == thread_id`**（不是 session_id）
- **`x-client-request-id == thread_id`**
- **`Conversation_id` 是上游 fork 自己加的 fingerprint，應該 REMOVE**

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

> 來源：`codex-rs/core/src/client.rs` 的 `build_responses_options`（line 959）、`build_responses_identity_headers`（line 612）、`build_responses_headers`（line 1648）、`build_websocket_headers`（line 890）、`build_ws_client_metadata`（line 625）；以及 `codex-rs/codex-api/src/endpoint/responses.rs` 的 `stream` 函式（line 75）和 `codex-rs/codex-api/src/requests/headers.rs` 的 `build_session_headers`。

### Standard HTTP `/responses` 路徑送的 headers

| Header | 值 | 條件 |
|---|---|---|
| `session_id` / `session-id` | state.session_id | always |
| `thread_id` / `thread-id` | state.thread_id | always |
| `x-client-request-id` | state.thread_id | always (when thread_id present) |
| `x-codex-window-id` | state.current_window_id() | always |
| `x-codex-beta-features` | beta features 字串 | 有設定 beta features 時 |
| `x-codex-turn-state` | turn 狀態 | 有 turn state 時 |
| `x-codex-turn-metadata` | turn metadata | 有 turn metadata 時 |
| `x-codex-parent-thread-id` | 父 thread 的 thread_id | 只在 subagent flow |
| `x-openai-subagent` | subagent 標籤 | 只在 subagent flow |
| `x-oai-attestation` | attestation token | 啟用 attestation provider 時 |
| `OpenAI-Beta` | `responses=v1`（預設）| always（HTTP path）|
| `User-Agent` | `codex_cli_rs/X.Y.Z (OS; arch) terminal/X.Y.Z` 動態組 | always |
| `Originator` | `codex_cli_rs` | always |
| `Authorization` | `Bearer <access_token>` | always |
| `Chatgpt-Account-Id` | account_id | always (when OAuth 不是 API key) |

### WS `/responses` upgrade request 額外送的 headers

| Header | 值 | 跟 HTTP 差別 |
|---|---|---|
| `OpenAI-Beta` | `responses_websockets=2026-02-06` | **不同值**（HTTP 是 `responses=v1`）|
| `x-responsesapi-include-timing-metrics` | `true` | 只在 timing flag 開時，HTTP path 也有但 WS 更常用 |

WS path 其它 headers（session_id 家族、x-client-request-id、identity headers）跟 HTTP 一樣。

### Compact `/responses/compact` 路徑（HTTP 子路徑）的不同點

| Header | 差別 |
|---|---|
| `x-codex-installation-id` | **這條路徑會把 installation_id 也放進 header**（standard `/responses` 不會） |

### Body 欄位（standard responses）

| 欄位 | 值 |
|---|---|
| `model` | model slug |
| `instructions` | system prompt |
| `input` | conversation messages array |
| `tools` / `tool_choice` / `parallel_tool_calls` | tool 設定 |
| `reasoning` | reasoning config |
| `store` | bool（azure 才設）|
| `stream` | always true |
| `include` | array |
| `service_tier` | per-user tier |
| `prompt_cache_key` | **= thread_id 字串** |
| `text` | output schema params |
| `client_metadata` | object，**always 包含 `x-codex-installation-id` = state.installation_id** |

### WS body (`build_ws_client_metadata`) 的 client_metadata 多了

WS request body 的 `client_metadata` 比 HTTP 更豐富：

| key | value |
|---|---|
| `x-codex-installation-id` | state.installation_id（同 HTTP）|
| `x-codex-window-id` | state.current_window_id() |
| `x-openai-subagent` | subagent 標籤（conditional）|
| `x-codex-parent-thread-id` | 父 thread_id（conditional）|
| `x-codex-turn-metadata` | turn metadata（conditional）|

### 其它層

- **HTTP/2 ALPN 與 header 順序**：Rust hyper / reqwest 的 client 跟 Go net/http 的 header 順序、frame 順序不同
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

### 已驗證（之前列為 §A / §B / §C，已於 2026-05-10 完成）

- ✅ **§A WS Conversation_id**：real Codex CLI **不送這個 header**。CLIProxyAPI 上游程式碼自己發明的。修法：刪掉 `applyCodexPromptCacheHeaders` 內的 `headers.Set("Conversation_id", cache.ID)`。
- ✅ **§B installation_id**：real Codex CLI **always 送在 body 的 `client_metadata.x-codex-installation-id`**（standard responses）；compact path **再加一條 header**。修法：codex direct path 確認 translator 有把 client_metadata 透過去；非 codex 路徑要 synthesize 一個 stable per-auth installation_id 注入 body。
- ✅ **§C 完整 header 掃描**：見 §3 全表。除了原本知道的 session/thread 系列，real Codex CLI 還 always 送 `x-codex-window-id`，subagent flow 還會送 `x-openai-subagent`、`x-codex-parent-thread-id`，attestation provider 啟用時送 `x-oai-attestation`。WS path 的 `client_metadata` 還包含 window_id 等。

### 後續要做（D-J，priority 由高到低）

**D. 修 L1 patch 拆兩個 derive stream**（最高優先）
- 加 helper 產 `sessionDerived` 跟 `threadDerived` 兩個 v7（兩個 timestamp 應該幾乎相同，random 部分獨立）
- header 寫入：
  - `Session_id` / `session_id` / `Session-id` / `session-id` ← `sessionDerived`（**完全相同字串**）
  - `Thread_id` / `thread_id` / `Thread-id` / `thread-id` ← `threadDerived`（**完全相同字串**，real client 都送）
  - `X-Client-Request-Id` ← `threadDerived`（real client 跟 thread_id 一致）
- body 寫入：
  - `prompt_cache_key` ← `threadDerived`（real client 用 thread_id 字串，不是 session_id）

**E. 移除 `Conversation_id` header**
- `internal/runtime/executor/codex_websockets_executor.go:817-818` 的 `headers.Set("Conversation_id", cache.ID)` 整行刪掉
- 對應測試斷言更新
- regression test 的 `crossAuthLeakFields` 內 `Conversation_id` 條目改為「**must be absent**」而非「must differ」

**F. installation_id 處理**
- 為每個 OAuth auth 在登入 / 第一次 refresh 時產一個 stable UUID 存到 `auth.Metadata["installation_id"]`（同 `refresh_interval_seconds` 的 metadata 持久化模式）
- 在 cacheHelper / applyCodexPromptCacheHeaders 內，把 body 的 `client_metadata.x-codex-installation-id` 設成這個值（不論 inbound 是 codex 還是非 codex，統一改寫，避免不一致）
- 對 compact path 同時加 header

**G. window_id 處理**
- real client always 送 `x-codex-window-id`
- 我們 fork 完全沒處理 → 可以選：
  - 不送（明顯欠缺，是 fingerprint）
  - synthesize per-(auth, session) 的 stable UUID（複雜度等同 thread_id）
  - 從 ginHeaders 繼承（codex direct 可以；非 codex 沒有 → 還是要 synthesize）

**H. Subagent / parent_thread_id / attestation**
- 這些都是 conditional headers（subagent flow / attestation provider 啟用時才有）
- 對 fork 來說：codex direct path 的 ginHeaders 有就 forward；非 codex 路徑 don't add（多送反而是 fingerprint）
- 確認 codex direct path 的這幾個 header 有正確 forward（目前 fork 只 forward 一些 X-Codex-* 系列）

**I. WS body `client_metadata` 多欄位處理**
- WS path 的 client_metadata 比 HTTP 多 window_id、subagent、parent_thread_id、turn_metadata
- 取決於 F + G + H 怎麼做

**J. 驗證 fork 的 body 有沒有保留 client_metadata field**
- 對 codex direct path，translator 是否把整個 body 透過去？包含 client_metadata？
- 對非 codex path，translator synthesize 的 body 應該完全沒有這個 field
- 用 fingerprint regression test 加一條 assertion：「body 必有 `client_metadata.x-codex-installation-id`」即可監控

### 對應的 doc 更新（隨 D-J 進行）

- LEAK_RISKS L1 — 描述拆兩 stream + 移除 Conversation_id + installation_id 處理
- SESSION_ID_BEHAVIOR — derive 兩個 stream 的 timestamp 關係、字串完全相同的 reuse 模式
- MERGE_GUIDE 不變式表 — 加新的不變式（session_derived ≠ thread_derived、prompt_cache_key == thread_derived、Conversation_id absent、installation_id present 等）
- fingerprint regression test — 加「Session_id ≠ prompt_cache_key」「Conversation_id 不存在」「client_metadata.x-codex-installation-id 存在」三條斷言

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
| 2026-05-10 | 完成 §A / §B / §C 三項驗證。確認 `Conversation_id` 不存在 real protocol（CLIProxyAPI 自己加的）、`x-codex-installation-id` always 在 body client_metadata、补完 §3 的 HTTP / WS 完整 header 表（多了 x-codex-window-id、x-codex-parent-thread-id、x-openai-subagent、x-oai-attestation 幾條）。 | main HEAD（待補 hash） |
