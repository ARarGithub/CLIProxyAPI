# Session ID 在線上 (on-the-wire) 的行為備忘

> 本檔記錄不同情境下，上游 Codex API 收到的 `Session_id` header / `prompt_cache_key` body 是什麼樣子。
>
> 完整背景見 `LEAK_RISKS.md` L1（patch 動機 + 設計），這份檔案是「行為對照表」。

---

## L1 patch 的核心 derive 機制

```go
// internal/runtime/executor/codex_session_id.go
func derivePerAuthSessionID(originalID string, auth *cliproxyauth.Auth) string {
    // ... nil / empty 防呆 ...
    return uuid.NewSHA1(uuid.NameSpaceOID, []byte(originalID+":"+authID)).String()
}
```

**呼叫點**：
- HTTP path：`internal/runtime/executor/codex_executor.go:785`（cacheHelper 內）
- WebSocket path：`internal/runtime/executor/codex_websockets_executor.go:851`（applyCodexPromptCacheHeaders 內）

兩個都在「決定要打哪個 auth 之後、寫到 outbound header / body 之前」。

實際送上游的 `Session_id` 永遠是 `derive(originalID, currentAuth)` 的結果，不是 `originalID` 本身。

---

## 不同 inbound 格式的 `originalID` 來源

| Inbound 格式 | originalID 來自 |
|---|---|
| **Codex CLI 直連** | client 送的 `Session_id` header |
| **Claude → Codex** (`from=="claude"`) | `helps.GetCodexCache(model + "-" + metadata.user_id)` 內存的 UUID |
| **OpenAI Chat → Codex** (`from=="openai"`) | `uuid.NewSHA1("cli-proxy-api:codex:prompt-cache:" + apiKey)`（apiKey = inbound CLIProxyAPI 的 userApiKey） |
| **OpenAI Responses → Codex** (`from=="openai-response"`) | client 送的 `prompt_cache_key` |

關鍵：除了 Codex CLI 直連，其它三種 originalID 都是 CLIProxyAPI 「合成」的，不是 client 直接送的 session id。

---

## 情境 A：跨 OAuth 帳號（單一 client / 單一 agent）

「自動切換」（CLIProxyAPI selector 因 rate-limit / `InvalidateAuth` fallback）跟「使用者手動切換」（disable A、enable B）對 L1 來說是同一回事——`selector.Pick` 回的 `auth` 不一樣就觸發 derive 結果不同。

| Client 類型 | Client 看到的 session id | 上游 OAuth 帳號 A 期間收到 | 上游 OAuth 帳號 B 期間收到 |
|---|---|---|---|
| Codex CLI direct | `X`（client 自己送的，不變） | `hash(X : A.ID)` | `hash(X : B.ID)` ✓ 不同 |
| Claude → Codex | （client 不送 session_id；CLIProxyAPI synthesize `Y`） | `hash(Y : A.ID)` | `hash(Y : B.ID)` ✓ 不同 |
| OpenAI Chat → Codex | （同上，synthesize `Y`） | `hash(Y : A.ID)` | `hash(Y : B.ID)` ✓ 不同 |
| OpenAI Responses → Codex | （同上，synthesize 或 client 提供 `Y`） | `hash(Y : A.ID)` | `hash(Y : B.ID)` ✓ 不同 |

**結論**：4 種 inbound 格式都受 L1 保護。換 OAuth 帳號時上游看到的 `Session_id` 一定改變。

---

## 情境 B：同 IP、同 inbound apiKey、多 agent（不同上下文）

> **這是原版設計遺留行為，L1 不解。本 fork 暫不優化。**

只發生在 **OpenAI Chat / Responses 兩個 inbound 格式**，且兩 agent 用同一個 CLIProxyAPI apiKey 時。Codex direct 跟 Claude 因為 originalID 來源本身就有「per-agent / per-conversation」粒度，不會撞。

### Inbound 是 OpenAI Chat (`from=="openai"`)

| 階段 | Agent #1 上游收到 | Agent #2 上游收到 |
|---|---|---|
| OAuth 帳號 A 期間 | `hash(K_A : A.ID)` ← K_A = `hash("cli-proxy-api:codex:prompt-cache:" + apiKey)` | `hash(K_A : A.ID)` **完全相同** |
| OAuth 切到 B | `hash(K_A : B.ID)` ← 共用值更新 | `hash(K_A : B.ID)` **同步更新且仍共用** |
| OAuth 再切到 C | `hash(K_A : C.ID)` | `hash(K_A : C.ID)` |

兩 agent 從第一次請求就在上游視角下共用 session_id；OAuth 換帳號時，這個共用值會改變，但兩 agent 仍共用新值。

### Inbound 是 OpenAI Responses (`from=="openai-response"`)

originalID = client 提供的 `prompt_cache_key`：

- 兩 agent 各自送不同 `prompt_cache_key` → 不會撞
- 兩 agent 送相同 `prompt_cache_key`（例如 client 端被設成寫死） → 同上 OpenAI Chat 表格

### Inbound 是 Codex direct / Claude

兩 agent 都會自然有不同 originalID（前者由 client 端送、後者由 Claude Code 的 `metadata.user_id` 區分），所以**不會撞**。

---

## 情境 B 的安全性影響

對上游來說會看到：「同一個 session_id 下出現兩條（或多條）內容語意完全不相關的對話交錯」。

跟 L1 解掉的「跨 OAuth 帳號 session 連續」相比：
- L1 那條：**決定性池化證據**（同 session id 對應兩個不同 OAuth 帳號）
- 本情境：**弱 bot-like 訊號**（同帳號 + 同 session id 內混亂的 conversation 內容）

對「監控 Codex CLI 模式」的視角來說，本情境屬於「跟真實 CLI 行為不太像」的弱訊號——真實 Codex CLI 一個 session_id 對應一條連貫對話。但要拿來當風控訊號需要更多 noise，影響等級比 L1 的決定性訊號低很多。

## 想避開情境 B 的話（本 fork 暫不做）

1. **每 agent 用不同 inbound apiKey**——management center 多開幾組 key，行為上各 agent 各自的 session id space 自然不撞。**最省事**。
2. **改 cache.ID 計算邏輯**——例如 `cache.ID = hash(apiKey + ":" + first_message_content)` 把對話內容也納進來。fork-local 改動 codex_executor.go 的 cacheHelper，merge 風險中等。如果之後判斷有需要再考慮。

---

## 相關

- `LEAK_RISKS.md` L1：why + 設計取捨
- `LEAK_RISKS.md` F9（在 `/home/ubu/lp/llm-proxy-fingerprint-checklist.md`）：通用 audit 框架對應的條目
- `internal/runtime/executor/codex_fingerprint_regression_test.go`：情境 A 的 4 種組合都有 sub-test 自動驗證
