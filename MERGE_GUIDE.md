# Merge Guide — fork-local fingerprint patches

> 本檔說明：當 upstream `router-for-me/CLIProxyAPI` 更新時，如何安全地把它合進這個 fork，並確保所有指紋優化 patch 在 merge 後仍然有效。
>
> 配套文件：
> - `LEAK_RISKS.md` — patch 的 WHY（每條指紋風險的成因 + 修復方案）
> - 本檔 — patch 的 HOW（merge 操作流程 + 衝突模式 + 驗證 gate）

---

## 1. 我們要保留的 patch 清單

| ID | 一句話描述 | 主要檔案 |
|---|---|---|
| **L1** | Codex `Session_id` per-auth 衍生，避免換 OAuth 帳號時上游能跨帳號關聯同一 session | `internal/runtime/executor/codex_executor.go`<br>`internal/runtime/executor/codex_websockets_executor.go`<br>`internal/runtime/executor/codex_session_id.go`（新檔）<br>`internal/runtime/executor/codex_executor_cache_test.go`<br>`internal/runtime/executor/codex_websockets_executor_test.go`<br>`internal/runtime/executor/codex_fingerprint_regression_test.go`（新檔，回歸測試） |
| **L4** | Codex refresh lead 隨機化 [3d, 7d) + 持久化到 metadata + startup burst jitter | `internal/auth/codex/refresh_lead.go`（新檔）<br>`internal/auth/codex/refresh_lead_test.go`（新檔）<br>`sdk/auth/codex.go`<br>`sdk/auth/codex_device.go`<br>`sdk/auth/codex_refresh_lead_test.go`（新檔）<br>`internal/runtime/executor/codex_executor.go`<br>`sdk/cliproxy/auth/auto_refresh_loop.go`<br>`sdk/cliproxy/auth/jitter_test.go`（新檔） |

兩個 patch 對應的 commit：
- L1: `39e7cd91 fix(codex): derive Session_id per-auth to prevent cross-account pool fingerprint`
- L4: `db489fb8 fix(codex): randomize + persist refresh lead and jitter startup burst`

---

## 2. Patch 的關鍵不變式（merge 後必須保住）

### L1 不變式

> **2026-05-11 重構**：所有 fingerprint hardening 集中到 `internal/runtime/executor/codex_fingerprint_hardening.go` 的 `applyCodexFingerprintHardeningHTTP` / `applyCodexFingerprintHardeningWS` 兩個函式。upstream 的 `cacheHelper` / `applyCodexHeaders` / `applyCodexPromptCacheHeaders` / `applyCodexWebsocketHeaders` 全部回到原版（**沒有 inline 修改**），只在每個 Execute 變體 / WS callsite 後面多一行 hardening 呼叫。下表的「驗證點」反映新結構。

| 不變式 | 驗證點 |
|---|---|
| **存在 hardening 函式** `applyCodexFingerprintHardeningHTTP` / `applyCodexFingerprintHardeningWS` | grep `internal/runtime/executor/codex_fingerprint_hardening.go` 內兩個函式定義 |
| **每條 outbound 路徑在 `applyCodex*Headers` 之後立即呼叫 hardening** | grep `applyCodexFingerprintHardeningHTTP(ctx, httpReq, auth, url)` 應出現 3 次（Execute, ExecuteStream, executeCompact）；`applyCodexFingerprintHardeningWS(ctx, body, wsHeaders, auth)` 應出現 2 次（websocket Execute / ExecuteStream） |
| **`cacheHelper` / `applyCodexPromptCacheHeaders` 是 upstream 原版**（不含 auth 參數、不含我們的 inline derive） | `cacheHelper` signature 不含 `auth`；`applyCodexPromptCacheHeaders` 不含 `ctx` / `auth` |
| **存在兩個獨立 derive 函式** `derivedSessionID` / `derivedThreadID`，namespace 不同 | `internal/runtime/executor/codex_session_id.go` 的 `derivedSessionNamespace` / `derivedThreadNamespace` 常數 + 兩個函式 |
| **對任何 (originalID, auth.ID)，`derivedSessionID(...) ≠ derivedThreadID(...)`** | `TestDerive_CrossStream_AlwaysDistinct_*` |
| **hardening 用 `derivedSessionID` 寫 `Session_id` header、用 `derivedThreadID` 寫 `Thread_id` / `X-Client-Request-Id` headers + body `prompt_cache_key`** | `applyCodexFingerprintHeaders` 函式內；`TestCodexFingerprintHardeningHTTP_*` / `TestCodexFingerprintHardeningWS_*` |
| **codex 直連路徑分別讀 inbound `Session_id` 與 `Thread_id` 兩個 header** | `computeCodexFingerprintValues` 從 ginCtx 讀取；`TestCodexFingerprintHardeningHTTP_DirectCodex_MirrorsInboundV7Timestamp` 用 inbound v7 各送一個並驗證 derived 對齊 |
| **WS hardening 必須 strip `Conversation_id` header**（upstream 原版會送，real client 不會） | `applyCodexFingerprintHardeningWS` 末尾 `headers.Del("Conversation_id")` 等四個 case 變體；`TestCodexFingerprintHardeningWS_NoConversationId_OnlySessionAndThread` |
| **derive 輸出永遠是合法 UUIDv7，timestamp 落在最近合理範圍** | `assertCodexV7Mimic` / `assertLooksLikeRealCodexSessionID` 在 regression test 與單元測試對 Session_id + Thread_id + prompt_cache_key 各跑一次 |
| **若 inbound 是合法 v7，輸出 v7 timestamp 必須等於 inbound 對應 stream 的 v7 timestamp** | `codex_session_id.go` 內 `if inU.Version()==7 { timestampMs = extractV7TimestampMs(inU) }`；`TestCodexFingerprintHardeningHTTP_DirectCodex_MirrorsInboundV7Timestamp` |
| **derive 輸出對 `(originalID, auth.ID)` 配對在進程 lifetime 內 deterministic** | `TestDerive_Deterministic_*` 跨 50 次呼叫驗證；timestamp cache TTL = 1h |
| **`Thread_id == X-Client-Request-Id == prompt_cache_key`**（real Codex CLI 三個都用 state.thread_id） | regression test 對每個 record 跑 `tid != xrid` / `tid != pck` 失敗 |
| **`Session_id ≠ prompt_cache_key`**（real Codex CLI 永不會等於） | regression test 對每個 record 跑 `sid == pck` 失敗 |
| **每個 auth 在 metadata 內有 `installation_id`（合法 UUIDv4）** | `ensureCodexInstallationID` 在 `buildAuthRecord` + `Refresh` 都呼叫；`TestEnsureCodexInstallationID_*` |
| **`ensureCodexInstallationID` 永不覆寫已存在的值** | `TestEnsureCodexInstallationID_PreservesExistingValue` |
| **body 永遠帶 `client_metadata.x-codex-installation-id`** 且為 v4 UUID | regression test |
| **compact path 多送 `X-Codex-Installation-Id` header** | `applyCodexFingerprintHeaders(headers, v, compactPath, ...)` 內 `if compactPath && v.installationID != ""` 那段；`TestCodexFingerprintHardeningHTTP_CompactPath_AddsInstallationIDHeader` |
| **`X-Codex-Window-Id` 永遠帶**，格式 `"{uuid}:{integer}"` | regression test |
| **`X-Codex-Window-Id` 的 thread 部分跨 auth 必不同** | `crossAuthLeakFields` 內條目 |
| **codex 直連路徑保留 inbound `X-Codex-Window-Id` 的 generation 數字** | `computeCodexFingerprintValues` 內 `parseInboundWindowGeneration(...)`；`TestCodexWindowID_RoundTripGenerationFromInbound` |
| **httpReq.Body 重置後 GetBody 也重設**（讓 Go transport 可 retry） | `resetRequestBody` 設 `httpReq.GetBody`；`TestCodexFingerprintHardeningHTTP_BodyResetIsRetrySafe` |
| **Conditional codex CLI headers**（`X-Openai-Subagent` / `X-Codex-Parent-Thread-Id`）只在 inbound 有時 forward；`X-Oai-Attestation` 永遠 strip | `applyCodexFingerprintHeaders` 內 setHeader + strip 段；`TestCodexFingerprintHardeningHTTP_ConditionalHeaders_ForwardedFromInbound` / `_AbsentWhenInboundAbsent` / `_Attestation_StrippedEvenWhenInboundPresent` |
| **`X-Codex-Parent-Thread-Id` 必 per-auth derive**（不可 verbatim forward） | `computeCodexFingerprintValues` 內 `derivedThreadID(inboundParent, auth)`；`TestCodexFingerprintHardeningHTTP_ParentThreadID_DerivedPerAuth`；regression test `crossAuthLeakFields` 內 `X-Codex-Parent-Thread-Id` + `client_metadata.x-codex-parent-thread-id` 條目 |
| **WS body `client_metadata.x-codex-parent-thread-id` 與 header `x-codex-parent-thread-id` 同值**（real Codex CLI 兩處同字串） | `applyCodexFingerprintBody` + `applyCodexFingerprintHeaders`；`TestCodexFingerprintHardeningWS_ClientMetadata_ParentThreadIDDerived` |
| **WS body `client_metadata.x-openai-subagent` / `.x-codex-turn-metadata` 是 passthrough**（hardening 不動，sjson 只動指定 key） | `TestCodexFingerprintHardeningWS_ClientMetadata_PassthroughFields` |

### L4 不變式

| 不變式 | 驗證點 |
|---|---|
| `CodexAuthenticator.RefreshLead()` 回 `[3d, 7d)` 隨機 (不是寫死 5d) | `sdk/auth/codex.go` |
| 新 OAuth 登入時 metadata 已有 `refresh_interval_seconds` | `sdk/auth/codex_device.go` 的 `buildAuthRecord` |
| `CodexExecutor.Refresh()` 成功後寫新 roll 到 `auth.Metadata["refresh_interval_seconds"]` | `internal/runtime/executor/codex_executor.go` 的 `Refresh` 函式 |
| `nextRefreshCheckAt` 內所有「立刻 refresh」的 return 都用 `jitteredNow(now)` 不是 `now` | `sdk/cliproxy/auth/auto_refresh_loop.go` |

---

## 3. Merge 標準流程

### Step 1 — 工作環境檢查

```bash
git status -s              # 必須 clean
git remote -v | grep upstream  # upstream 必須存在；沒有就 git remote add upstream https://github.com/router-for-me/CLIProxyAPI
```

### Step 2 — Fetch + 預檢

```bash
git fetch upstream main
git log --oneline HEAD..upstream/main | head -30   # upstream 新增了什麼
git diff --stat HEAD..upstream/main -- \
  internal/runtime/executor/codex_executor.go \
  internal/runtime/executor/codex_websockets_executor.go \
  internal/runtime/executor/codex_executor_cache_test.go \
  internal/runtime/executor/codex_websockets_executor_test.go \
  sdk/auth/codex.go \
  sdk/auth/codex_device.go \
  sdk/cliproxy/auth/auto_refresh_loop.go \
  internal/auth/codex/openai_auth.go
```

如果上面 `diff --stat` 列出的檔案都沒被 upstream 動 → merge 大概率乾淨。
如果有動 → 預期會衝突，往下看常見模式。

### Step 3 — Merge

```bash
git merge upstream/main --no-commit --no-ff
```

`--no-commit --no-ff` 確保 merge commit 一定建立、且能在 commit 前先解衝突 + 跑測試。

### Step 4 — 解衝突

按 §4 的「常見衝突模式」處理。最後：

```bash
git status -s              # 應該只剩你已解的檔案
go build ./... 2>&1 | head -20
```

### Step 5 — 驗證 gate（必跑）

```bash
# 5a. L1 回歸測試 — 跨 auth fingerprint 必須測過
go test ./internal/runtime/executor/ -run 'TestCodexUpstreamFingerprintRegression' -v

# 5b. Session ID 行為測試套件 — 詳見 §6
go test ./internal/runtime/executor/ -run 'TestDerivePerAuthSessionID' -v

# 5c. L1 + L4 unit tests
go test ./internal/runtime/executor/ -run 'CodexExecutorCacheHelper|ApplyCodexPromptCacheHeaders'
go test ./internal/auth/codex/ -run 'NextRefreshLead'
go test ./sdk/auth/ -run 'CodexAuthenticator_RefreshLead'
go test ./sdk/cliproxy/auth/ -run 'JitteredNow'

# 5d. 全測試（看是否引入新 regression；本 fork 預期 3 個既有失敗：
#     antigravity_executor_credits_test.go x 2、registry/model_definitions_test.go x 1）
go test ./... 2>&1 | tail -30
```

**Gate 條件**：5a + 5b + 5c 必須全綠。5d 的失敗清單必須跟 merge 前一致（沒有「新增」的失敗）。

### Step 6 — Commit + push

```bash
git commit --no-edit       # 或自己改 merge message
git push origin main
```

### Step 7 — Tag with the fork-local convention（如果 upstream 帶進來的是新 release）

如果剛 merge 進來的 upstream 包含新 tag（例如 `v7.1.0`），且 main 上 fork 的 patch 全部驗證 OK，就用「upstream tag + `-cpa`」的格式打 tag：

```bash
# 例如 upstream 剛出 v7.1.0、merge 完 + 驗證 gate 通過
UPSTREAM_TAG=v7.1.0
git tag -a "${UPSTREAM_TAG}-cpa" -m "fork ${UPSTREAM_TAG}-cpa: upstream ${UPSTREAM_TAG} + L1 + L4"
git push origin "${UPSTREAM_TAG}-cpa"
```

`-cpa` = Cli-Proxy-API（fork 自己的後綴），讓 fork 的 release 跟 upstream tag 一眼可對：

| Fork tag | 對應 upstream | 內容 |
|---|---|---|
| `v7.0.0-cpa` | `v7.0.0` | upstream v7.0.0 + L1 + L4 |
| `v7.1.0-cpa` | `v7.1.0` | upstream v7.1.0 + L1 + L4（可能含 patch 重新貼合） |
| `v7.1.0-cpa.1` | `v7.1.0` | 在 `v7.1.0-cpa` 之後又改了 fork-local patch |

`-cpa` tag 推上去之後 `.github/workflows/ghcr-publish.yml` 自動 build 一個對應 image：
- `ghcr.io/arargithub/cli-proxy-api:v7.1.0-cpa`（pinned，永遠不動）
- `ghcr.io/arargithub/cli-proxy-api:latest`（移到這個 tag）

**只在「升級 upstream 大/中版號」時打 tag**。fork-local 小修不打 tag——就靠 `latest` + commit SHA tag 跑。

---

## 4. 常見衝突模式 + 解法

### Mode A — Module path bump (v6 → v7 → vN)

**症狀**：upstream 升 module 大版號時，所有 import path 從 `CLIProxyAPI/v6/...` 變成 `CLIProxyAPI/v7/...`。Auto-merge 通常處理掉大部分但會在我們新加的檔案漏改。

**解法**：
1. `grep -rn "CLIProxyAPI/v[0-9]" internal/runtime/executor/codex_session_id.go internal/runtime/executor/codex_fingerprint_regression_test.go internal/auth/codex/refresh_lead.go internal/auth/codex/refresh_lead_test.go sdk/auth/codex_refresh_lead_test.go sdk/cliproxy/auth/jitter_test.go` 找出我們新檔案內的舊版 import
2. 用新版號 search-and-replace。

### Mode B — gin context key 改名 (`apiKey` → `userApiKey` 之類)

**症狀**：upstream 改 gin context 的 key 名（已發生過：`apiKey` → `userApiKey`），測試裡 `ginCtx.Set("...")` 跟 `helps.APIKeyFromContext` 讀的 key 不一致。

**解法**：
1. 開 `internal/runtime/executor/helps/usage_helpers.go` 看 `APIKeyFromContext` 用什麼 key
2. 把我們的測試裡 `ginCtx.Set("舊key", ...)` 全部改成新 key（檢查 `internal/runtime/executor/codex_executor_cache_test.go`、`internal/runtime/executor/codex_fingerprint_regression_test.go`）

### Mode C — `cacheHelper` / `applyCodexPromptCacheHeaders` body 上游改

**症狀**：upstream 改這些函式的內部邏輯。

**解法**：**通常不用做事**。2026-05-11 重構後我們不再 inline 修改這些函式——所有 fingerprint hardening 集中在 `applyCodexFingerprintHardeningHTTP` / `applyCodexFingerprintHardeningWS`，在 upstream 函式之後跑、會覆寫 upstream 的輸出。upstream 改 cacheHelper 內 `cache.ID` 算法、改 header 名字、改 body 欄位設定——hardening 會把它覆寫成我們要的值，下游看不出差異。

例外：upstream 把 `cacheHelper` / `applyCodexPromptCacheHeaders` 的 signature 改了 → callsite 衝突。先 accept upstream 改動，3 個 cacheHelper callsite 與 2 個 applyCodexPromptCacheHeaders callsite 後面加回 hardening 呼叫即可（grep 範例見「L1 不變式」表）。

### Mode D — `Refresh()` 函式 upstream 重構

**症狀**：upstream 改了 token 寫入 metadata 的順序 / 條件 / 結構。

**解法**：保住「成功 refresh 後一定要寫一筆 `auth.Metadata["refresh_interval_seconds"] = int(codexauth.NextRefreshLead().Seconds())`」這個不變式。**位置可以調整，但這行必須存在且只在 refresh 成功路徑。**

### Mode E — `nextRefreshCheckAt` 邏輯上游改寫

**症狀**：upstream 改了排程邏輯，新增 / 刪除 `return now, true` 的分支。

**解法**：
1. Search `return now, true` 在 `nextRefreshCheckAt` 函式內的所有出現
2. 改成 `return jitteredNow(now), true`
3. 確認 `jitteredNow` 函式還在 `auto_refresh_loop.go`，沒被 upstream 改掉
4. 確認 `import "math/rand"` 還在

### Mode F — `buildAuthRecord` 在 `codex_device.go` 被改

**症狀**：upstream 改 metadata 初始 keys。

**解法**：保住 `metadata` map 內必須包含 `"refresh_interval_seconds": int(codex.NextRefreshLead().Seconds())`。

### Mode G — 整個函式被刪掉 / 改名

**症狀**：upstream 重構掉了我們依賴的 hook（例如 `cacheHelper` 被拆成多個小函式、或 `applyCodexHeaders` 被合併到別處）。

**解法**：這是最棘手的情況。需要：
1. 看 upstream 的新架構，找出「等價的 hook 點」
2. 把 L1 的 per-auth 衍生 / L4 的 metadata 寫入邏輯 移到新 hook 點
3. 跑回歸測試確認 fingerprint 還是被擋住
4. 更新本檔的「主要檔案」清單與不變式

### Mode H — `.github/workflows/docker-image.yml` 被 upstream 修改

**症狀**：merge 時出現 `CONFLICT (modify/delete): .github/workflows/docker-image.yml`。

**解法**：**保持刪除狀態**。這個 workflow 是 upstream 用來 push 到他們的 Docker Hub repo `eceasy/cli-proxy-api`，需要 `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` secret 才能跑——本 fork 沒有也不需要這些 secret，每次 tag push 都會失敗噪音化 Actions 頁面。fork 用 `.github/workflows/ghcr-publish.yml` 推到 ghcr.io 取代它。

```bash
git rm .github/workflows/docker-image.yml
git add .github/workflows/docker-image.yml   # 確認刪除狀態被 stage
# 繼續 merge commit
```

如果哪天 fork 也想推 Docker Hub，**新建一個 `.github/workflows/dockerhub-publish.yml`** 模仿 `ghcr-publish.yml` 的結構（讀 `DOCKERHUB_*` secret），不要 revive `docker-image.yml`，理由同 §3 開頭：避開高頻檔案。

---

## 5. 萬一回歸測試 fail

### `TestCodexUpstreamFingerprintRegression_NoCrossAuthCorrelation/<scenario>` 失敗

每個 sub-test 對一個 inbound 格式（codex 直連 / openai-response / openai chat / claude）。失敗訊息形式：

- **`LEAK: header Session_id = "..." across auth-A and auth-B`**
  → 上游收到「跨 auth 同 session id」的決定性指紋。表示 L1 的 derive 路徑被打掉了。回 §4 Mode C 或 G。

- **`LEAK: body prompt_cache_key = "..." across ...`**
  → cacheHelper 的 body 寫入路徑被打掉了，或 derive 跑了但只寫 header 沒寫 body。檢查 cacheHelper 結尾的 `sjson.SetBytes(rawJSON, "prompt_cache_key", cache.ID)`。

- **`STABILITY: header Session_id differs across two requests with the same auth`**
  → 同 auth 跑兩次 session id 不穩定，prompt cache 會 miss。多半是 `derivePerAuthSessionID` 本身被改成非 deterministic。確認還在用 `uuid.NewSHA1(NameSpaceOID, ...)`。

- **`potential new leak: header X = "..." is identical across auth-A and auth-B`**
  → **Soft warning**，不會 fail 測試但要 review。如果 X 是新 header 且確實是 upstream 加的「conversation/session 關聯欄位」，需要把它也加進 `crossAuthLeakFields` 清單裡，並讓 L1 的 derive 涵蓋它。如果 X 是 transport 層或常數，加到 `genericNoiseFieldsAllowedIdentical` 白名單。

### L4 unit tests 失敗

- `TestNextRefreshLead_WithinBounds` → `NextRefreshLead` 範圍出錯，檢查 `internal/auth/codex/refresh_lead.go`
- `TestCodexAuthenticator_RefreshLead_RandomInBounds` → `sdk/auth/codex.go` 的 RefreshLead 沒在用 helper
- `TestJitteredNow_*` → `auto_refresh_loop.go` 的 `jitteredNow` 函式被改掉

---

## 6. Session ID 行為測試套件

> **動 `derivePerAuthSessionID` 之前先看這節**。每條測試對應一個 patch 必須保住的不變式，跑掉哪條就回去看是不是把對應的不變式破壞了。

測試檔：`internal/runtime/executor/codex_session_id_test.go`

執行：

```bash
go test ./internal/runtime/executor/ -run 'TestDerivePerAuthSessionID' -v
```

| 測試 | 不變式 |
|---|---|
| `_Deterministic_CodexDirect` | Codex 直連路徑：同 `(originalID, auth.ID)` 跨 50 次呼叫輸出一致（timestamp 借自 inbound 不變） |
| `_Deterministic_NonCodex` | 非 codex 路徑：同 `(originalID, auth.ID)` 跨 50 次呼叫輸出一致（in-memory cache 命中） |
| `_AuthSwitching_RoundTrip_CodexDirect` | 切換 `(X,A)→(X,B)→(X,A)→(X,B)` 後，`s0==s2 ∧ s1==s3 ∧ s0!=s1`。回到舊 auth 必須拿到原本的 upstream id（讓 prompt cache 連續性可用）|
| `_AuthSwitching_RoundTrip_NonCodex` | 同上，覆蓋非 codex 路徑（cache 必須以 auth 為維度獨立 pin） |
| `_Timestamp_BorrowedFromInboundV7` | Codex 直連的輸出 v7 timestamp 必須**等於** inbound v7 timestamp（不論 auth 是哪個） |
| `_Timestamp_PinnedAtFirstCall_NonCodex` | 非 codex 路徑 first-call 的輸出 timestamp 在「呼叫前 `time.Now()`」與「呼叫後 `time.Now()`」之間（誤差 100ms 容忍）；之後即使 sleep 過了，第二次呼叫的輸出 timestamp 必須等於第一次（cache pin） |
| `_Timestamp_DifferentAuthsHaveIndependentCacheEntries` | 同 `originalID` + 不同 `auth.ID` 的 cache 必須是獨立 entry，各自 pin 各自的 timestamp |
| `_DifferentInputs_DifferentOutputs` | 同 auth + 不同 originalID → 不同 output |
| `_DifferentAuths_DifferentOutputs` | 同 originalID + 不同 auth → 不同 output（這是 L1 主訴求） |
| `_EmptyOriginalID_ReturnsEmpty` | 空字串 / 純空白 originalID → 回空字串（防止 derive 出垃圾） |
| `_NilAuth_ReturnsOriginal` | nil auth → 原樣回 originalID（測試友善 + 防呆） |
| `_EmptyAuthID_ReturnsOriginal` | 空 auth.ID → 原樣回 originalID（同上） |
| `_NonV7Inbound_OutputsV7` | inbound 是 v4 / v5 / 任意字串時，輸出仍然是 v7（**永遠不要把 inbound 的非 v7 版本傳到上游**） |
| `_StructurallyValidV7` | 5 個 inbound 變體（v7 / v4 / v5 / 非 UUID / 長字串）的輸出都通過 `assertLooksLikeRealCodexSessionID`（合法 UUID + version=7 + RFC4122 variant + timestamp 在最近 30 天內） |
| `_ConcurrentSameInput_AllAgree` | 64 個 goroutine 同時對同一個 input 呼叫，輸出必須全部一致（cache mutex 沒壞） |

### 加新測試的時機

- 新增 fingerprint 通道時（例如 derive 函式的輸入或輸出多了一個欄位）
- 新增一個 inbound 格式時（例如 fork 之後支援新的 client 種類）
- 上游改了 UUID 套件 / 換了 hash 演算法 / Codex CLI 升級到 UUIDv8
- 動到 `cachedDerivedTimestampMs` 的 cache 行為（TTL、cleanup、lock 等）

### 故障診斷對照（除了這套測試之外，回歸測試 fail 訊息對照見 §5）

| 跑掛的測試 | 通常原因 |
|---|---|
| `_Deterministic_*` | derive 函式被改成非純函數（例如直接用 `time.Now()` 不經 cache） |
| `_AuthSwitching_RoundTrip_*` | cache key 算法被改、不再以 `(originalID, auth.ID)` pair 為唯一索引 |
| `_Timestamp_BorrowedFromInboundV7` | derive 對 inbound v7 timestamp 的處理被打掉（例如改成永遠用 `time.Now()`）|
| `_Timestamp_PinnedAtFirstCall_NonCodex` | 非 codex 路徑沒在用 cache，每次都 fresh `time.Now()` |
| `_NonV7Inbound_OutputsV7` | derive 函式被改成「mirror inbound version」之類的——不要這樣做，real Codex CLI 永遠是 v7 |
| `_StructurallyValidV7` | version bits / variant bits / timestamp 注入邏輯壞了 |
| `_ConcurrentSameInput_AllAgree` | cache mutex 漏掉、變成 race-condition |

---

## 7. 已知預先存在的測試失敗（不要修，不影響）

下列測試在純 upstream HEAD 也會失敗，跟本 fork 無關：

- `internal/runtime/executor/antigravity_executor_credits_test.go` — `TestEnsureAccessToken_WarmTokenLoadsCreditsHint`
- `internal/runtime/executor/antigravity_executor_credits_test.go` — `TestUpdateAntigravityCreditsBalance_LoadCodeAssistUserAgent`
- `internal/registry/model_definitions_test.go` — `TestCodexFreeModelsExcludeGPT55`

驗證方式：merge 後跑測試列出失敗，跟這份清單對。**只要沒有「新增」的失敗就 OK**。

---

## 8. 維護紀錄

| 日期 | 動作 | Commit |
|---|---|---|
| 2026-05-10 | 初版 L1 patch + 回歸測試 | `39e7cd91` |
| 2026-05-10 | 第一次 merge upstream（v6→v7、apiKey→userApiKey）；衝突解在 `codex_executor_cache_test.go` | merge commit `7f59970a` |
| 2026-05-10 | L4 patch（隨機 lead + persistence + jitter） | `db489fb8` |
| 2026-05-11 | L1 拆兩 stream（D）+ 移除 Conversation_id（E） | `1df53cd5` |
| 2026-05-11 | 新增 F（per-auth installation_id）+ G（x-codex-window-id） | `85214cd0` |
| 2026-05-11 | 重構：fingerprint hardening 集中到 `codex_fingerprint_hardening.go`；upstream 函式全 revert | `4f3165aa` |
| 2026-05-11 | H 完成：conditional codex headers（subagent / parent_thread_id / attestation）；I 完成：WS client_metadata 多欄位處理（parent derive、其它 passthrough）；J 完成：regression test 加 subagent scenario 與 per-record conditional invariants | `720b664d` |

未來每次 merge 完更新一行：日期 + merge 帶進來的 upstream 版本 + 解過的衝突類別（對照 §4 Mode A-G）+ commit hash。
