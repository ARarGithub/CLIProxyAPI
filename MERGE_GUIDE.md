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

| 不變式 | 驗證點 |
|---|---|
| `cacheHelper` 接受 `auth *cliproxyauth.Auth` 參數 | `internal/runtime/executor/codex_executor.go` 的 `cacheHelper` 函式 signature |
| `applyCodexPromptCacheHeaders` 接受 `ctx` 與 `auth` 參數 | `internal/runtime/executor/codex_websockets_executor.go` 的同名函式 signature |
| 三個 HTTP / 兩個 websocket callsite 把 auth 傳進去 | grep `cacheHelper(ctx,` / `applyCodexPromptCacheHeaders(ctx,` |
| `derivePerAuthSessionID(cache.ID, auth)` 在 cache.ID 設值之後、寫到 body / header 之前被呼叫 | 兩個 cacheHelper 函式內 |
| `applyCodexHeaders` 內對 `Session_id` 的後處理是「target 已有就不動」(不會被 `misc.EnsureHeader` 用 ginHeaders 覆蓋) | `codex_executor.go` 內 `if strings.TrimSpace(r.Header.Get("Session_id")) == ""` 那段 |

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

# 5b. L1 + L4 unit tests
go test ./internal/runtime/executor/ -run 'CodexExecutorCacheHelper|ApplyCodexPromptCacheHeaders'
go test ./internal/auth/codex/ -run 'NextRefreshLead'
go test ./sdk/auth/ -run 'CodexAuthenticator_RefreshLead'
go test ./sdk/cliproxy/auth/ -run 'JitteredNow'

# 5c. 全測試（看是否引入新 regression；本 fork 預期 3 個既有失敗：
#     antigravity_executor_credits_test.go x 2、registry/model_definitions_test.go x 1）
go test ./... 2>&1 | tail -30
```

**Gate 條件**：5a + 5b 必須全綠。5c 的失敗清單必須跟 merge 前一致（沒有「新增」的失敗）。

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
- `ghcr.io/ararfgithub/cli-proxy-api:v7.1.0-cpa`（pinned，永遠不動）
- `ghcr.io/ararfgithub/cli-proxy-api:latest`（移到這個 tag）

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

### Mode C — `cacheHelper` / `applyCodexPromptCacheHeaders` signature 上游也改

**症狀**：upstream 也加 / 改參數，造成 signature 衝突。

**解法**：
1. 先 accept upstream 對該函式的非 auth 相關修改
2. 然後手動把 `auth *cliproxyauth.Auth` 加回參數列（一般加在最後）
3. callsite 同步傳 auth
4. 函式內保留 `derivePerAuthSessionID(cache.ID, auth)` 那一行

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

## 6. 已知預先存在的測試失敗（不要修，不影響）

下列測試在純 upstream HEAD 也會失敗，跟本 fork 無關：

- `internal/runtime/executor/antigravity_executor_credits_test.go` — `TestEnsureAccessToken_WarmTokenLoadsCreditsHint`
- `internal/runtime/executor/antigravity_executor_credits_test.go` — `TestUpdateAntigravityCreditsBalance_LoadCodeAssistUserAgent`
- `internal/registry/model_definitions_test.go` — `TestCodexFreeModelsExcludeGPT55`

驗證方式：merge 後跑測試列出失敗，跟這份清單對。**只要沒有「新增」的失敗就 OK**。

---

## 7. 維護紀錄

| 日期 | 動作 | Commit |
|---|---|---|
| 2026-05-10 | 初版 L1 patch + 回歸測試 | `39e7cd91` |
| 2026-05-10 | 第一次 merge upstream（v6→v7、apiKey→userApiKey）；衝突解在 `codex_executor_cache_test.go` | merge commit `7f59970a` |
| 2026-05-10 | L4 patch（隨機 lead + persistence + jitter） | `db489fb8` |

未來每次 merge 完更新一行：日期 + merge 帶進來的 upstream 版本 + 解過的衝突類別（對照 §4 Mode A-G）+ commit hash。
