# `auth.Metadata["refresh_interval_seconds"]` — 寫入時機備忘

> 簡短摘要：這個欄位**只有兩個時機**會被建立或更新。其他改 auth 檔的動作都不會碰它。
>
> 完整背景見 `LEAK_RISKS.md` L4。

---

## 唯二 write 路徑

| # | 觸發 | 程式碼位置 | 行為 |
|---|---|---|---|
| **1** | OAuth 新登入完成 | `sdk/auth/codex_device.go:buildAuthRecord` | `metadata` 初始化時就 seed `int(codex.NextRefreshLead().Seconds())` |
| **2** | Token refresh 成功 | `internal/runtime/executor/codex_executor.go:Refresh` | 寫入 `int(codexauth.NextRefreshLead().Seconds())`；不存在就新增、存在就覆蓋 |

兩條路徑的值**都是當下重新 roll 的 [3d, 7d) 隨機 `time.Duration` 換算成秒的整數**（259200 ≤ value < 604800）。

## **不會** write 的路徑（即使動 auth 檔）

- enable / disable auth（`PatchAuthFile` `Disabled` 翻 flag）
- 上傳 / import auth 檔（`UploadAuthFile` 原樣寫 bytes）
- 編輯 prefix / proxy_url / headers / priority / note 等欄位
- File watcher 偵測磁碟變動後重 load
- Auth selector 的 session-affinity rebinding
- Manager.Update 由其他理由觸發的存檔

## 衍生事實

- **舊 auth 檔（升級到本 fork 之前就存在）在第一次 Refresh 成功之前，這個欄位是缺的**——這是預期行為，不是 bug。
- **指紋保護不依賴此欄位存在**：即使欄位缺，scheduler 每次 reschedule 仍透過 `nextRefreshCheckAt` → `ProviderRefreshLead` → `CodexAuthenticator.RefreshLead()` 即時 roll 一個 [3d, 7d) 隨機值。差別只在「重啟會 re-roll」這個附加屬性。
- **這個欄位的價值是「跨重啟穩定」**：persisted 之後，docker compose down/up、process restart、heap rebuild 都不會 re-roll，下個 Refresh 才換新值。
- 想對舊 auth 立刻有此欄位，見 `LEAK_RISKS.md` L4 的 jq seed 腳本。

## 觀念釐清：login 與 refresh 為什麼都「順手」寫這個值

兩條路徑寫此欄位的角色其實一致：**都是 defensive 的順手 persist，不是該流程本身需要這個值**。

- Login 不需要 `RefreshLead()`——剛拿到 token，還沒有「下次什麼時候 refresh」這個問題
- Refresh 也不需要先讀 `refresh_interval_seconds` 才能跑——這次 refresh 的時機是上一個 cycle 的值決定的

兩處寫入都是寫給**未來 cycle** 的 scheduler 用的。SDK 排程鏈 `nextRefreshCheckAt → authPreferredInterval → ProviderRefreshLead` 跟「值是誰寫的、何時寫的」無關，只在乎讀到的值是什麼。

## 驗證

```bash
# 看某個 auth 檔的當前值（秒）
jq '.refresh_interval_seconds' path/to/auths/<file>.json

# 換算成天
jq '.refresh_interval_seconds / 86400' path/to/auths/<file>.json
```

期望：259200 ≤ value < 604800（3d ≤ value < 7d）。

跨 cycle 觀察：成功 Refresh 一次後再看，**值應該不同**（因為 path 2 重 roll）。
