package executor

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestCodexExecutorCacheHelper_OpenAIChatCompletions_StablePromptCacheKeyFromAPIKey(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Set("userApiKey", "test-api-key")

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	executor := &CodexExecutor{}
	rawJSON := []byte(`{"model":"gpt-5.3-codex","stream":true}`)
	req := cliproxyexecutor.Request{
		Model:   "gpt-5.3-codex",
		Payload: []byte(`{"model":"gpt-5.3-codex"}`),
	}
	url := "https://example.com/responses"
	auth := &cliproxyauth.Auth{ID: "auth-A"}

	httpReq, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON, auth)
	if err != nil {
		t.Fatalf("cacheHelper error: %v", err)
	}

	body, errRead := io.ReadAll(httpReq.Body)
	if errRead != nil {
		t.Fatalf("read request body: %v", errRead)
	}

	baseKey := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:test-api-key")).String()
	expectedKey := uuid.NewSHA1(uuid.NameSpaceOID, []byte(baseKey+":auth-A")).String()
	gotKey := gjson.GetBytes(body, "prompt_cache_key").String()
	if gotKey != expectedKey {
		t.Fatalf("prompt_cache_key = %q, want %q", gotKey, expectedKey)
	}
	if gotConversation := httpReq.Header.Get("Conversation_id"); gotConversation != "" {
		t.Fatalf("Conversation_id = %q, want empty", gotConversation)
	}
	if gotSession := httpReq.Header.Get("Session_id"); gotSession != expectedKey {
		t.Fatalf("Session_id = %q, want %q", gotSession, expectedKey)
	}

	httpReq2, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON, auth)
	if err != nil {
		t.Fatalf("cacheHelper error (second call): %v", err)
	}
	body2, errRead2 := io.ReadAll(httpReq2.Body)
	if errRead2 != nil {
		t.Fatalf("read request body (second call): %v", errRead2)
	}
	gotKey2 := gjson.GetBytes(body2, "prompt_cache_key").String()
	if gotKey2 != expectedKey {
		t.Fatalf("prompt_cache_key (second call) = %q, want %q", gotKey2, expectedKey)
	}
}

func TestCodexExecutorCacheHelper_PerAuthSessionIDDiffersAcrossAuths(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Set("userApiKey", "test-api-key")

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	executor := &CodexExecutor{}
	rawJSON := []byte(`{"model":"gpt-5.3-codex","stream":true}`)
	req := cliproxyexecutor.Request{
		Model:   "gpt-5.3-codex",
		Payload: []byte(`{"model":"gpt-5.3-codex"}`),
	}
	url := "https://example.com/responses"

	authA := &cliproxyauth.Auth{ID: "auth-A"}
	authB := &cliproxyauth.Auth{ID: "auth-B"}

	reqA, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON, authA)
	if err != nil {
		t.Fatalf("cacheHelper(authA) error: %v", err)
	}
	reqB, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON, authB)
	if err != nil {
		t.Fatalf("cacheHelper(authB) error: %v", err)
	}

	sidA := reqA.Header.Get("Session_id")
	sidB := reqB.Header.Get("Session_id")
	if sidA == "" || sidB == "" {
		t.Fatalf("Session_id missing: A=%q B=%q", sidA, sidB)
	}
	if sidA == sidB {
		t.Fatalf("Session_id leaked across auths: A=B=%q (must differ)", sidA)
	}

	bodyA, _ := io.ReadAll(reqA.Body)
	bodyB, _ := io.ReadAll(reqB.Body)
	pckA := gjson.GetBytes(bodyA, "prompt_cache_key").String()
	pckB := gjson.GetBytes(bodyB, "prompt_cache_key").String()
	if pckA == pckB {
		t.Fatalf("prompt_cache_key leaked across auths: A=B=%q (must differ)", pckA)
	}
	if pckA != sidA || pckB != sidB {
		t.Fatalf("body prompt_cache_key must match header Session_id (A: %q vs %q; B: %q vs %q)", pckA, sidA, pckB, sidB)
	}
}

func TestCodexExecutorCacheHelper_DirectCodexInheritsAndDerivesGinSessionID(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Request.Header.Set("Session_id", "client-session-XYZ")

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	executor := &CodexExecutor{}
	rawJSON := []byte(`{"model":"gpt-5.3-codex"}`)
	req := cliproxyexecutor.Request{Model: "gpt-5.3-codex", Payload: []byte(`{}`)}
	url := "https://example.com/responses"

	authA := &cliproxyauth.Auth{ID: "auth-A"}
	authB := &cliproxyauth.Auth{ID: "auth-B"}

	reqA, err := executor.cacheHelper(ctx, sdktranslator.FromString("codex"), url, req, rawJSON, authA)
	if err != nil {
		t.Fatalf("cacheHelper(authA) error: %v", err)
	}
	reqB, err := executor.cacheHelper(ctx, sdktranslator.FromString("codex"), url, req, rawJSON, authB)
	if err != nil {
		t.Fatalf("cacheHelper(authB) error: %v", err)
	}

	sidA := reqA.Header.Get("Session_id")
	sidB := reqB.Header.Get("Session_id")
	if sidA == "" || sidB == "" {
		t.Fatalf("direct path did not set Session_id: A=%q B=%q", sidA, sidB)
	}
	if sidA == "client-session-XYZ" || sidB == "client-session-XYZ" {
		t.Fatalf("direct path forwarded raw client session_id without derivation: A=%q B=%q", sidA, sidB)
	}
	if sidA == sidB {
		t.Fatalf("direct path leaked session_id across auths: %q", sidA)
	}
	expectedA := uuid.NewSHA1(uuid.NameSpaceOID, []byte("client-session-XYZ:auth-A")).String()
	if sidA != expectedA {
		t.Fatalf("direct path Session_id = %q, want %q", sidA, expectedA)
	}
}
