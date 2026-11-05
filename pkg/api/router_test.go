package api

import (
	"io"
	"log/slog"
	"net/http"
	"strings"

	"net/http/httptest"
	"testing"

	pclient "github.com/didlawowo/proton-mcp-service/pkg/proton"
)

func TestAPIKeyMiddleware(t *testing.T) {
	cases := []struct {
		name, key, header, path string
		allow                   bool
		want                    int
		body                    string
	}{
		{"missing", "test-key", "", "/api/v1/messages", false, 401, ""},
		{"wrong", "test-key", "wrong", "/api/v1/auth/login", false, 401, ""},
		{"correct", "test-key", "test-key", "/api/v1/auth/logout", false, 204, ""},
		{"empty key closed", "", "", "/api/v1/messages", false, 401, ""},
		{"explicit bypass", "test-key", "", "/api/v1/messages", true, 204, ""},
		{"health probe", "test-key", "", "/health", false, 200, "{\"status\":\"ok\"}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("X-API-Key", tc.header)
			rec := httptest.NewRecorder()
			apiKeyMiddleware(tc.key, tc.allow, next).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.body != "" && rec.Body.String() != tc.body {
				t.Fatalf("health response = %q", rec.Body.String())
			}
		})
	}
}

func TestNewRouterAuthenticationAndWriteGate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name, apiKey, writeKey string
		allowAPI, allowWrites  bool
		method, path           string
		want                   int
	}{
		{"read missing api key", "", "", false, false, http.MethodGet, "/api/v1/messages", http.StatusUnauthorized},
		{"read invalid api key", "wrong", "", false, false, http.MethodGet, "/api/v1/messages", http.StatusUnauthorized},
		{"write missing api key", "", "write-secret", false, false, http.MethodPost, "/api/v1/messages/send", http.StatusUnauthorized},
		{"write invalid api key", "wrong", "write-secret", false, false, http.MethodPost, "/api/v1/messages/send", http.StatusUnauthorized},
		{"write missing write key", "api-secret", "", false, false, http.MethodPost, "/api/v1/messages/send", http.StatusForbidden},
		{"write invalid write key", "api-secret", "wrong", false, false, http.MethodPost, "/api/v1/messages/send", http.StatusForbidden},
		{"write with both keys proceeds to proton authentication", "api-secret", "write-secret", false, false, http.MethodPost, "/api/v1/messages/send", http.StatusUnauthorized},
		{"explicit api bypass still requires write key", "", "", true, false, http.MethodPost, "/api/v1/messages/send", http.StatusForbidden},
		{"explicit write bypass proceeds to proton authentication", "api-secret", "", false, true, http.MethodPost, "/api/v1/messages/send", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := NewRouter(&pclient.Client{}, WriteGate{Secret: "write-secret", AllowWithoutKey: tc.allowWrites}, "api-secret", tc.allowAPI, logger)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"to":["a@b.c"],"subject":"s","body":"b"}`))
			if tc.apiKey != "" {
				req.Header.Set("X-API-Key", tc.apiKey)
			}
			if tc.writeKey != "" {
				req.Header.Set("X-Write-Key", tc.writeKey)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestNewRouterHealthDoesNotDiscloseSession(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := NewRouter(&pclient.Client{}, WriteGate{}, "api-secret", false, logger)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("public health disclosed more than status: %d %q", rec.Code, rec.Body.String())
	}
}
