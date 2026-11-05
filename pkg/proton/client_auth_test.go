package proton

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	goproton "github.com/ProtonMail/go-proton-api"
	"github.com/go-resty/resty/v2"

	"github.com/didlawowo/proton-mcp-service/pkg/session"
)

// fakeProton is a minimal Proton API double: it serves /core/v4/users and
// /auth/v4/refresh, and lets tests script the refresh outcome.
type fakeProton struct {
	srv *httptest.Server

	refreshStatus atomic.Int32 // HTTP status returned by /auth/v4/refresh
	refreshCalls  atomic.Int32
	userCalls     atomic.Int32
}

func newFakeProton(t *testing.T) *fakeProton {
	t.Helper()
	f := &fakeProton{}
	f.refreshStatus.Store(http.StatusOK)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v4/refresh", func(w http.ResponseWriter, r *http.Request) {
		f.refreshCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		status := int(f.refreshStatus.Load())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			fmt.Fprintf(w, `{"Code":%d,"Error":"refresh rejected"}`, status)
			return
		}
		fmt.Fprint(w, `{"Code":1000,"UID":"uid1","AccessToken":"acc2","RefreshToken":"ref2","Scope":"full"}`)
	})
	mux.HandleFunc("/core/v4/users", func(w http.ResponseWriter, r *http.Request) {
		f.userCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// Only the refreshed token is accepted: the first call with "acc1"
		// gets a 401, which makes go-proton-api refresh and retry.
		if r.Header.Get("Authorization") != "Bearer acc2" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"Code":401,"Error":"Invalid access token"}`)
			return
		}
		fmt.Fprint(w, `{"Code":1000,"User":{"ID":"u1","Name":"alice","Email":"alice@example.com"}}`)
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func newTestClient(t *testing.T, f *fakeProton) *Client {
	t.Helper()
	store := session.NewStore(filepath.Join(t.TempDir(), "session.json"))
	c := NewClient(store, "pw", "test@1.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.manager.Close()
	c.manager = goproton.New(
		goproton.WithHostURL(f.srv.URL),
		goproton.WithAppVersion("test@1.0"),
		goproton.WithRetryCount(0),
	)
	// Close the manager directly: c.Close() takes c.mu, which would hang the
	// cleanup if a test left a goroutine deadlocked on that mutex.
	t.Cleanup(c.manager.Close)
	return c
}

// runWithTimeout fails the test if fn does not return within d. This is how
// the deadlock regression is detected: a deadlocked call never returns.
func runWithTimeout(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("call did not return within %s (deadlock?)", d)
	}
}

// Regression test for the auth-handler deadlock: go-proton-api invokes the
// AuthHandler synchronously from inside an API call, while the calling method
// of this package holds c.mu.RLock. The handler must not take c.mu.
func TestAuthHandlerDuringAPICallDoesNotDeadlock(t *testing.T) {
	f := newFakeProton(t)
	c := newTestClient(t, f)

	// Simulate a logged-in client holding a stale access token.
	c.mu.Lock()
	c.client = c.manager.NewClient("uid1", "acc1", "ref1")
	c.username = "alice@example.com"
	c.setAuth(goproton.Auth{UID: "uid1", AccessToken: "acc1", RefreshToken: "ref1"})
	c.installAuthHandler()
	c.mu.Unlock()

	var user *goproton.User
	var err error
	runWithTimeout(t, 5*time.Second, func() {
		// GetUser takes c.mu.RLock, gets a 401, refreshes (→ AuthHandler), retries.
		user, err = c.GetUser(context.Background())
	})
	if err != nil {
		t.Fatalf("GetUser() error: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Errorf("user.Email = %q, want alice@example.com", user.Email)
	}
	if got := f.refreshCalls.Load(); got != 1 {
		t.Errorf("refresh calls = %d, want 1", got)
	}

	// The handler must have recorded and persisted the new tokens.
	if got := c.currentAuth().AccessToken; got != "acc2" {
		t.Errorf("currentAuth().AccessToken = %q, want acc2", got)
	}
	tokens, err := c.store.Load()
	if err != nil || tokens == nil {
		t.Fatalf("store.Load() = %v, %v", tokens, err)
	}
	if tokens.RefreshToken != "ref2" || tokens.Username != "alice@example.com" {
		t.Errorf("persisted tokens = %+v, want ref2 for alice@example.com", tokens)
	}
}

// /health must never block behind an in-flight login or API call.
func TestHealthReadsAreLockFree(t *testing.T) {
	f := newFakeProton(t)
	c := newTestClient(t, f)

	c.mu.Lock() // simulate a long Login/Submit2FA holding the write lock
	defer c.mu.Unlock()

	runWithTimeout(t, time.Second, func() {
		if c.IsAuthenticated() {
			t.Error("IsAuthenticated() = true, want false")
		}
		_ = c.SessionInfo()
	})
}

func TestRestore(t *testing.T) {
	seed := func(t *testing.T, c *Client) {
		t.Helper()
		if err := c.store.Save("alice@example.com", goproton.Auth{UID: "uid1", AccessToken: "acc1", RefreshToken: "ref1"}); err != nil {
			t.Fatalf("seed Save() error: %v", err)
		}
	}

	t.Run("transient refresh failure keeps the saved session", func(t *testing.T) {
		f := newFakeProton(t)
		c := newTestClient(t, f)
		seed(t, c)
		f.refreshStatus.Store(http.StatusServiceUnavailable)

		err := c.Restore(context.Background())
		if err == nil {
			t.Fatal("Restore() expected an error on 503")
		}
		if !c.store.Exists() {
			t.Error("session file was cleared on a transient error; it must be kept")
		}
		if c.IsAuthenticated() {
			t.Error("IsAuthenticated() = true after failed restore")
		}
	})

	t.Run("rejected refresh token clears the saved session", func(t *testing.T) {
		f := newFakeProton(t)
		c := newTestClient(t, f)
		seed(t, c)
		f.refreshStatus.Store(http.StatusUnprocessableEntity)

		if err := c.Restore(context.Background()); err == nil {
			t.Fatal("Restore() expected an error on 422")
		}
		if c.store.Exists() {
			t.Error("session file must be cleared when Proton rejects the refresh token")
		}
		if info := c.SessionInfo(); info.Username != "" {
			t.Errorf("SessionInfo().Username = %q after clear, want empty", info.Username)
		}
	})

	t.Run("no saved session is reported without touching the API", func(t *testing.T) {
		f := newFakeProton(t)
		c := newTestClient(t, f)

		if err := c.Restore(context.Background()); err == nil {
			t.Fatal("Restore() expected an error without a saved session")
		}
		if got := f.refreshCalls.Load(); got != 0 {
			t.Errorf("refresh calls = %d, want 0", got)
		}
	})
}

func TestIsDeauthError(t *testing.T) {
	respErr := func(status int) error {
		rec := httptest.NewRecorder()
		rec.WriteHeader(status)
		return &resty.ResponseError{
			Response: &resty.Response{RawResponse: rec.Result()},
			Err:      errors.New("boom"),
		}
	}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("dial tcp: connection refused"), false},
		{"resty 400", respErr(400), true},
		{"resty 422", respErr(422), true},
		{"resty 401", respErr(401), false},
		{"resty 429", respErr(429), false},
		{"resty 503", respErr(503), false},
		{"api error 422", &goproton.APIError{Status: 422}, true},
		{"api error 500", &goproton.APIError{Status: 500}, false},
		{"wrapped resty 400", fmt.Errorf("refresh: %w", respErr(400)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDeauthError(tt.err); got != tt.want {
				t.Errorf("isDeauthError() = %v, want %v", got, tt.want)
			}
		})
	}
}
