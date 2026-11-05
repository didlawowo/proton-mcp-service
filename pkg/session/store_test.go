package session

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-proton-api"
)

func TestSavePreservesCreatedAt(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "session.json"))

	auth := proton.Auth{UID: "u1", AccessToken: "a1", RefreshToken: "r1"}
	if err := store.Save("user@example.com", auth); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	first, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if first.CreatedAt.IsZero() {
		t.Fatal("CreatedAt should be set on first save")
	}
	if first.Username != "user@example.com" {
		t.Errorf("Username = %q, want user@example.com", first.Username)
	}

	time.Sleep(10 * time.Millisecond)

	// Second save (token refresh) must keep CreatedAt but update SavedAt.
	auth.AccessToken = "a2"
	if err := store.Save("user@example.com", auth); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	second, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("CreatedAt changed across saves: %v -> %v", first.CreatedAt, second.CreatedAt)
	}
	if second.SavedAt.Before(first.SavedAt) {
		t.Errorf("SavedAt should advance, got %v then %v", first.SavedAt, second.SavedAt)
	}
	if second.AccessToken != "a2" {
		t.Errorf("AccessToken = %q, want a2", second.AccessToken)
	}
}

func TestLoadMissingReturnsNil(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "nope.json"))
	tokens, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if tokens != nil {
		t.Errorf("Load() = %+v, want nil", tokens)
	}
}
