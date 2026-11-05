package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ProtonMail/go-proton-api"
)

// Tokens holds the auth tokens needed to restore a session.
type Tokens struct {
	Username     string    `json:"username"`
	UID          string    `json:"uid"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	CreatedAt    time.Time `json:"created_at"`
	SavedAt      time.Time `json:"saved_at"`
}

// Store persists auth tokens to a JSON file.
// In K8s, the file sits on a PVC so it survives pod restarts.
type Store struct {
	path string
	mu   sync.RWMutex
}

// NewStore creates a store that persists tokens at the given path.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// Save writes the current auth tokens to disk.
func (s *Store) Save(username string, auth proton.Auth) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Preserve the original session creation time across token refreshes.
	var createdAt time.Time
	if existing, err := s.loadLocked(); err == nil && existing != nil {
		createdAt = existing.CreatedAt
	}
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	t := Tokens{
		Username:     username,
		UID:          auth.UID,
		AccessToken:  auth.AccessToken,
		RefreshToken: auth.RefreshToken,
		CreatedAt:    createdAt,
		SavedAt:      time.Now(),
	}

	data, err := json.MarshalIndent(t, "", "  ") // #nosec G117 -- Session restoration requires these tokens; the directory and file are owner-only (0700/0600).
	if err != nil {
		return fmt.Errorf("marshal tokens: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("write session file: %w", err)
	}

	return nil
}

// loadLocked reads the saved tokens from disk. The caller must hold s.mu.
func (s *Store) loadLocked() (*Tokens, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read session file: %w", err)
	}

	var t Tokens
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("unmarshal tokens: %w", err)
	}

	return &t, nil
}

// Load reads saved tokens from disk.
func (s *Store) Load() (*Tokens, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadLocked()
}

// Clear removes the saved session.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove session file: %w", err)
	}

	return nil
}

// Exists checks if a session file exists.
func (s *Store) Exists() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, err := os.Stat(s.path)
	return err == nil
}
