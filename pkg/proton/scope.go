package proton

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	goproton "github.com/ProtonMail/go-proton-api"
	srp "github.com/ProtonMail/go-srp"
)

// unlockScope raises the session to the "locked" scope, required by the
// calendar and keys/salts endpoints (403, Proton code 9101), via an SRP proof
// of the login password to PUT /core/v4/users/unlock. go-proton-api does not
// implement this endpoint, so it goes through a raw HTTP request. The caller
// must hold c.mu (read or write).
func (c *Client) unlockScope(ctx context.Context) error {
	if c.username == "" {
		return fmt.Errorf("username is required for scope unlock")
	}

	info, err := c.manager.AuthInfo(ctx, goproton.AuthInfoReq{Username: c.username})
	if err != nil {
		return fmt.Errorf("fetch auth info: %w", err)
	}

	auth, err := srp.NewAuth(info.Version, c.username, c.password, info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return fmt.Errorf("prepare SRP auth: %w", err)
	}

	proofs, err := auth.GenerateProofs(2048)
	if err != nil {
		return fmt.Errorf("generate SRP proofs: %w", err)
	}

	var out struct {
		ServerProof string
	}
	if err := c.rawPut(ctx, "/core/v4/users/unlock", map[string]any{
		"ClientEphemeral": base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		"ClientProof":     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"SRPSession":      info.SRPSession,
	}, &out); err != nil {
		return fmt.Errorf("PUT /core/v4/users/unlock: %w", err)
	}

	serverProof, err := base64.StdEncoding.DecodeString(out.ServerProof)
	if err != nil {
		return fmt.Errorf("decode server proof: %w", err)
	}
	if !bytes.Equal(serverProof, proofs.ExpectedServerProof) {
		return fmt.Errorf("server proof mismatch on unlock")
	}

	c.logger.Debug("scope unlocked")
	return nil
}

// lockScope drops the "locked" scope again (best effort).
func (c *Client) lockScope(ctx context.Context) {
	if err := c.rawPut(ctx, "/core/v4/users/lock", map[string]any{}, nil); err != nil {
		c.logger.Debug("scope lock failed (best effort)", "error", err)
	}
}

// rawPut performs an authenticated PUT against the Proton API using the
// current session tokens, for endpoints go-proton-api does not expose. All
// current callers (scope unlock/lock, calendar events/sync for create and
// delete) hit PUT endpoints.
func (c *Client) rawPut(ctx context.Context, path string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	auth := c.currentAuth()
	uid := auth.UID
	token := auth.AccessToken
	if token == "" {
		return fmt.Errorf("no access token")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, goproton.DefaultHostURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("x-pm-uid", uid)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("x-pm-appversion", c.appVersion)
	req.Header.Set("Accept", "application/vnd.protonmail.v1+json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("PUT %s: status %d: %s", path, res.StatusCode, string(respBody))
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return err
		}
	}
	return nil
}
