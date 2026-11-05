package proton

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/mail"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProtonMail/gluon/rfc822"
	goproton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/go-resty/resty/v2"

	"github.com/didlawowo/proton-mcp-service/pkg/session"
)

// HVRequiredError reports that Proton demands a human-verification (CAPTCHA)
// before the login can complete. The caller must solve the challenge at
// VerifyURL and retry Login with the returned HV token.
type HVRequiredError struct {
	VerifyURL string
	Methods   []string
}

func (e *HVRequiredError) Error() string {
	return fmt.Sprintf("human verification required (methods: %s): %s", strings.Join(e.Methods, ", "), e.VerifyURL)
}

// Client wraps go-proton-api with session management and key unlocking.
type Client struct {
	manager    *goproton.Manager
	client     *goproton.Client
	store      *session.Store
	password   []byte
	username   string
	appVersion string

	// lastAuth caches the most recent Auth so we can re-persist it after
	// flows where the underlying client doesn't fire AddAuthHandler (e.g. 2FA).
	//
	// It is guarded by authMu, NOT by mu: go-proton-api invokes the auth
	// handlers synchronously from inside API calls (Client.authRefresh), i.e.
	// while the caller of this package already holds mu.RLock. Taking mu.Lock
	// there would deadlock the whole service (RWMutex is not reentrant).
	authMu   sync.Mutex
	lastAuth goproton.Auth

	// authenticated mirrors "client != nil && userKR != nil" so that health
	// checks can be answered without touching mu (which may be held for the
	// duration of a network round-trip to Proton).
	authenticated atomic.Bool

	// sessionSnap is an in-memory snapshot of the persisted session, refreshed
	// on every successful Save/Clear so status endpoints never hit the disk.
	sessionSnap atomic.Pointer[SessionInfo]

	userKR  *crypto.KeyRing
	addrKRs map[string]*crypto.KeyRing

	mu     sync.RWMutex
	logger *slog.Logger
}

// NewClient creates a new ProtonMail client.
func NewClient(store *session.Store, password, appVersion string, logger *slog.Logger) *Client {
	m := goproton.New(
		goproton.WithAppVersion(appVersion),
	)

	c := &Client{
		manager:    m,
		store:      store,
		password:   []byte(password),
		appVersion: appVersion,
		logger:     logger,
	}
	// Seed the session snapshot from disk once, so status endpoints can report
	// the persisted session (username, timestamps) without re-reading the file.
	c.reloadSessionSnapshot()
	return c
}

// setAuth records the most recent Auth. Safe to call from go-proton-api's
// auth handlers (which run while mu may be held by the caller).
func (c *Client) setAuth(auth goproton.Auth) {
	c.authMu.Lock()
	c.lastAuth = auth
	c.authMu.Unlock()
}

// currentAuth returns a copy of the most recent Auth.
func (c *Client) currentAuth() goproton.Auth {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	return c.lastAuth
}

// persistAuth saves the tokens to the store and refreshes the in-memory
// session snapshot. Failures are logged, never fatal: the in-memory session
// stays valid even if the disk write fails.
func (c *Client) persistAuth(username string, auth goproton.Auth, what string) {
	if err := c.store.Save(username, auth); err != nil {
		c.logger.Warn("failed to persist auth tokens", "stage", what, "error", err)
	}
	c.reloadSessionSnapshot()
}

// reloadSessionSnapshot reads the persisted session once and caches it for
// SessionInfo(). It deliberately does not take mu.
func (c *Client) reloadSessionSnapshot() {
	info := &SessionInfo{}
	if tokens, err := c.store.Load(); err == nil && tokens != nil {
		info.Username = tokens.Username
		info.CreatedAt = tokens.CreatedAt
		info.SavedAt = tokens.SavedAt
	}
	c.sessionSnap.Store(info)
}

// clearSession removes the persisted session and resets the snapshot.
func (c *Client) clearSession() error {
	err := c.store.Clear()
	c.reloadSessionSnapshot()
	return err
}

// isDeauthError reports whether a token refresh failed because the refresh
// token is definitively invalid (Proton answers 400/422 in that case, which
// is also what go-proton-api treats as a de-auth). Network errors, 5xx and
// rate limiting return false so the caller keeps the persisted session.
func isDeauthError(err error) bool {
	var respErr *resty.ResponseError
	if errors.As(err, &respErr) && respErr.Response != nil {
		switch respErr.Response.StatusCode() {
		case 400, 422:
			return true
		}
	}
	var apiErr *goproton.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case 400, 422:
			return true
		}
	}
	return false
}

// Login authenticates with username/password. Returns true if 2FA is required.
// If Proton demands a CAPTCHA, an *HVRequiredError is returned with the
// verification URL to solve; the login is retried by passing the resulting
// token as hvToken.
func (c *Client) Login(ctx context.Context, username, hvToken string) (needs2FA bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var hv *goproton.APIHVDetails
	if hvToken != "" {
		hv = &goproton.APIHVDetails{Methods: []string{"captcha"}, Token: hvToken}
	}

	client, auth, err := c.manager.NewClientWithLoginWithHVToken(ctx, username, c.password, hv)
	if err != nil {
		var apiErr *goproton.APIError
		if errors.As(err, &apiErr) && apiErr.IsHVError() {
			return false, hvRequiredError(apiErr)
		}
		return false, fmt.Errorf("login: %w", err)
	}

	// A fresh login invalidates any previously unlocked keyrings.
	c.authenticated.Store(false)
	c.userKR = nil
	c.addrKRs = nil

	c.client = client
	c.username = username
	c.setAuth(auth)
	c.installAuthHandler()
	c.logger.Info("login scope", "scope", auth.Scope)

	c.persistAuth(c.username, auth, "login")

	if auth.TwoFA.Enabled&goproton.HasTOTP != 0 {
		return true, nil
	}

	if err := c.unlockKeys(ctx); err != nil {
		return false, fmt.Errorf("unlock keys: %w", err)
	}

	c.logger.Info("login successful", "user", username)
	return false, nil
}

// hvRequiredError builds an *HVRequiredError from a Proton human-verification
// API error, deriving the verification URL from the error details when
// possible.
func hvRequiredError(apiErr *goproton.APIError) *HVRequiredError {
	e := &HVRequiredError{}

	var details struct {
		HumanVerificationMethods []string `json:"HumanVerificationMethods"`
		HumanVerificationToken   string   `json:"HumanVerificationToken"`
		WebURL                   string   `json:"WebURL"`
	}
	if err := json.Unmarshal(apiErr.Details, &details); err == nil {
		e.Methods = details.HumanVerificationMethods
		if details.WebURL != "" {
			e.VerifyURL = details.WebURL
		} else if details.HumanVerificationToken != "" {
			e.VerifyURL = "https://account.proton.me/verify?methods=captcha&token=" + url.QueryEscape(details.HumanVerificationToken)
		}
	}

	if e.VerifyURL == "" {
		e.VerifyURL = "https://account.proton.me/verify?methods=captcha"
	}
	if len(e.Methods) == 0 {
		e.Methods = []string{"captcha"}
	}
	return e
}

// Submit2FA completes the 2FA step after Login.
func (c *Client) Submit2FA(ctx context.Context, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client == nil {
		return fmt.Errorf("must call Login first")
	}

	if err := c.client.Auth2FA(ctx, goproton.Auth2FAReq{TwoFactorCode: code}); err != nil {
		return fmt.Errorf("2FA: %w", err)
	}

	// The /auth/v4/2fa response carries only the upgraded scope ("full"),
	// no new tokens. The proper post-2FA access token is issued on the next
	// refresh, so rebuild the client via a refresh (also rotates the tokens
	// persisted on the PVC).
	prev := c.currentAuth()
	if newClient, auth, rerr := c.manager.NewClientWithRefresh(ctx, prev.UID, prev.RefreshToken); rerr == nil {
		c.client.Close()
		c.client = newClient
		c.setAuth(auth)
		c.installAuthHandler()
		c.logger.Info("refreshed after 2FA", "scope", auth.Scope)
	} else {
		c.logger.Warn("refresh after 2FA failed, keeping pre-2FA tokens", "error", rerr)
	}

	c.persistAuth(c.username, c.currentAuth(), "2fa")

	if err := c.unlockKeys(ctx); err != nil {
		return fmt.Errorf("unlock keys after 2FA: %w", err)
	}

	c.logger.Info("2FA completed, keys unlocked")
	return nil
}

// Restore tries to resume a previous session from saved tokens.
func (c *Client) Restore(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	tokens, err := c.store.Load()
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	if tokens == nil {
		return fmt.Errorf("no saved session")
	}

	client, auth, err := c.manager.NewClientWithRefresh(ctx, tokens.UID, tokens.RefreshToken)
	if err != nil {
		// Only drop the persisted session when Proton definitively rejected
		// the refresh token. A transient failure (network, 5xx, 429) must keep
		// the file so the next start can retry without a manual 2FA login.
		if isDeauthError(err) {
			c.logger.Warn("saved session rejected by Proton, clearing it", "error", err)
			_ = c.clearSession()
		}
		return fmt.Errorf("refresh session: %w", err)
	}

	c.client = client
	c.username = tokens.Username
	c.setAuth(auth)
	c.installAuthHandler()

	c.persistAuth(c.username, auth, "restore")

	// A restored session's refreshed token lacks the "locked" scope needed
	// by keys/salts — raise it with an SRP proof of the login password.
	if err := c.unlockScope(ctx); err != nil {
		c.logger.Warn("scope unlock on restore failed, keys may not unlock", "error", err)
	}

	if err := c.unlockKeys(ctx); err != nil {
		return fmt.Errorf("unlock keys: %w", err)
	}

	c.logger.Info("session restored from saved tokens")
	return nil
}

// IsAuthenticated returns true if the client has an active session with
// unlocked keys. It is lock-free so that health probes are never blocked by
// an in-flight login or API call holding mu.
func (c *Client) IsAuthenticated() bool {
	return c.authenticated.Load()
}

// Logout closes the session and clears saved tokens.
func (c *Client) Logout(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.authenticated.Store(false)

	if c.client != nil {
		_ = c.client.AuthDelete(ctx)
		c.client.Close()
		c.client = nil
	}

	c.userKR = nil
	c.addrKRs = nil
	c.setAuth(goproton.Auth{})

	return c.clearSession()
}

// Close cleans up resources without revoking the session.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.authenticated.Store(false)

	if c.client != nil {
		c.client.Close()
		c.client = nil
	}

	c.manager.Close()
}

// ListMessages returns message metadata matching the given filter.
func (c *Client) ListMessages(ctx context.Context, filter goproton.MessageFilter) ([]goproton.MessageMetadata, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	return c.client.GetMessageMetadata(ctx, filter)
}

// GetMessage returns a single message with its decrypted body.
func (c *Client) GetMessage(ctx context.Context, messageID string) (*DecryptedMessage, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	msg, err := c.client.GetMessage(ctx, messageID)
	if err != nil {
		return nil, fmt.Errorf("get message: %w", err)
	}

	kr := c.addrKRs[msg.AddressID]
	if kr == nil {
		return nil, fmt.Errorf("no keyring for address %s", msg.AddressID)
	}

	body, err := msg.Decrypt(kr)
	if err != nil {
		return nil, fmt.Errorf("decrypt message: %w", err)
	}

	return &DecryptedMessage{
		MessageMetadata: msg.MessageMetadata,
		Body:            string(body),
		MIMEType:        string(msg.MIMEType),
		Attachments:     msg.Attachments,
	}, nil
}

// ListLabels returns the account's labels, folders and system labels.
// Type is one of goproton.LabelTypeLabel (1), LabelTypeContactGroup (2),
// LabelTypeFolder (3), LabelTypeSystem (4).
func (c *Client) ListLabels(ctx context.Context) ([]goproton.Label, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	return c.client.GetLabels(ctx,
		goproton.LabelTypeLabel,
		goproton.LabelTypeFolder,
		goproton.LabelTypeSystem,
	)
}

// AddressInfo describes one of the authenticated account's addresses. A single
// Proton account routinely owns several addresses (primary + aliases + custom
// domains); this is what lets callers see which address received a message and
// pick which one to send from.
type AddressInfo struct {
	ID          string
	Email       string
	Status      string // "enabled" | "disabled" | "deleting" | "unknown"
	Type        string // "original" | "alias" | "custom" | "premium" | "external" | "unknown"
	Send        bool
	Receive     bool
	Order       int
	DisplayName string
}

// ListAddresses returns all addresses of the authenticated account, in Proton's
// own order (primary first). It maps AddressID <-> email so callers can filter
// reads by address and choose a sender address by email rather than opaque ID.
func (c *Client) ListAddresses(ctx context.Context) ([]AddressInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	addrs, err := c.client.GetAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("get addresses: %w", err)
	}

	out := make([]AddressInfo, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, AddressInfo{
			ID:          a.ID,
			Email:       a.Email,
			Status:      addressStatusString(a.Status),
			Type:        addressTypeString(a.Type),
			Send:        bool(a.Send),
			Receive:     bool(a.Receive),
			Order:       a.Order,
			DisplayName: a.DisplayName,
		})
	}
	return out, nil
}

// ErrAddressNotFound is returned when an email does not match any address of the
// account. Callers should map it to a client error (HTTP 400), not a 500.
var ErrAddressNotFound = errors.New("address not found among account addresses")

// ResolveAddressID maps an account email to its AddressID (case-insensitive),
// so read filters can be expressed as an email address instead of an opaque ID.
func (c *Client) ResolveAddressID(ctx context.Context, email string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return "", fmt.Errorf("not authenticated")
	}

	addrs, err := c.client.GetAddresses(ctx)
	if err != nil {
		return "", fmt.Errorf("get addresses: %w", err)
	}

	for _, a := range addrs {
		if strings.EqualFold(a.Email, email) {
			return a.ID, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrAddressNotFound, email)
}

func addressStatusString(s goproton.AddressStatus) string {
	switch s {
	case goproton.AddressStatusDisabled:
		return "disabled"
	case goproton.AddressStatusEnabled:
		return "enabled"
	case goproton.AddressStatusDeleting:
		return "deleting"
	default:
		return "unknown"
	}
}

func addressTypeString(t goproton.AddressType) string {
	switch t {
	case goproton.AddressTypeOriginal:
		return "original"
	case goproton.AddressTypeAlias:
		return "alias"
	case goproton.AddressTypeCustom:
		return "custom"
	case goproton.AddressTypePremium:
		return "premium"
	case goproton.AddressTypeExternal:
		return "external"
	default:
		return "unknown"
	}
}

// DownloadAttachment downloads and decrypts an attachment.
func (c *Client) DownloadAttachment(ctx context.Context, messageID, attachmentID string) ([]byte, string, string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return nil, "", "", fmt.Errorf("not authenticated")
	}

	msg, err := c.client.GetMessage(ctx, messageID)
	if err != nil {
		return nil, "", "", fmt.Errorf("get message for attachment: %w", err)
	}

	var att *goproton.Attachment
	for i := range msg.Attachments {
		if msg.Attachments[i].ID == attachmentID {
			att = &msg.Attachments[i]
			break
		}
	}
	if att == nil {
		return nil, "", "", fmt.Errorf("attachment %s not found in message %s", attachmentID, messageID)
	}

	kr := c.addrKRs[msg.AddressID]
	if kr == nil {
		return nil, "", "", fmt.Errorf("no keyring for address %s", msg.AddressID)
	}

	encData, err := c.client.GetAttachment(ctx, attachmentID)
	if err != nil {
		return nil, "", "", fmt.Errorf("download attachment: %w", err)
	}

	keyPackets, err := base64.StdEncoding.DecodeString(att.KeyPackets)
	if err != nil {
		return nil, "", "", fmt.Errorf("decode key packets: %w", err)
	}

	splitMsg := crypto.NewPGPSplitMessage(keyPackets, encData)
	plainMsg, err := kr.DecryptAttachment(splitMsg)
	if err != nil {
		return nil, "", "", fmt.Errorf("decrypt attachment: %w", err)
	}

	return plainMsg.GetBinary(), att.Name, string(att.MIMEType), nil
}

// Attachment describes a file to attach to an outgoing message.
type Attachment struct {
	Filename string
	MIMEType string
	Content  []byte
}

// SendAction décrit le lien de threading avec un message parent (reply/forward).
type SendAction string

const (
	// SendActionReply répond au parent (destinataires = expéditeur du parent).
	SendActionReply SendAction = "reply"
	// SendActionReplyAll répond à tous (expéditeur + To + CC du parent).
	SendActionReplyAll SendAction = "reply_all"
	// SendActionForward transfère le parent à de nouveaux destinataires.
	SendActionForward SendAction = "forward"
)

// SendRequest describes an outgoing email. Body is sent as text/plain unless
// HTML is provided, in which case the HTML body is sent (text/html).
type SendRequest struct {
	To          []string
	CC          []string
	Subject     string
	Body        string
	HTML        string
	Attachments []Attachment

	// From est l'adresse d'envoi optionnelle (doit être une adresse active du
	// compte). Vide = adresse primaire (première adresse active).
	From string

	// ParentID est l'ID interne Proton du message auquel répondre/que
	// transférer (tel qu'exposé par GetMessage/ListMessages). Vide = nouveau
	// message sans lien de fil.
	ParentID string
	// Action lie le message au parent : reply | reply_all | forward
	// (ignorée si ParentID est vide).
	Action SendAction
}

// sendMIMEType returns the MIME type and body to use for an outgoing message:
// HTML when provided, otherwise plain text. Proton only accepts text/html or
// text/plain (multipart/alternative is rejected by the API).
func sendMIMEType(req SendRequest) (rfc822.MIMEType, string) {
	if req.HTML != "" {
		return rfc822.TextHTML, req.HTML
	}
	return rfc822.TextPlain, req.Body
}

// attachmentMIMEType resolves the MIME type of an attachment, inferring it
// from the filename extension when not explicitly provided.
func attachmentMIMEType(filename, mimeType string) string {
	if mimeType != "" {
		return mimeType
	}
	if ext := mime.TypeByExtension(filepath.Ext(filename)); ext != "" {
		return ext
	}
	return "application/octet-stream"
}

// SendMessage composes a draft and sends it.
// Recipients are resolved individually: internal Proton recipients are
// end-to-end encrypted with their public key, external recipients receive a
// cleartext package (Proton's standard behaviour when no key is available).
func (c *Client) SendMessage(ctx context.Context, req SendRequest) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil || c.userKR == nil {
		return "", fmt.Errorf("not authenticated")
	}
	if len(req.To) == 0 {
		return "", fmt.Errorf("at least one recipient is required")
	}

	// Adresse d'envoi : `from` si fourni, sinon la première adresse active
	// (primaire).
	fromEmail, addrKR, err := c.resolveSenderAddress(ctx, req.From)
	if err != nil {
		return "", err
	}

	toList := make([]*mail.Address, 0, len(req.To))
	for _, r := range req.To {
		toList = append(toList, &mail.Address{Address: r})
	}
	ccList := make([]*mail.Address, 0, len(req.CC))
	for _, r := range req.CC {
		ccList = append(ccList, &mail.Address{Address: r})
	}

	mimeType, body := sendMIMEType(req)

	draftReq := goproton.CreateDraftReq{
		Message: goproton.DraftTemplate{
			Subject:  req.Subject,
			Sender:   &mail.Address{Address: fromEmail},
			ToList:   toList,
			CCList:   ccList,
			Body:     body,
			MIMEType: mimeType,
		},
		ParentID: req.ParentID,
	}
	// L'action de threading n'est appliquée que si un parent est fourni :
	// sinon on garde la valeur zéro (nouveau message).
	if req.ParentID != "" {
		switch req.Action {
		case SendActionReply:
			draftReq.Action = goproton.ReplyAction
		case SendActionReplyAll:
			draftReq.Action = goproton.ReplyAllAction
		case SendActionForward:
			draftReq.Action = goproton.ForwardAction
		}
	}

	draft, err := c.client.CreateDraft(ctx, addrKR, draftReq)
	if err != nil {
		return "", fmt.Errorf("create draft: %w", err)
	}

	// Upload the attachments on the draft and collect their session keys so the
	// send packages can reference them (encrypted per-recipient).
	attKeys := make(map[string]*crypto.SessionKey)
	for _, att := range req.Attachments {
		up, err := c.client.UploadAttachment(ctx, addrKR, goproton.CreateAttachmentReq{
			MessageID:   draft.ID,
			Filename:    att.Filename,
			MIMEType:    rfc822.MIMEType(attachmentMIMEType(att.Filename, att.MIMEType)),
			Disposition: goproton.AttachmentDisposition,
			Body:        att.Content,
		})
		if err != nil {
			return "", fmt.Errorf("upload attachment %s: %w", att.Filename, err)
		}

		keyPackets, err := base64.StdEncoding.DecodeString(up.KeyPackets)
		if err != nil {
			return "", fmt.Errorf("decode key packets for %s: %w", att.Filename, err)
		}

		attKey, err := addrKR.DecryptSessionKey(keyPackets)
		if err != nil {
			return "", fmt.Errorf("decrypt session key for %s: %w", att.Filename, err)
		}

		attKeys[up.ID] = attKey
	}

	prefs := map[string]goproton.SendPreferences{}
	for _, r := range append(append([]string{}, req.To...), req.CC...) {
		keys, rtype, err := c.client.GetPublicKeys(ctx, r)
		if err == nil && rtype == goproton.RecipientTypeInternal && len(keys) > 0 {
			kr, kerr := keys.GetKeyRing()
			if kerr == nil {
				prefs[r] = goproton.SendPreferences{
					Encrypt:          true,
					PubKey:           kr,
					SignatureType:    goproton.DetachedSignature,
					EncryptionScheme: goproton.InternalScheme,
					MIMEType:         mimeType,
				}
				continue
			}
		}
		// Externe / sans clé : envoi en clair.
		prefs[r] = goproton.SendPreferences{
			Encrypt:          false,
			SignatureType:    goproton.NoSignature,
			EncryptionScheme: goproton.ClearScheme,
			MIMEType:         mimeType,
		}
	}

	var sreq goproton.SendDraftReq
	if err := sreq.AddTextPackage(
		addrKR, body, mimeType, prefs, attKeys,
	); err != nil {
		return "", fmt.Errorf("build send package: %w", err)
	}

	sent, err := c.client.SendDraft(ctx, draft.ID, sreq)
	if err != nil {
		return "", fmt.Errorf("send draft: %w", err)
	}

	c.logger.Info("message sent", "id", sent.ID, "to", req.To)
	return sent.ID, nil
}

// --- Calendar (lecture) ---

// CalendarInfo is a calendar as returned to API clients.
type CalendarInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	Display     bool   `json:"display"`
	Type        int    `json:"type"`
}

// CalendarEventInfo is a calendar event with its decrypted VEVENT payload.
type CalendarEventInfo struct {
	ID            string `json:"id"`
	UID           string `json:"uid"`
	CalendarID    string `json:"calendar_id"`
	StartTime     int64  `json:"start_time"`
	StartTimezone string `json:"start_timezone"`
	EndTime       int64  `json:"end_time"`
	EndTimezone   string `json:"end_timezone"`
	FullDay       bool   `json:"full_day"`
	Author        string `json:"author"`
	VEVENT        string `json:"vevent"`
}

// ListCalendars returns the calendars accessible to the user.
func (c *Client) ListCalendars(ctx context.Context) ([]CalendarInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	cals, err := c.client.GetCalendars(ctx)
	if err != nil {
		return nil, fmt.Errorf("get calendars: %w", err)
	}

	result := make([]CalendarInfo, 0, len(cals))
	for _, cal := range cals {
		result = append(result, CalendarInfo{
			ID:          cal.ID,
			Name:        cal.Name,
			Description: cal.Description,
			Color:       cal.Color,
			Display:     bool(cal.Display),
			Type:        int(cal.Type),
		})
	}

	return result, nil
}

// ListCalendarEvents returns the events of a calendar with their decrypted
// VEVENT payloads (Proton calendars are end-to-end encrypted), sorted by start
// time. When from or to is non-zero (unix seconds, 0 = unbounded), only events
// overlapping that window are returned, including events already in progress
// and recurring series that began earlier. timezone is the IANA zone Proton
// uses to place full-day events in the window; empty means UTC.
func (c *Client) ListCalendarEvents(ctx context.Context, calendarID string, from, to int64, timezone string) ([]CalendarEventInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return nil, fmt.Errorf("not authenticated")
	}
	if calendarID == "" {
		return nil, fmt.Errorf("calendar ID is required")
	}

	calKR, addrKR, _, err := c.calendarKeyRing(ctx, calendarID)
	if err != nil {
		return nil, err
	}

	// Proton rejects the library's default page size (150) on the calendar
	// events endpoint (max 100), so paginate manually. When a time range is
	// requested, use Proton's four official query types instead of comparing
	// StartTime locally: the "before window" types preserve recurring events
	// whose series began before from but have an occurrence in the window.
	const pageSize = 100
	var events []goproton.CalendarEvent
	seen := make(map[string]struct{})
	for _, filter := range calendarEventFilters(from, to, timezone) {
		for page := 0; ; page++ {
			evs, err := c.client.GetCalendarEvents(ctx, calendarID, page, pageSize, filter)
			if err != nil {
				return nil, fmt.Errorf("get calendar events: %w", err)
			}
			for _, ev := range evs {
				if _, duplicate := seen[ev.ID]; !duplicate {
					events = append(events, ev)
					seen[ev.ID] = struct{}{}
				}
			}
			if len(evs) < pageSize {
				break
			}
		}
	}

	result := make([]CalendarEventInfo, 0, len(events))
	for _, ev := range events {
		calKP, err := base64.StdEncoding.DecodeString(ev.CalendarKeyPacket)
		if err != nil {
			c.logger.Warn("skip event: invalid calendar key packet", "event", ev.ID, "error", err)
			continue
		}
		sharedKP, _ := base64.StdEncoding.DecodeString(ev.SharedKeyPacket)

		// Proton splits an event across several encrypted cards: the shared
		// card carries SUMMARY/DESCRIPTION/LOCATION, the calendar/personal
		// cards carry the rest. Shared cards are encrypted with the shared
		// key packet; calendar/personal cards with the calendar key packet.
		fragments := make([]string, 0, 4)
		partSets := []struct {
			parts []goproton.CalendarEventPart
			kp    []byte
		}{
			{ev.SharedEvents, sharedKP},
			{ev.CalendarEvents, calKP},
			{ev.AttendeesEvents, sharedKP},
			{ev.PersonalEvents, calKP},
		}
		for _, ps := range partSets {
			for i := range ps.parts {
				part := &ps.parts[i]
				if err := decryptEventPart(part, calKR, addrKR, ps.kp); err == nil && part.Data != "" {
					fragments = append(fragments, part.Data)
				} else if err != nil {
					c.logger.Debug("calendar part decrypt failed", "event", ev.ID, "type", part.Type, "error", err)
				}
			}
		}

		result = append(result, CalendarEventInfo{
			ID:            ev.ID,
			UID:           ev.UID,
			CalendarID:    ev.CalendarID,
			StartTime:     ev.StartTime,
			StartTimezone: ev.StartTimezone,
			EndTime:       ev.EndTime,
			EndTimezone:   ev.EndTimezone,
			FullDay:       bool(ev.FullDay),
			Author:        ev.Author,
			VEVENT:        mergeVEVENT(fragments),
		})
	}

	sortByStartTime(result)

	return result, nil
}

// defaultCalendarQueryEnd is the upper bound sent to Proton when a query has a
// start but no end: Proton requires both Start and End on a filtered query.
const defaultCalendarQueryEnd int64 = 1924991999 // 2030-12-31T23:59:59Z

// calendarEventFilters builds Proton Calendar's time-window queries. Types 1
// and 3 explicitly include events that began before the window, which covers
// recurring series and multi-day events. A missing lower bound starts at 0 and
// a missing upper bound ends at defaultCalendarQueryEnd. Proton places full-day
// events in the window using timezone, which defaults to UTC when empty.
func calendarEventFilters(from, to int64, timezone string) []url.Values {
	if from == 0 && to == 0 {
		return []url.Values{nil}
	}
	if from < 0 {
		from = 0
	}
	if to <= 0 {
		to = defaultCalendarQueryEnd
	}
	if timezone == "" {
		timezone = "UTC"
	}

	filters := make([]url.Values, 0, 4)
	for _, queryType := range []string{"0", "1", "2", "3"} {
		filters = append(filters, url.Values{
			"Start":    {strconv.FormatInt(from, 10)},
			"End":      {strconv.FormatInt(to, 10)},
			"Timezone": {timezone},
			"Type":     {queryType},
		})
	}
	return filters
}

// sortByStartTime sorts calendar events ascending by start time, in place.
func sortByStartTime(events []CalendarEventInfo) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].StartTime < events[j].StartTime
	})
}

// calendarKeyRing unlocks the keyring of the given calendar and returns it
// along with the address keyring of the matching member (needed for signature
// verification of event parts) and the member ID (needed to author new events).
// The member is resolved against any of the account's enabled addresses (not
// just the primary): the calendar may be owned by another address of the account.
func (c *Client) calendarKeyRing(ctx context.Context, calendarID string) (*crypto.KeyRing, *crypto.KeyRing, string, error) {
	// Calendar keys/passphrase/members require the elevated "locked" scope
	// (403, Proton code 9101). Raise it, then drop it once we are done.
	if err := c.unlockScope(ctx); err != nil {
		c.logger.Warn("calendar scope unlock failed, continuing (endpoints may 403)", "error", err)
	}
	defer c.lockScope(ctx)

	keys, err := c.client.GetCalendarKeys(ctx, calendarID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("get calendar keys: %w", err)
	}

	pass, err := c.client.GetCalendarPassphrase(ctx, calendarID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("get calendar passphrase: %w", err)
	}

	members, err := c.client.GetCalendarMembers(ctx, calendarID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("get calendar members: %w", err)
	}

	addrs, err := c.client.GetAddresses(ctx)
	if err != nil {
		return nil, nil, "", fmt.Errorf("get addresses: %w", err)
	}

	var memberID string
	var addrKR *crypto.KeyRing
	for _, m := range members {
		for _, a := range addrs {
			if a.Status != goproton.AddressStatusEnabled {
				continue
			}
			kr := c.addrKRs[a.ID]
			if kr == nil || !strings.EqualFold(m.Email, a.Email) {
				continue
			}
			memberID = m.ID
			addrKR = kr
			break
		}
		if memberID != "" {
			break
		}
	}
	if memberID == "" || addrKR == nil {
		return nil, nil, "", fmt.Errorf("no calendar member matching any account address")
	}

	passBytes, err := pass.Decrypt(memberID, addrKR)
	if err != nil {
		return nil, nil, "", fmt.Errorf("decrypt calendar passphrase: %w", err)
	}

	calKR, err := keys.Unlock(passBytes)
	if err != nil {
		return nil, nil, "", fmt.Errorf("unlock calendar keys: %w", err)
	}

	return calKR, addrKR, memberID, nil
}

// ErrSenderAddressNotFound is returned when a requested sender address is not
// among the account's enabled addresses. Callers should map it to a client
// error (HTTP 400), not a server error.
var ErrSenderAddressNotFound = errors.New("sender address not found among enabled addresses")

// resolveSenderAddress returns the email and keyring to use for sending.
// If preferred is empty, it falls back to the first enabled (primary)
// address of the authenticated user.
func (c *Client) resolveSenderAddress(ctx context.Context, preferred string) (string, *crypto.KeyRing, error) {
	addrs, err := c.client.GetAddresses(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("get addresses: %w", err)
	}
	return pickSenderAddress(addrs, c.addrKRs, preferred)
}

// pickSenderAddress selects the email/keyring to send from. When preferred is
// set, it must match an enabled address (case-insensitive) with a usable
// keyring; otherwise the first enabled address with a usable keyring wins.
func pickSenderAddress(addrs []goproton.Address, addrKRs map[string]*crypto.KeyRing, preferred string) (string, *crypto.KeyRing, error) {
	for _, a := range addrs {
		if a.Status != goproton.AddressStatusEnabled {
			continue
		}
		kr := addrKRs[a.ID]
		if kr == nil {
			continue
		}
		if preferred == "" || strings.EqualFold(a.Email, preferred) {
			return a.Email, kr, nil
		}
	}

	if preferred != "" {
		return "", nil, fmt.Errorf("%w: %q", ErrSenderAddressNotFound, preferred)
	}
	return "", nil, fmt.Errorf("no usable sender address/keyring")
}

// mergeVEVENT merges several decrypted VEVENT fragments (shared + calendar +
// personal cards) into a single self-contained VEVENT, keeping one copy of
// each property line (properties repeat across cards).
func mergeVEVENT(fragments []string) string {
	seen := make(map[string]bool)
	var lines []string

	for _, frag := range fragments {
		inVevent := false
		for _, raw := range strings.Split(frag, "\n") {
			line := strings.TrimSpace(raw) // handles \r\n and \n line endings
			upper := strings.ToUpper(line)
			switch {
			case upper == "BEGIN:VEVENT":
				inVevent = true
				continue
			case upper == "END:VEVENT":
				inVevent = false
				continue
			case strings.HasPrefix(upper, "BEGIN:VCALENDAR") || strings.HasPrefix(upper, "END:VCALENDAR"):
				continue
			case line == "":
				continue
			}
			if !inVevent {
				continue
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//proton-service//mergeVEVENT//EN\r\nBEGIN:VEVENT\r\n")
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\r\n")
	}
	b.WriteString("END:VEVENT\r\nEND:VCALENDAR\r\n")
	return b.String()
}

// decryptEventPart decrypts and verifies a single calendar event part in
// place. It mirrors go-proton-api's CalendarEventPart.Decode, whose value
// receiver discards the decrypted payload.
func decryptEventPart(
	part *goproton.CalendarEventPart,
	calKR *crypto.KeyRing,
	addrKR *crypto.KeyRing,
	kp []byte,
) error {
	if part.Type&goproton.CalendarEventTypeEncrypted != 0 {
		var enc *crypto.PGPMessage

		if kp != nil {
			raw, err := base64.StdEncoding.DecodeString(part.Data)
			if err != nil {
				return fmt.Errorf("decode event data: %w", err)
			}
			enc = crypto.NewPGPSplitMessage(kp, raw).GetPGPMessage()
		} else {
			var err error
			if enc, err = crypto.NewPGPMessageFromArmored(part.Data); err != nil {
				return fmt.Errorf("parse armored event data: %w", err)
			}
		}

		dec, err := calKR.Decrypt(enc, nil, crypto.GetUnixTime())
		if err != nil {
			return fmt.Errorf("decrypt event: %w", err)
		}
		part.Data = dec.GetString()
	}

	if part.Type&goproton.CalendarEventTypeSigned != 0 {
		// Best-effort: the shared events are signed by keys we may not hold
		// (calendar key / creator key). The data is already decrypted with the
		// calendar key — don't reject the part just because we can't verify.
		if sig, err := crypto.NewPGPSignatureFromArmored(part.Signature); err == nil {
			plain := crypto.NewPlainMessageFromString(part.Data)
			_ = addrKR.VerifyDetached(plain, sig, crypto.GetUnixTime())
			if calKR != nil {
				_ = calKR.VerifyDetached(plain, sig, crypto.GetUnixTime())
			}
		}
	}

	return nil
}

// SessionInfo is a snapshot of the persisted session for status endpoints.
type SessionInfo struct {
	Authenticated bool      `json:"authenticated"`
	Username      string    `json:"username,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	SavedAt       time.Time `json:"saved_at,omitempty"`
}

// SessionInfo returns a snapshot of the current session (persisted state).
// It is lock-free and does not touch the disk: the snapshot is refreshed on
// every token save/clear, which keeps /health cheap and independent of the
// PVC latency and of any in-flight Proton call.
func (c *Client) SessionInfo() SessionInfo {
	info := SessionInfo{Authenticated: c.authenticated.Load()}
	if snap := c.sessionSnap.Load(); snap != nil {
		info.Username = snap.Username
		info.CreatedAt = snap.CreatedAt
		info.SavedAt = snap.SavedAt
	}
	return info
}

// GetUser returns info about the authenticated user.
func (c *Client) GetUser(ctx context.Context) (*goproton.User, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	user, err := c.client.GetUser(ctx)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// unlockKeys fetches user/address info and unlocks the PGP keyrings.
func (c *Client) unlockKeys(ctx context.Context) error {
	user, err := c.client.GetUser(ctx)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	addrs, err := c.client.GetAddresses(ctx)
	if err != nil {
		return fmt.Errorf("get addresses: %w", err)
	}

	salts, err := c.client.GetSalts(ctx)
	if err != nil {
		return fmt.Errorf("get salts: %w", err)
	}

	saltedPass, err := salts.SaltForKey(c.password, user.Keys.Primary().ID)
	if err != nil {
		return fmt.Errorf("salt password: %w", err)
	}

	userKR, addrKRs, err := goproton.Unlock(user, addrs, saltedPass, nil)
	if err != nil {
		return fmt.Errorf("unlock keys: %w", err)
	}

	c.userKR = userKR
	c.addrKRs = addrKRs
	c.authenticated.Store(true)

	c.logger.Info("keys unlocked", "addresses", len(addrKRs))
	return nil
}

// installAuthHandler watches for token refreshes and persists them.
//
// IMPORTANT: go-proton-api calls these handlers synchronously from inside
// Client.authRefresh, i.e. in the middle of an API call made by a method of
// this package that already holds mu (usually RLock). The handlers must
// therefore never acquire mu — doing so deadlocks the whole service (all
// readers, including /health, block behind the pending writer).
func (c *Client) installAuthHandler() {
	// username is only written under mu.Lock by Login/Restore, before the
	// handler can fire; capture it here to avoid reading c.username later.
	username := c.username

	c.client.AddAuthHandler(func(auth goproton.Auth) {
		c.setAuth(auth)
		c.persistAuth(username, auth, "refresh")
		c.logger.Debug("auth tokens refreshed and persisted")
	})

	c.client.AddDeauthHandler(func() {
		c.logger.Warn("session revoked by server, re-login required")
		c.authenticated.Store(false)
		_ = c.clearSession()
	})
}

// DecryptedMessage is a message with its body already decrypted.
type DecryptedMessage struct {
	goproton.MessageMetadata
	Body        string                `json:"body"`
	MIMEType    string                `json:"mime_type"`
	Attachments []goproton.Attachment `json:"attachments"`
}
