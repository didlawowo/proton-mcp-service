// Package api exposes the proton-service HTTP API.
//
// @title Proton Service API
// @version 1.0.0
// @description Micro-service Proton Mail + Calendar (Go + MCP). Envoi d'emails, threading (reply/forward), calendrier chiffré.
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-Key
// @Security ApiKeyAuth
// @securityDefinitions.apikey WriteKey
// @in header
// @name X-Write-Key
package api

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/mail"
	"strconv"
	"time"

	goproton "github.com/ProtonMail/go-proton-api"

	pclient "github.com/didlawowo/proton-mcp-service/pkg/proton"
)

// WriteGate configures how mutating operations are authorized.
type WriteGate struct {
	// Secret is the value expected in the X-Write-Key header.
	Secret string
	// AllowWithoutKey authorizes writes without any X-Write-Key header. It is
	// an explicit opt-out: an empty Secret alone still disables writes.
	AllowWithoutKey bool
}

// Handlers holds the HTTP handlers and their dependencies.
type Handlers struct {
	client    *pclient.Client
	logger    *slog.Logger
	writeGate WriteGate
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(client *pclient.Client, writeGate WriteGate, logger *slog.Logger) *Handlers {
	return &Handlers{client: client, logger: logger, writeGate: writeGate}
}

// requireWriteKey gates mutating operations. Writes pass without a key only
// when the gate is explicitly opened. Otherwise it fails closed: if no write
// secret is configured, writes are disabled; else the X-Write-Key header must
// match. Returns false (and writes an error response) when denied.
func (h *Handlers) requireWriteKey(w http.ResponseWriter, r *http.Request) bool {
	if h.writeGate.AllowWithoutKey {
		return true
	}
	if h.writeGate.Secret == "" {
		writeError(w, http.StatusForbidden, "write operations disabled: set PROTON_WRITE_SECRET, or PROTON_ALLOW_WRITES_WITHOUT_KEY=true to allow writes without a key")
		return false
	}
	got := r.Header.Get("X-Write-Key")
	if subtle.ConstantTimeCompare([]byte(got), []byte(h.writeGate.Secret)) != 1 {
		writeError(w, http.StatusForbidden, "invalid or missing X-Write-Key header")
		return false
	}
	return true
}

// --- Auth ---

type loginRequest struct {
	Username string `json:"username"`
	HVToken  string `json:"hv_token"`
}

type login2FARequest struct {
	Code string `json:"code"`
}

// Login initiates authentication.
// @Summary Initier l'authentification Proton
// @Tags auth
// @Accept json
// @Produce json
// @Param request body loginRequest true "Identifiants"
// @Success 200 {object} map[string]any "authenticated"
// @Success 202 {object} map[string]any "2fa_required"
// @Failure 400 {object} map[string]any
// @Failure 401 {object} map[string]any
// @Failure 428 {object} map[string]any "human verification required"
// @Router /auth/login [post]
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	needs2FA, err := h.client.Login(r.Context(), req.Username, req.HVToken)
	if err != nil {
		var hvErr *pclient.HVRequiredError
		if errors.As(err, &hvErr) {
			writeJSON(w, http.StatusPreconditionRequired, map[string]any{
				"error":       "human verification required",
				"hv_required": true,
				"verify_url":  hvErr.VerifyURL,
				"methods":     hvErr.Methods,
			})
			return
		}
		h.logger.Error("login failed", "error", err)
		writeError(w, http.StatusUnauthorized, fmt.Sprintf("login failed: %v", err))
		return
	}

	if needs2FA {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":    "2fa_required",
			"message":   "Submit TOTP code via POST /api/v1/auth/2fa",
			"needs_2fa": true,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "authenticated",
		"message": "Login successful, keys unlocked",
	})
}

// Submit2FA completes the 2FA step.
func (h *Handlers) Submit2FA(w http.ResponseWriter, r *http.Request) {
	var req login2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	if err := h.client.Submit2FA(r.Context(), req.Code); err != nil {
		h.logger.Error("2FA failed", "error", err)
		writeError(w, http.StatusUnauthorized, fmt.Sprintf("2FA failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "authenticated",
		"message": "2FA successful, keys unlocked",
	})
}

// AuthStatus returns the current authentication state.
func (h *Handlers) AuthStatus(w http.ResponseWriter, r *http.Request) {
	authenticated := h.client.IsAuthenticated()

	resp := map[string]any{
		"authenticated": authenticated,
	}

	if authenticated {
		user, err := h.client.GetUser(r.Context())
		if err == nil {
			resp["user"] = map[string]any{
				"name":  user.Name,
				"email": user.Email,
			}
		}
	}

	resp["session"] = h.client.SessionInfo()

	writeJSON(w, http.StatusOK, resp)
}

// Logout revokes the session.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.client.Logout(r.Context()); err != nil {
		h.logger.Error("logout failed", "error", err)
		writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "logged_out",
		"message": "Session revoked and tokens cleared",
	})
}

// --- Messages ---

type messageResponse struct {
	ID             string   `json:"id"`
	Subject        string   `json:"subject"`
	SenderEmail    string   `json:"sender_email"`
	SenderName     string   `json:"sender_name"`
	AddressID      string   `json:"address_id"`
	To             []string `json:"to"`
	CC             []string `json:"cc"`
	Time           string   `json:"time"`
	UnixTime       int64    `json:"unix_time"`
	NumAttachments int      `json:"num_attachments"`
	Unread         bool     `json:"unread"`
	LabelIDs       []string `json:"label_ids"`
	Size           int      `json:"size"`
}

// addrEmails flattens a list of parsed addresses to their email strings,
// dropping nil entries. Returns an empty (non-nil) slice so the JSON field is
// always an array.
func addrEmails(list []*mail.Address) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		if a != nil {
			out = append(out, a.Address)
		}
	}
	return out
}

func toMessageResponse(m goproton.MessageMetadata) messageResponse {
	senderEmail := ""
	senderName := ""
	if m.Sender != nil {
		senderEmail = m.Sender.Address
		senderName = m.Sender.Name
	}

	return messageResponse{
		ID:             m.ID,
		Subject:        m.Subject,
		SenderEmail:    senderEmail,
		SenderName:     senderName,
		AddressID:      m.AddressID,
		To:             addrEmails(m.ToList),
		CC:             addrEmails(m.CCList),
		Time:           time.Unix(m.Time, 0).UTC().Format(time.RFC3339),
		UnixTime:       m.Time,
		NumAttachments: m.NumAttachments,
		Unread:         bool(m.Unread),
		LabelIDs:       m.LabelIDs,
		Size:           m.Size,
	}
}

// ListMessages returns message metadata with optional filters.
func (h *Handlers) ListMessages(w http.ResponseWriter, r *http.Request) {
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	filter := goproton.MessageFilter{
		Desc: goproton.Bool(true),
	}

	if label := r.URL.Query().Get("label"); label != "" {
		filter.LabelID = label
	} else {
		filter.LabelID = goproton.InboxLabel
	}

	if subject := r.URL.Query().Get("subject"); subject != "" {
		filter.Subject = subject
	}

	// Optional per-address filter: accept an opaque address_id directly, or an
	// email that we resolve to its AddressID (case-insensitive). This is how a
	// caller scopes a read to one of the account's addresses.
	if addrID := r.URL.Query().Get("address_id"); addrID != "" {
		filter.AddressID = addrID
	} else if email := r.URL.Query().Get("address"); email != "" {
		id, err := h.client.ResolveAddressID(r.Context(), email)
		if err != nil {
			if errors.Is(err, pclient.ErrAddressNotFound) {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown account address: %s", email))
				return
			}
			h.logger.Error("resolve address failed", "error", err, "address", email)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("resolve address: %v", err))
			return
		}
		filter.AddressID = id
	}

	msgs, err := h.client.ListMessages(r.Context(), filter)
	if err != nil {
		h.logger.Error("list messages failed", "error", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("list messages: %v", err))
		return
	}

	// Apply limit
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if len(msgs) > limit {
		msgs = msgs[:limit]
	}

	// Filter by attachments
	if r.URL.Query().Get("has_attachments") == "true" {
		filtered := make([]goproton.MessageMetadata, 0, len(msgs))
		for _, m := range msgs {
			if m.NumAttachments > 0 {
				filtered = append(filtered, m)
			}
		}
		msgs = filtered
	}

	result := make([]messageResponse, len(msgs))
	for i, m := range msgs {
		result[i] = toMessageResponse(m)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"messages": result,
		"count":    len(result),
	})
}

// GetMessage returns a single message with decrypted body.
func (h *Handlers) GetMessage(w http.ResponseWriter, r *http.Request) {
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	messageID := r.PathValue("id")
	if messageID == "" {
		writeError(w, http.StatusBadRequest, "message ID is required")
		return
	}

	msg, err := h.client.GetMessage(r.Context(), messageID)
	if err != nil {
		h.logger.Error("get message failed", "error", err, "id", messageID)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("get message: %v", err))
		return
	}

	attachments := make([]map[string]any, len(msg.Attachments))
	for i, att := range msg.Attachments {
		attachments[i] = map[string]any{
			"id":        att.ID,
			"name":      att.Name,
			"size":      att.Size,
			"mime_type": string(att.MIMEType),
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":              msg.ID,
		"subject":         msg.Subject,
		"address_id":      msg.AddressID,
		"to":              addrEmails(msg.ToList),
		"cc":              addrEmails(msg.CCList),
		"body":            msg.Body,
		"mime_type":       msg.MIMEType,
		"time":            time.Unix(msg.Time, 0).UTC().Format(time.RFC3339),
		"num_attachments": msg.NumAttachments,
		"label_ids":       msg.LabelIDs,
		"attachments":     attachments,
	})
}

// ListLabels returns the account's labels, folders and system labels.
// @Summary Lister les labels et dossiers
// @Tags messages
// @Produce json
// @Success 200 {object} map[string]any "labels, count"
// @Failure 401 {object} map[string]any
// @Router /labels [get]
func (h *Handlers) ListLabels(w http.ResponseWriter, r *http.Request) {
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	labels, err := h.client.ListLabels(r.Context())
	if err != nil {
		h.logger.Error("list labels failed", "error", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("list labels: %v", err))
		return
	}

	result := make([]map[string]any, 0, len(labels))
	for _, l := range labels {
		result = append(result, map[string]any{
			"id":        l.ID,
			"name":      l.Name,
			"type":      l.Type,
			"path":      l.Path,
			"color":     l.Color,
			"parent_id": l.ParentID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"labels": result,
		"count":  len(result),
	})
}

// ListAddresses returns the account's email addresses (primary, aliases, custom
// domains) with their status and send/receive capability.
// @Summary Lister les adresses du compte
// @Tags messages
// @Produce json
// @Success 200 {object} map[string]any "addresses, count"
// @Failure 401 {object} map[string]any
// @Router /addresses [get]
func (h *Handlers) ListAddresses(w http.ResponseWriter, r *http.Request) {
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	addrs, err := h.client.ListAddresses(r.Context())
	if err != nil {
		h.logger.Error("list addresses failed", "error", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("list addresses: %v", err))
		return
	}

	result := make([]map[string]any, 0, len(addrs))
	for _, a := range addrs {
		result = append(result, map[string]any{
			"id":           a.ID,
			"email":        a.Email,
			"status":       a.Status,
			"type":         a.Type,
			"send":         a.Send,
			"receive":      a.Receive,
			"order":        a.Order,
			"display_name": a.DisplayName,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"addresses": result,
		"count":     len(result),
	})
}

// DownloadAttachment returns a decrypted attachment.
func (h *Handlers) DownloadAttachment(w http.ResponseWriter, r *http.Request) {
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	messageID := r.PathValue("id")
	attachmentID := r.PathValue("attachmentId")

	if messageID == "" || attachmentID == "" {
		writeError(w, http.StatusBadRequest, "message ID and attachment ID are required")
		return
	}

	data, filename, mimeType, err := h.client.DownloadAttachment(r.Context(), messageID, attachmentID)
	if err != nil {
		h.logger.Error("download attachment failed", "error", err,
			"messageID", messageID, "attachmentID", attachmentID)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("download attachment: %v", err))
		return
	}

	writeAttachment(w, data, filename, mimeType)
}

// writeAttachment serves untrusted attachment bytes as a download, never inline.
func writeAttachment(w http.ResponseWriter, data []byte, filename, mimeType string) {
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data) // #nosec G705 -- Serve original attachment bytes as a forced download with an escaped filename and nosniff.
}

// --- Send ---

type attachmentReq struct {
	Filename string `json:"filename"`
	Content  string `json:"content"` // base64
	MIMEType string `json:"mime_type"`
}

type sendRequest struct {
	To          []string        `json:"to"`
	CC          []string        `json:"cc"`
	Subject     string          `json:"subject"`
	Body        string          `json:"body"`
	HTML        string          `json:"html,omitempty"`
	Attachments []attachmentReq `json:"attachments,omitempty"`
	// From : adresse d'envoi optionnelle (adresse active du compte).
	// Vide = adresse primaire.
	From string `json:"from,omitempty"`
	// InReplyTo : ID interne Proton du message parent (threading reply/forward).
	InReplyTo string `json:"in_reply_to,omitempty"`
	// Action : reply | reply_all | forward (ignorée si InReplyTo vide).
	Action string `json:"action,omitempty"`
}

// decodeAttachments decodes base64 attachment contents into pclient.Attachment.
func decodeAttachments(reqs []attachmentReq) ([]pclient.Attachment, error) {
	atts := make([]pclient.Attachment, 0, len(reqs))
	for _, a := range reqs {
		if a.Filename == "" {
			return nil, fmt.Errorf("attachment filename is required")
		}
		content, err := base64.StdEncoding.DecodeString(a.Content)
		if err != nil {
			return nil, fmt.Errorf("attachment %s: invalid base64 content", a.Filename)
		}
		atts = append(atts, pclient.Attachment{
			Filename: a.Filename,
			MIMEType: a.MIMEType,
			Content:  content,
		})
	}
	return atts, nil
}

// SendMessage envoie un email. Corps HTML si fourni (sinon texte brut).
// Destinataires internes chiffrés, externes en clair.
// @Summary Envoyer un email
// @Tags messages
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Security WriteKey
// @Param request body sendRequest true "Email à envoyer (in_reply_to + action pour répondre/transférer dans le fil)"
// @Success 200 {object} map[string]any "status: sent, message_id"
// @Failure 400 {object} map[string]any
// @Failure 401 {object} map[string]any
// @Failure 403 {object} map[string]any
// @Router /messages/send [post]
func (h *Handlers) SendMessage(w http.ResponseWriter, r *http.Request) {
	if !h.requireWriteKey(w, r) {
		return
	}
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req sendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.To) == 0 {
		writeError(w, http.StatusBadRequest, "at least one recipient ('to') is required")
		return
	}

	attachments, err := decodeAttachments(req.Attachments)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	action := pclient.SendAction(req.Action)
	switch action {
	case "", pclient.SendActionReply, pclient.SendActionReplyAll, pclient.SendActionForward:
		// valide
	default:
		writeError(w, http.StatusBadRequest, "action must be one of: reply, reply_all, forward")
		return
	}

	id, err := h.client.SendMessage(r.Context(), pclient.SendRequest{
		To:          req.To,
		CC:          req.CC,
		Subject:     req.Subject,
		Body:        req.Body,
		HTML:        req.HTML,
		Attachments: attachments,
		From:        req.From,
		ParentID:    req.InReplyTo,
		Action:      action,
	})
	if err != nil {
		h.logger.Error("send failed", "error", err)
		writeError(w, sendErrorStatus(err), fmt.Sprintf("send failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "sent", "message_id": id})
}

// sendErrorStatus maps client send errors to HTTP statuses. A requested sender
// address that doesn't exist is a client error (400); anything else is a
// server error (500).
func sendErrorStatus(err error) int {
	if errors.Is(err, pclient.ErrSenderAddressNotFound) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// --- Calendar ---

// parseUnixParam reads an optional unix-timestamp query param. An absent or
// empty value returns 0 (unbounded).
func parseUnixParam(r *http.Request, name string) (int64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a unix timestamp: %w", name, err)
	}
	return n, nil
}

// parseTimeRange reads the optional from/to unix-timestamp query params. A zero
// bound is unbounded on that side; an inverted range is rejected.
func parseTimeRange(r *http.Request) (from, to int64, err error) {
	if from, err = parseUnixParam(r, "from"); err != nil {
		return 0, 0, err
	}
	if to, err = parseUnixParam(r, "to"); err != nil {
		return 0, 0, err
	}
	if from > 0 && to > 0 && to < from {
		return 0, 0, fmt.Errorf("to must not be before from")
	}
	return from, to, nil
}

// parseTimezoneParam reads the optional IANA timezone Proton uses to place
// full-day events in the requested window. An absent value means UTC.
func parseTimezoneParam(r *http.Request) (string, error) {
	tz := r.URL.Query().Get("timezone")
	if tz == "" {
		return "UTC", nil
	}
	if _, err := time.LoadLocation(tz); err != nil || tz == "Local" {
		return "", fmt.Errorf("timezone must be an IANA name such as Europe/Paris")
	}
	return tz, nil
}

// ListCalendars returns the user's calendars.
// @Summary Lister les calendriers
// @Tags calendar
// @Produce json
// @Success 200 {object} map[string]any "calendars, count"
// @Failure 401 {object} map[string]any
// @Router /calendars [get]
func (h *Handlers) ListCalendars(w http.ResponseWriter, r *http.Request) {
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	cals, err := h.client.ListCalendars(r.Context())
	if err != nil {
		h.logger.Error("list calendars failed", "error", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("list calendars: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"calendars": cals,
		"count":     len(cals),
	})
}

// ListCalendarEvents returns the events of a calendar (decrypted VEVENTs),
// optionally restricted to a time range and always sorted by start time.
// @Summary Lister les événements d'un calendrier
// @Tags calendar
// @Produce json
// @Param id path string true "ID du calendrier"
// @Param from query int false "Timestamp Unix (secondes) : ne renvoie que les événements débutant à partir de cette date"
// @Param to query int false "Timestamp Unix (secondes) : ne renvoie que les événements débutant avant cette date"
// @Param timezone query string false "Fuseau IANA (ex. Europe/Paris) utilisé par Proton pour placer les événements sur la journée entière dans la fenêtre ; défaut UTC"
// @Success 200 {object} map[string]any "events, count"
// @Failure 400 {object} map[string]any
// @Failure 401 {object} map[string]any
// @Router /calendars/{id}/events [get]
func (h *Handlers) ListCalendarEvents(w http.ResponseWriter, r *http.Request) {
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	calendarID := r.PathValue("id")
	if calendarID == "" {
		writeError(w, http.StatusBadRequest, "calendar ID is required")
		return
	}

	from, to, err := parseTimeRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	timezone, err := parseTimezoneParam(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	events, err := h.client.ListCalendarEvents(r.Context(), calendarID, from, to, timezone)
	if err != nil {
		h.logger.Error("list calendar events failed", "error", err, "calendarID", calendarID)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("list calendar events: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
	})
}

// CreateCalendarEvent creates an encrypted event in a calendar (write-gated).
// @Summary Créer un événement chiffré
// @Tags calendar
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Security WriteKey
// @Param id path string true "ID du calendrier"
// @Param request body pclient.CreateCalendarEventRequest true "Événement (summary, start, end, full_day, description, location)"
// @Success 200 {object} map[string]any "status: created, event"
// @Failure 400 {object} map[string]any
// @Failure 401 {object} map[string]any
// @Failure 403 {object} map[string]any
// @Router /calendars/{id}/events [post]
func (h *Handlers) CreateCalendarEvent(w http.ResponseWriter, r *http.Request) {
	if !h.requireWriteKey(w, r) {
		return
	}
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	calendarID := r.PathValue("id")
	if calendarID == "" {
		writeError(w, http.StatusBadRequest, "calendar ID is required")
		return
	}

	var req pclient.CreateCalendarEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ev, err := h.client.CreateCalendarEvent(r.Context(), calendarID, req)
	if err != nil {
		h.logger.Error("create calendar event failed", "error", err, "calendarID", calendarID)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create calendar event: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "created",
		"event":  ev,
	})
}

// DeleteCalendarEvent removes an event from a calendar (write-gated).
// @Summary Supprimer un événement
// @Tags calendar
// @Produce json
// @Security ApiKeyAuth
// @Security WriteKey
// @Param id path string true "ID du calendrier"
// @Param eventId path string true "ID de l'événement"
// @Success 200 {object} map[string]any "status: deleted"
// @Failure 400 {object} map[string]any
// @Failure 401 {object} map[string]any
// @Failure 403 {object} map[string]any
// @Router /calendars/{id}/events/{eventId} [delete]
func (h *Handlers) DeleteCalendarEvent(w http.ResponseWriter, r *http.Request) {
	if !h.requireWriteKey(w, r) {
		return
	}
	if !h.client.IsAuthenticated() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	calendarID := r.PathValue("id")
	eventID := r.PathValue("eventId")
	if calendarID == "" || eventID == "" {
		writeError(w, http.StatusBadRequest, "calendar ID and event ID are required")
		return
	}

	if err := h.client.DeleteCalendarEvent(r.Context(), calendarID, eventID); err != nil {
		h.logger.Error("delete calendar event failed", "error", err,
			"calendarID", calendarID, "eventID", eventID)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("delete calendar event: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

// --- Health ---

// Health returns service health.
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"authenticated": h.client.IsAuthenticated(),
		"session":       h.client.SessionInfo(),
	})
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
