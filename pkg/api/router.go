package api

import (
	"crypto/subtle"
	"log/slog"
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	// docs embarquées (générées par swag init, package docs/).
	_ "github.com/didlawowo/proton-mcp-service/docs"

	pclient "github.com/didlawowo/proton-mcp-service/pkg/proton"
)

// NewRouter creates the HTTP router with all routes registered.
func NewRouter(client *pclient.Client, writeGate WriteGate, apiKey string, allowUnauthenticated bool, logger *slog.Logger) http.Handler {
	h := NewHandlers(client, writeGate, logger)
	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /health", h.Health)

	// Auth
	mux.HandleFunc("POST /api/v1/auth/login", h.Login)
	mux.HandleFunc("POST /api/v1/auth/2fa", h.Submit2FA)
	mux.HandleFunc("GET /api/v1/auth/status", h.AuthStatus)
	mux.HandleFunc("POST /api/v1/auth/logout", h.Logout)

	// Messages
	mux.HandleFunc("GET /api/v1/messages", h.ListMessages)
	mux.HandleFunc("GET /api/v1/messages/{id}", h.GetMessage)
	mux.HandleFunc("GET /api/v1/messages/{id}/attachments/{attachmentId}", h.DownloadAttachment)
	mux.HandleFunc("GET /api/v1/labels", h.ListLabels)
	mux.HandleFunc("GET /api/v1/addresses", h.ListAddresses)
	mux.HandleFunc("POST /api/v1/messages/send", h.SendMessage)

	// Calendar
	mux.HandleFunc("GET /api/v1/calendars", h.ListCalendars)
	mux.HandleFunc("GET /api/v1/calendars/{id}/events", h.ListCalendarEvents)
	mux.HandleFunc("POST /api/v1/calendars/{id}/events", h.CreateCalendarEvent)
	mux.HandleFunc("DELETE /api/v1/calendars/{id}/events/{eventId}", h.DeleteCalendarEvent)

	// Swagger UI (docs générées par swag init)
	mux.Handle("GET /swagger/", httpSwagger.WrapHandler)

	return loggingMiddleware(logger, apiKeyMiddleware(apiKey, allowUnauthenticated, mux))
}

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// apiKeyMiddleware protects every route. The health probe remains available but
// reveals no session data without a valid key.
func apiKeyMiddleware(key string, allowUnauthenticated bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowUnauthenticated || (key != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), []byte(key)) == 1) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/health" {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid or missing API key")
	})
}
