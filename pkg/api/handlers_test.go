package api

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"testing"

	goproton "github.com/ProtonMail/go-proton-api"
	pclient "github.com/didlawowo/proton-mcp-service/pkg/proton"
)

func TestWriteAttachmentForcesDownloadWithUntrustedMetadata(t *testing.T) {
	for _, tt := range []struct {
		name     string
		filename string
		mimeType string
		wantType string
	}{
		{"html attachment", "message.html", "text/html", "text/html"},
		{"quoted filename", `x"; inline; filename="payload.html`, "text/html", "text/html"},
		{"unicode and newline", "résumé\n.txt", "text/plain", "text/plain"},
		{"unknown type", "file.bin", "", "application/octet-stream"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("<script>alert(1)</script>\x00\xff")
			recorder := httptest.NewRecorder()
			writeAttachment(recorder, body, tt.filename, tt.mimeType)
			response := recorder.Result()
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", response.StatusCode)
			}
			if got := response.Header.Get("Content-Type"); got != tt.wantType {
				t.Errorf("Content-Type = %q, want %q", got, tt.wantType)
			}
			if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q", got)
			}
			header := response.Header.Get("Content-Disposition")
			if strings.ContainsAny(header, "\r\n") {
				t.Fatalf("Content-Disposition contains a raw line break: %q", header)
			}
			disposition, params, err := mime.ParseMediaType(header)
			if err != nil || disposition != "attachment" || params["filename"] != tt.filename {
				t.Errorf("unsafe or lossy Content-Disposition: %q (error: %v)", header, err)
			}
			got, err := io.ReadAll(response.Body)
			if err != nil || !bytes.Equal(got, body) {
				t.Errorf("attachment bytes changed: %x (error: %v)", got, err)
			}
		})
	}
}

func TestDecodeAttachments(t *testing.T) {
	tests := []struct {
		name    string
		reqs    []attachmentReq
		wantLen int
		wantErr bool
	}{
		{
			name: "decodes one base64 attachment",
			reqs: []attachmentReq{
				{
					Filename: "report.xlsx",
					Content:  base64.StdEncoding.EncodeToString([]byte("file-bytes")),
					MIMEType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
				},
			},
			wantLen: 1,
		},
		{
			name: "decodes multiple attachments",
			reqs: []attachmentReq{
				{Filename: "a.txt", Content: base64.StdEncoding.EncodeToString([]byte("aaa"))},
				{Filename: "b.txt", Content: base64.StdEncoding.EncodeToString([]byte("bbb"))},
			},
			wantLen: 2,
		},
		{
			name: "rejects empty filename",
			reqs: []attachmentReq{
				{Filename: "", Content: base64.StdEncoding.EncodeToString([]byte("x"))},
			},
			wantErr: true,
		},
		{
			name: "rejects invalid base64",
			reqs: []attachmentReq{
				{Filename: "bad.txt", Content: "not-base64!!!"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atts, err := decodeAttachments(tt.reqs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeAttachments() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(atts) != tt.wantLen {
				t.Fatalf("decodeAttachments() len = %d, want %d", len(atts), tt.wantLen)
			}
			for i, att := range atts {
				if att.Filename != tt.reqs[i].Filename {
					t.Errorf("attachment %d filename = %q, want %q", i, att.Filename, tt.reqs[i].Filename)
				}
				if att.MIMEType != tt.reqs[i].MIMEType {
					t.Errorf("attachment %d MIME = %q, want %q", i, att.MIMEType, tt.reqs[i].MIMEType)
				}
				wantContent, _ := base64.StdEncoding.DecodeString(tt.reqs[i].Content)
				if !bytes.Equal(att.Content, wantContent) {
					t.Errorf("attachment %d content = %q, want %q", i, att.Content, wantContent)
				}
			}
		})
	}
}

func TestDecodeAttachmentsPreservesContent(t *testing.T) {
	reqs := []attachmentReq{
		{Filename: "hello.txt", Content: base64.StdEncoding.EncodeToString([]byte("hello, world"))},
	}
	atts, err := decodeAttachments(reqs)
	if err != nil {
		t.Fatalf("decodeAttachments() unexpected error: %v", err)
	}
	if got := string(atts[0].Content); got != "hello, world" {
		t.Errorf("decoded content = %q, want %q", got, "hello, world")
	}
}

func TestRequireWriteKey(t *testing.T) {
	newReq := func(key string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if key != "" {
			r.Header.Set("X-Write-Key", key)
		}
		return r
	}

	t.Run("allows writes without a key when explicitly opened", func(t *testing.T) {
		h := &Handlers{writeGate: WriteGate{AllowWithoutKey: true}}
		rec := httptest.NewRecorder()
		if !h.requireWriteKey(rec, newReq("")) {
			t.Fatalf("requireWriteKey should allow writes without a key, got status %d", rec.Code)
		}
	})

	t.Run("opened gate does not require the configured secret", func(t *testing.T) {
		h := &Handlers{writeGate: WriteGate{Secret: "s3cret", AllowWithoutKey: true}}
		rec := httptest.NewRecorder()
		if !h.requireWriteKey(rec, newReq("")) {
			t.Fatalf("requireWriteKey should ignore the secret when the gate is opened, got status %d", rec.Code)
		}
	})

	t.Run("disabled when no secret configured (fail-closed)", func(t *testing.T) {
		h := &Handlers{}
		rec := httptest.NewRecorder()
		if h.requireWriteKey(rec, newReq("anything")) {
			t.Fatal("requireWriteKey should deny when no secret is configured")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("denies missing header", func(t *testing.T) {
		h := &Handlers{writeGate: WriteGate{Secret: "s3cret"}}
		rec := httptest.NewRecorder()
		if h.requireWriteKey(rec, newReq("")) {
			t.Fatal("requireWriteKey should deny a missing header")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("denies wrong header", func(t *testing.T) {
		h := &Handlers{writeGate: WriteGate{Secret: "s3cret"}}
		rec := httptest.NewRecorder()
		if h.requireWriteKey(rec, newReq("wrong")) {
			t.Fatal("requireWriteKey should deny a wrong key")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("allows matching header", func(t *testing.T) {
		h := &Handlers{writeGate: WriteGate{Secret: "s3cret"}}
		rec := httptest.NewRecorder()
		if !h.requireWriteKey(rec, newReq("s3cret")) {
			t.Fatal("requireWriteKey should allow the matching key")
		}
		if rec.Code != 0 && rec.Code != http.StatusOK {
			t.Errorf("unexpected status %d", rec.Code)
		}
	})
}

func TestRouterWriteGate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// A client that is non-nil but has no live Proton session: reads pass the
	// write gate and fail on auth, writes fail on the gate itself.
	emptyClient := &pclient.Client{}

	t.Run("send without write key is forbidden", func(t *testing.T) {
		r := NewRouter(emptyClient, WriteGate{Secret: "s3cret"}, "", true, logger)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/messages/send",
			bytes.NewReader([]byte(`{"to":["a@b.c"],"subject":"s","body":"b"}`)))
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("create event without write key is forbidden", func(t *testing.T) {
		r := NewRouter(emptyClient, WriteGate{Secret: "s3cret"}, "", true, logger)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/calendars/cal1/events",
			bytes.NewReader([]byte(`{"summary":"x","start_time":1,"end_time":2}`)))
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("read routes stay open", func(t *testing.T) {
		r := NewRouter(emptyClient, WriteGate{Secret: "s3cret"}, "", true, logger)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/calendars", nil))
		// Not 403: the gate must not apply to reads (they fail on auth, not the gate).
		if rec.Code == http.StatusForbidden {
			t.Errorf("read route should not hit the write gate, got %d", rec.Code)
		}
	})

	t.Run("labels route stays open (read)", func(t *testing.T) {
		r := NewRouter(emptyClient, WriteGate{Secret: "s3cret"}, "", true, logger)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/labels", nil))
		if rec.Code == http.StatusForbidden {
			t.Errorf("labels read route should not hit the write gate, got %d", rec.Code)
		}
		// Unauthenticated client: 401, not a panic or 500.
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("labels route status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestAddrEmails(t *testing.T) {
	t.Run("flattens addresses and skips nil", func(t *testing.T) {
		got := addrEmails([]*mail.Address{
			{Address: "a@example.com"},
			nil,
			{Name: "Bob", Address: "b@example.com"},
		})
		want := []string{"a@example.com", "b@example.com"}
		if len(got) != len(want) {
			t.Fatalf("addrEmails() len = %d, want %d (%v)", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("addrEmails()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("empty input yields non-nil empty slice", func(t *testing.T) {
		got := addrEmails(nil)
		if got == nil {
			t.Fatal("addrEmails(nil) should return a non-nil slice so JSON is []")
		}
		if len(got) != 0 {
			t.Errorf("addrEmails(nil) len = %d, want 0", len(got))
		}
	})
}

func TestParseUnixParam(t *testing.T) {
	t.Run("absent value is unbounded (zero)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/calendars/cal1/events", nil)
		got, err := parseUnixParam(req, "from")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 0 {
			t.Errorf("got %d, want 0", got)
		}
	})

	t.Run("valid value is parsed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/calendars/cal1/events?from=1700000000", nil)
		got, err := parseUnixParam(req, "from")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 1700000000 {
			t.Errorf("got %d, want 1700000000", got)
		}
	})

	t.Run("non-numeric value is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/calendars/cal1/events?from=not-a-number", nil)
		if _, err := parseUnixParam(req, "from"); err == nil {
			t.Fatal("expected an error for a non-numeric value")
		}
	})
}

func TestParseTimeRange(t *testing.T) {
	newReq := func(query string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/api/v1/calendars/cal1/events"+query, nil)
	}

	t.Run("single lower bound is accepted", func(t *testing.T) {
		from, to, err := parseTimeRange(newReq("?from=100"))
		if err != nil || from != 100 || to != 0 {
			t.Fatalf("got (%d, %d, %v), want (100, 0, nil)", from, to, err)
		}
	})

	t.Run("ordered range is accepted", func(t *testing.T) {
		from, to, err := parseTimeRange(newReq("?from=100&to=200"))
		if err != nil || from != 100 || to != 200 {
			t.Fatalf("got (%d, %d, %v), want (100, 200, nil)", from, to, err)
		}
	})

	t.Run("inverted range is rejected", func(t *testing.T) {
		if _, _, err := parseTimeRange(newReq("?from=200&to=100")); err == nil {
			t.Fatal("expected an error when to is before from")
		}
	})

	t.Run("non-numeric bound is rejected", func(t *testing.T) {
		if _, _, err := parseTimeRange(newReq("?to=soon")); err == nil {
			t.Fatal("expected an error for a non-numeric bound")
		}
	})
}

func TestParseTimezoneParam(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		want    string
		wantErr bool
	}{
		{"absent defaults to UTC", "", "UTC", false},
		{"IANA name is kept", "?timezone=Europe/Paris", "Europe/Paris", false},
		{"unknown zone is rejected", "?timezone=Mars/Olympus", "", true},
		{"Local is rejected", "?timezone=Local", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/calendars/cal1/events"+tt.query, nil)
			got, err := parseTimezoneParam(req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestToMessageResponse(t *testing.T) {
	m := goproton.MessageMetadata{
		ID:        "msg1",
		AddressID: "addr-alias",
		Subject:   "Hello",
		Sender:    &mail.Address{Name: "Alice", Address: "alice@ext.com"},
		ToList: []*mail.Address{
			{Address: "me+alias@proton.me"},
		},
		CCList: []*mail.Address{
			{Address: "team@proton.me"},
		},
		Time:           1_700_000_000,
		NumAttachments: 2,
		LabelIDs:       []string{"5"},
	}

	got := toMessageResponse(m)

	if got.AddressID != "addr-alias" {
		t.Errorf("AddressID = %q, want %q", got.AddressID, "addr-alias")
	}
	if len(got.To) != 1 || got.To[0] != "me+alias@proton.me" {
		t.Errorf("To = %v, want [me+alias@proton.me]", got.To)
	}
	if len(got.CC) != 1 || got.CC[0] != "team@proton.me" {
		t.Errorf("CC = %v, want [team@proton.me]", got.CC)
	}
	if got.SenderEmail != "alice@ext.com" {
		t.Errorf("SenderEmail = %q, want %q", got.SenderEmail, "alice@ext.com")
	}
}

func TestAddressesRouteReadOnly(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	emptyClient := &pclient.Client{}
	r := NewRouter(emptyClient, WriteGate{Secret: "s3cret"}, "", true, logger)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/addresses", nil))

	// Read route: must not hit the write gate; unauthenticated client => 401.
	if rec.Code == http.StatusForbidden {
		t.Errorf("addresses read route should not hit the write gate, got %d", rec.Code)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("addresses route status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSendErrorStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "sender not found (direct)",
			err:  pclient.ErrSenderAddressNotFound,
			want: http.StatusBadRequest,
		},
		{
			name: "sender not found (wrapped)",
			err:  fmt.Errorf("send failed: %w", pclient.ErrSenderAddressNotFound),
			want: http.StatusBadRequest,
		},
		{
			name: "other send error is a server error",
			err:  errors.New("proton api unreachable"),
			want: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sendErrorStatus(tt.err); got != tt.want {
				t.Errorf("sendErrorStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}
