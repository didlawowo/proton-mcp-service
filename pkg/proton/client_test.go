package proton

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/gluon/rfc822"
	goproton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/didlawowo/proton-mcp-service/pkg/session"
)

func TestSendMIMEType(t *testing.T) {
	tests := []struct {
		name     string
		req      SendRequest
		wantMIME rfc822.MIMEType
		wantBody string
	}{
		{
			name: "HTML provided wins over plain text",
			req: SendRequest{
				Body: "plain fallback",
				HTML: "<h1>Hello</h1>",
			},
			wantMIME: rfc822.TextHTML,
			wantBody: "<h1>Hello</h1>",
		},
		{
			name: "no HTML uses plain text",
			req: SendRequest{
				Body: "hello world",
			},
			wantMIME: rfc822.TextPlain,
			wantBody: "hello world",
		},
		{
			name: "empty body with no HTML defaults to plain text",
			req: SendRequest{
				Body: "",
			},
			wantMIME: rfc822.TextPlain,
			wantBody: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMIME, gotBody := sendMIMEType(tt.req)
			if gotMIME != tt.wantMIME {
				t.Errorf("sendMIMEType() MIME = %q, want %q", gotMIME, tt.wantMIME)
			}
			if gotBody != tt.wantBody {
				t.Errorf("sendMIMEType() body = %q, want %q", gotBody, tt.wantBody)
			}
		})
	}
}

func TestHVRequiredError(t *testing.T) {
	t.Run("parses WebURL and methods from details", func(t *testing.T) {
		apiErr := &goproton.APIError{
			Code:    9001,
			Details: goproton.ErrDetails(`{"HumanVerificationMethods":["captcha"],"HumanVerificationToken":"tok","WebURL":"https://account.proton.me/verify/custom"}`),
		}
		e := hvRequiredError(apiErr)
		if e.VerifyURL != "https://account.proton.me/verify/custom" {
			t.Errorf("VerifyURL = %q, want custom URL", e.VerifyURL)
		}
		if len(e.Methods) != 1 || e.Methods[0] != "captcha" {
			t.Errorf("Methods = %v, want [captcha]", e.Methods)
		}
	})

	t.Run("builds verify URL from token when WebURL absent", func(t *testing.T) {
		apiErr := &goproton.APIError{
			Code:    9001,
			Details: goproton.ErrDetails(`{"HumanVerificationMethods":["captcha"],"HumanVerificationToken":"abc123"}`),
		}
		e := hvRequiredError(apiErr)
		if e.VerifyURL == "" || e.VerifyURL == "https://account.proton.me/verify?methods=captcha" {
			t.Errorf("VerifyURL = %q, want token-scoped URL", e.VerifyURL)
		}
		if !strings.Contains(e.VerifyURL, "abc123") {
			t.Errorf("VerifyURL %q missing the token", e.VerifyURL)
		}
	})

	t.Run("falls back to default verify URL", func(t *testing.T) {
		e := hvRequiredError(&goproton.APIError{Code: 9001})
		if e.VerifyURL != "https://account.proton.me/verify?methods=captcha" {
			t.Errorf("VerifyURL = %q, want default", e.VerifyURL)
		}
		if len(e.Methods) != 1 || e.Methods[0] != "captcha" {
			t.Errorf("Methods = %v, want [captcha]", e.Methods)
		}
	})
}

func TestSessionInfo(t *testing.T) {
	t.Run("reports persisted session", func(t *testing.T) {
		store := session.NewStore(filepath.Join(t.TempDir(), "session.json"))
		if err := store.Save("user@example.com", goproton.Auth{UID: "u", AccessToken: "a", RefreshToken: "r"}); err != nil {
			t.Fatalf("Save() error: %v", err)
		}

		c := NewClient(store, "", "test@1.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
		defer c.Close()
		info := c.SessionInfo()
		if info.Username != "user@example.com" {
			t.Errorf("Username = %q, want user@example.com", info.Username)
		}
		if info.CreatedAt.IsZero() {
			t.Error("CreatedAt should be set")
		}
		if info.Authenticated {
			t.Error("Authenticated should be false (no live client)")
		}
	})

	t.Run("no session leaves zero values", func(t *testing.T) {
		c := NewClient(session.NewStore(filepath.Join(t.TempDir(), "nope.json")), "", "test@1.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
		defer c.Close()
		info := c.SessionInfo()
		if info.Username != "" || !info.CreatedAt.IsZero() {
			t.Errorf("unexpected session info for empty store: %+v", info)
		}
	})
}

func TestMergeVEVENT(t *testing.T) {
	t.Run("merges shared and calendar fragments with dedup", func(t *testing.T) {
		shared := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:abc@proton.me\r\nSUMMARY:RDV dentiste\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
		calendar := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:abc@proton.me\r\nDTSTAMP:20260801T120000Z\r\nSTATUS:CONFIRMED\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

		got := mergeVEVENT([]string{shared, calendar})
		if !strings.Contains(got, "SUMMARY:RDV dentiste") {
			t.Errorf("merged VEVENT missing SUMMARY: %q", got)
		}
		if !strings.Contains(got, "STATUS:CONFIRMED") {
			t.Errorf("merged VEVENT missing STATUS: %q", got)
		}
		if strings.Count(got, "UID:abc@proton.me") != 1 {
			t.Errorf("UID should appear once, got: %q", got)
		}
		if !strings.HasPrefix(got, "BEGIN:VCALENDAR") || !strings.HasSuffix(got, "END:VCALENDAR\r\n") {
			t.Errorf("merged VEVENT not well-formed: %q", got)
		}
	})

	t.Run("no fragments returns empty", func(t *testing.T) {
		if got := mergeVEVENT(nil); got != "" {
			t.Errorf("mergeVEVENT(nil) = %q, want empty", got)
		}
	})

	t.Run("identical property lines deduped across fragments", func(t *testing.T) {
		a := "BEGIN:VEVENT\r\nUID:x@proton.me\r\nSTATUS:CONFIRMED\r\nEND:VEVENT"
		b := "BEGIN:VEVENT\r\nUID:x@proton.me\r\nDTSTAMP:20260801T120000Z\r\nEND:VEVENT"
		got := mergeVEVENT([]string{a, b})
		if strings.Count(got, "UID:x@proton.me") != 1 {
			t.Errorf("UID should appear once, got: %q", got)
		}
		if !strings.Contains(got, "STATUS:CONFIRMED") || !strings.Contains(got, "DTSTAMP:20260801T120000Z") {
			t.Errorf("merged VEVENT missing properties: %q", got)
		}
	})

	t.Run("handles LF-only line endings (no CRLF)", func(t *testing.T) {
		lf := "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nUID:x@proton.me\nSUMMARY:Team lunch\nEND:VEVENT\nEND:VCALENDAR\n"
		got := mergeVEVENT([]string{lf})
		if !strings.Contains(got, "SUMMARY:Team lunch") {
			t.Errorf("LF-only fragment SUMMARY lost: %q", got)
		}
	})
}

func TestDecryptEventPart(t *testing.T) {
	tests := []struct {
		name    string
		part    goproton.CalendarEventPart
		wantErr bool
	}{
		{
			name: "clear part is a no-op",
			part: goproton.CalendarEventPart{
				Type: goproton.CalendarEventTypeClear,
				Data: "clear vevent data",
			},
		},
		{
			name: "encrypted part with invalid base64 data errors",
			part: goproton.CalendarEventPart{
				Type: goproton.CalendarEventTypeEncrypted,
				Data: "not-base64!!!",
			},
			wantErr: true,
		},
		{
			name: "signed part with invalid armored signature is best-effort",
			part: goproton.CalendarEventPart{
				Type:      goproton.CalendarEventTypeSigned,
				Data:      "vevent data",
				Signature: "not-an-armored-signature",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := decryptEventPart(&tt.part, nil, nil, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decryptEventPart() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.name == "clear part is a no-op" && tt.part.Data != "clear vevent data" {
				t.Errorf("clear part data was modified: %q", tt.part.Data)
			}
		})
	}
}

func TestAttachmentMIMEType(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		mimeType string
		want     string
	}{
		{
			name:     "explicit MIME type is kept",
			filename: "report.csv",
			mimeType: "text/csv",
			want:     "text/csv",
		},
		{
			name:     "MIME inferred from known extension",
			filename: "prospects.xlsx",
			want:     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		},
		{
			name:     "unknown extension falls back to octet-stream",
			filename: "archive.unknownext",
			want:     "application/octet-stream",
		},
		{
			name:     "empty filename and MIME falls back to octet-stream",
			filename: "",
			want:     "application/octet-stream",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := attachmentMIMEType(tt.filename, tt.mimeType); got != tt.want {
				t.Errorf("attachmentMIMEType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPickSenderAddress(t *testing.T) {
	kr := &crypto.KeyRing{}
	addrKRs := map[string]*crypto.KeyRing{
		"primary": kr,
		"alias":   kr,
	}
	addrs := []goproton.Address{
		{ID: "disabled", Email: "old@example.com", Status: goproton.AddressStatusDisabled},
		{ID: "primary", Email: "chris@example.com", Status: goproton.AddressStatusEnabled},
		{ID: "alias", Email: "alias@example.com", Status: goproton.AddressStatusEnabled},
		{ID: "nokey", Email: "nokey@example.com", Status: goproton.AddressStatusEnabled},
	}

	t.Run("empty preferred falls back to first enabled address with keyring", func(t *testing.T) {
		got, _, err := pickSenderAddress(addrs, addrKRs, "")
		if err != nil {
			t.Fatalf("pickSenderAddress() unexpected error: %v", err)
		}
		if got != "chris@example.com" {
			t.Errorf("email = %q, want %q", got, "chris@example.com")
		}
	})

	t.Run("preferred matches case-insensitively", func(t *testing.T) {
		got, _, err := pickSenderAddress(addrs, addrKRs, "ALIAS@Example.COM")
		if err != nil {
			t.Fatalf("pickSenderAddress() unexpected error: %v", err)
		}
		if got != "alias@example.com" {
			t.Errorf("email = %q, want %q", got, "alias@example.com")
		}
	})

	t.Run("unknown preferred returns ErrSenderAddressNotFound", func(t *testing.T) {
		_, _, err := pickSenderAddress(addrs, addrKRs, "nobody@example.com")
		if !errors.Is(err, ErrSenderAddressNotFound) {
			t.Fatalf("error = %v, want ErrSenderAddressNotFound", err)
		}
	})

	t.Run("enabled address without keyring is skipped", func(t *testing.T) {
		// nokey@example.com is enabled but has no keyring → must not match.
		_, _, err := pickSenderAddress(addrs, addrKRs, "nokey@example.com")
		if !errors.Is(err, ErrSenderAddressNotFound) {
			t.Fatalf("error = %v, want ErrSenderAddressNotFound", err)
		}
	})

	t.Run("no usable address reports a distinct error", func(t *testing.T) {
		_, _, err := pickSenderAddress(addrs, nil, "")
		if err == nil || errors.Is(err, ErrSenderAddressNotFound) {
			t.Fatalf("error = %v, want a 'no usable sender' error", err)
		}
	})
}

func TestCalendarEventFilters(t *testing.T) {
	t.Run("no bounds keeps the unfiltered endpoint", func(t *testing.T) {
		filters := calendarEventFilters(0, 0, "")
		if len(filters) != 1 || filters[0] != nil {
			t.Fatalf("filters = %#v, want one nil filter", filters)
		}
	})

	t.Run("time range queries all event categories including series before the window", func(t *testing.T) {
		filters := calendarEventFilters(100, 200, "Europe/Paris")
		if len(filters) != 4 {
			t.Fatalf("got %d filters, want 4", len(filters))
		}
		for i, filter := range filters {
			if got := filter.Get("Type"); got != strconv.Itoa(i) {
				t.Errorf("filter %d Type = %q, want %d", i, got, i)
			}
			if got := filter.Get("Start"); got != "100" {
				t.Errorf("filter %d Start = %q, want 100", i, got)
			}
			if got := filter.Get("End"); got != "200" {
				t.Errorf("filter %d End = %q, want 200", i, got)
			}
			if got := filter.Get("Timezone"); got != "Europe/Paris" {
				t.Errorf("filter %d Timezone = %q, want Europe/Paris", i, got)
			}
		}
	})

	t.Run("missing upper bound ends at the end of 2030 UTC", func(t *testing.T) {
		want := time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC).Unix()
		if got := calendarEventFilters(100, 0, "")[0].Get("End"); got != strconv.FormatInt(want, 10) {
			t.Errorf("End = %q, want %d", got, want)
		}
	})

	t.Run("empty timezone defaults to UTC", func(t *testing.T) {
		for i, filter := range calendarEventFilters(100, 200, "") {
			if got := filter.Get("Timezone"); got != "UTC" {
				t.Errorf("filter %d Timezone = %q, want UTC", i, got)
			}
		}
	})
}

func TestSortByStartTime(t *testing.T) {
	events := []CalendarEventInfo{
		{ID: "c", StartTime: 300},
		{ID: "a", StartTime: 100},
		{ID: "b", StartTime: 200},
	}

	sortByStartTime(events)

	want := []string{"a", "b", "c"}
	for i, id := range want {
		if events[i].ID != id {
			t.Errorf("events[%d].ID = %q, want %q", i, events[i].ID, id)
		}
	}
}
