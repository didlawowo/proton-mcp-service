package proton

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func TestNewCalendarUID(t *testing.T) {
	u1, err := newCalendarUID()
	if err != nil {
		t.Fatalf("newCalendarUID: %v", err)
	}
	u2, err := newCalendarUID()
	if err != nil {
		t.Fatalf("newCalendarUID: %v", err)
	}
	if !strings.HasSuffix(u1, "@proton.me") {
		t.Errorf("UID %q should end with @proton.me", u1)
	}
	if len(u1) != len("AAAAAAAAAAAAAAAAAAAAAAAAAAAA@proton.me") {
		t.Errorf("UID %q has length %d, want 28+@proton.me", u1, len(u1))
	}
	if u1 == u2 {
		t.Error("two generated UIDs should differ")
	}
	if strings.Contains(u1, "=") || strings.Contains(u1, "+") || strings.Contains(u1, "/") {
		t.Errorf("UID %q should be base64url without padding", u1)
	}
}

func TestIcsEscape(t *testing.T) {
	got := icsEscape("a,b;c\\d\ne\nf")
	if got != "a\\,b\\;c\\\\d\\ne\\nf" {
		t.Errorf("icsEscape() = %q", got)
	}
}

func TestIcsDateProperty(t *testing.T) {
	ts := time.Date(2026, 8, 9, 14, 30, 0, 0, time.UTC).Unix()

	if got := icsDateProperty("DTSTART", ts, "", false); got != "DTSTART:20260809T143000Z" {
		t.Errorf("UTC timed = %q", got)
	}
	if got := icsDateProperty("DTSTART", ts, "Europe/Paris", false); got != "DTSTART;TZID=Europe/Paris:20260809T163000" {
		t.Errorf("TZID timed = %q", got)
	}
	if got := icsDateProperty("DTEND", ts, "", true); got != "DTEND;VALUE=DATE:20260809" {
		t.Errorf("full day = %q", got)
	}
	// Full-day date is derived in the event's timezone: 23:30 UTC is already the
	// next day in Europe/Paris (UTC+2 in summer).
	lateTs := time.Date(2026, 8, 9, 23, 30, 0, 0, time.UTC).Unix()
	if got := icsDateProperty("DTSTART", lateTs, "Europe/Paris", true); got != "DTSTART;VALUE=DATE:20260810" {
		t.Errorf("full day tz-aware = %q, want DTSTART;VALUE=DATE:20260810", got)
	}
}

func TestBuildVEVENTsShareUID(t *testing.T) {
	now := time.Now().UTC()
	req := CreateCalendarEventRequest{
		Summary:     "RDV dentiste",
		Description: "Nettoyage",
		Location:    "Clinique",
		StartTime:   now.Add(time.Hour).Unix(),
		EndTime:     now.Add(2 * time.Hour).Unix(),
		Timezone:    "Europe/Paris",
		FullDay:     false,
	}
	uid, err := newCalendarUID()
	if err != nil {
		t.Fatalf("newCalendarUID: %v", err)
	}
	signed := buildSignedVEVENT(uid, now, req)
	encrypted := buildEncryptedVEVENT(uid, now, req)

	for name, v := range map[string]string{"signed": signed, "encrypted": encrypted} {
		if !strings.HasPrefix(v, "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:"+prodID) {
			t.Errorf("%s card not a well-formed VCALENDAR: %q", name, v)
		}
		if !strings.Contains(v, "UID:"+uid) {
			t.Errorf("%s card missing shared UID", name)
		}
	}
	if !strings.Contains(signed, "DTSTART") || !strings.Contains(signed, "DTEND") {
		t.Error("signed card should carry the timing properties")
	}
	if !strings.Contains(encrypted, "SUMMARY:RDV dentiste") {
		t.Error("encrypted card should carry the summary")
	}
	if strings.Contains(signed, "SUMMARY") {
		t.Error("signed card should not carry the summary")
	}
	if strings.Contains(signed, "DESCRIPTION") || strings.Contains(signed, "LOCATION") {
		t.Error("signed card should not carry content properties")
	}
}

func TestEncryptCardRoundTrip(t *testing.T) {
	calKey, err := crypto.GenerateKey("cal", "cal@proton.me", "rsa", 2048)
	if err != nil {
		t.Fatalf("generate calendar key: %v", err)
	}
	calKR, err := crypto.NewKeyRing(calKey)
	if err != nil {
		t.Fatalf("new calendar keyring: %v", err)
	}

	memberKey, err := crypto.GenerateKey("member", "member@proton.me", "rsa", 2048)
	if err != nil {
		t.Fatalf("generate member key: %v", err)
	}
	memberKR, err := crypto.NewKeyRing(memberKey)
	if err != nil {
		t.Fatalf("new member keyring: %v", err)
	}

	vevent := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:secret\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

	t.Run("signed clear card is not encrypted but verifies", func(t *testing.T) {
		part, err := encryptCard(vevent, memberKR, nil)
		if err != nil {
			t.Fatalf("encryptCard: %v", err)
		}
		if part.Type != eventTypeSigned {
			t.Errorf("type = %d, want %d", part.Type, eventTypeSigned)
		}
		if part.Data != vevent {
			t.Error("signed clear card should store the plaintext")
		}
		if err := verifyPartSignature(part, memberKR); err != nil {
			t.Errorf("signature verification failed: %v", err)
		}
	})

	t.Run("encrypted card decrypts and verifies", func(t *testing.T) {
		sk, err := crypto.GenerateSessionKey()
		if err != nil {
			t.Fatalf("generate session key: %v", err)
		}
		part, err := encryptCard(vevent, memberKR, sk)
		if err != nil {
			t.Fatalf("encryptCard: %v", err)
		}
		if part.Type != eventTypeEncryptedSigned {
			t.Errorf("type = %d, want %d", part.Type, eventTypeEncryptedSigned)
		}

		keyPacket, err := calKR.EncryptSessionKey(sk)
		if err != nil {
			t.Fatalf("encrypt session key: %v", err)
		}

		// Mirror the read path: split message = key packet + data packet,
		// then decrypt and verify against the decrypted plaintext.
		raw, err := base64.StdEncoding.DecodeString(part.Data)
		if err != nil {
			t.Fatalf("decode data packet: %v", err)
		}
		enc := crypto.NewPGPSplitMessage(keyPacket, raw).GetPGPMessage()
		dec, err := calKR.Decrypt(enc, nil, crypto.GetUnixTime())
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		// Text-mode OpenPGP normalizes CRLF to LF on decrypt (as the real read
		// path does); compare the decrypted payload accordingly.
		plaintext := dec.GetString()
		if plaintext != strings.ReplaceAll(vevent, "\r\n", "\n") {
			t.Errorf("decrypted card = %q, want normalized %q", plaintext, strings.ReplaceAll(vevent, "\r\n", "\n"))
		}

		// Verify the detached signature against the decrypted plaintext.
		sig, err := crypto.NewPGPSignatureFromArmored(part.Signature)
		if err != nil {
			t.Fatalf("parse signature: %v", err)
		}
		if err := memberKR.VerifyDetached(crypto.NewPlainMessageFromString(plaintext), sig, crypto.GetUnixTime()); err != nil {
			t.Errorf("signature verification failed: %v", err)
		}
	})
}

func TestCreateCalendarEventValidation(t *testing.T) {
	c := &Client{}
	if _, err := c.CreateCalendarEvent(t.Context(), "cal1", CreateCalendarEventRequest{}); err == nil {
		t.Error("create with empty times should fail (unauthenticated client)")
	}
}

// verifyPartSignature re-verifies the detached signature against the plaintext
// payload (for signed cards the payload is the card text itself).
func verifyPartSignature(part CalendarEventPart, addrKR *crypto.KeyRing) error {
	sig, err := crypto.NewPGPSignatureFromArmored(part.Signature)
	if err != nil {
		return err
	}
	plain := crypto.NewPlainMessageFromString(part.Data)
	return addrKR.VerifyDetached(plain, sig, crypto.GetUnixTime())
}
