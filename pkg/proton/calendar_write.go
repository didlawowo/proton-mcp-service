package proton

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Calendar event card types, mirroring Proton's card model (bitmask).
const (
	eventTypeSigned          = 2
	eventTypeEncryptedSigned = 3
)

// prodID identifies this service as the author of created events.
const prodID = "-//Proton AG//proton-service//EN"

// CreateCalendarEventRequest carries the plaintext fields of a new event.
type CreateCalendarEventRequest struct {
	Summary     string `json:"summary"`
	Description string `json:"description,omitempty"`
	Location    string `json:"location,omitempty"`
	// StartTime/EndTime are unix timestamps.
	StartTime int64  `json:"start_time"`
	EndTime   int64  `json:"end_time"`
	Timezone  string `json:"timezone,omitempty"` // IANA name, optional (UTC if empty)
	FullDay   bool   `json:"full_day,omitempty"`
}

// CalendarEventPart is one encrypted/signed card as the API stores it.
type CalendarEventPart struct {
	Type      int    `json:"Type"`
	Data      string `json:"Data"`
	Signature string `json:"Signature"`
}

// eventPayload is a single event inside the sync request.
type eventPayload struct {
	Permissions          int                 `json:"Permissions"`
	IsPersonalSingleEdit bool                `json:"IsPersonalSingleEdit"`
	SharedKeyPacket      string              `json:"SharedKeyPacket"`
	SharedEventContent   []CalendarEventPart `json:"SharedEventContent"`
	Notifications        any                 `json:"Notifications"`
	Color                any                 `json:"Color"`
}

// syncRequest is the body of PUT /calendar/v1/{id}/events/sync.
type syncRequest struct {
	MemberID string `json:"MemberID"`
	Events   []struct {
		Overwrite int          `json:"Overwrite"`
		Event     eventPayload `json:"Event"`
	} `json:"Events"`
}

type syncResponse struct {
	Responses []struct {
		Response struct {
			Code  int    `json:"Code"`
			Error string `json:"Error"`
			Event *struct {
				ID  string `json:"ID"`
				UID string `json:"UID"`
			} `json:"Event"`
		} `json:"Response"`
	} `json:"Responses"`
}

// CreateCalendarEvent creates an E2E-encrypted event in the given calendar.
// The event is split into a signed (clear timing) card and an encrypted
// (summary/description/location) card, following Proton's calendar protocol.
func (c *Client) CreateCalendarEvent(ctx context.Context, calendarID string, req CreateCalendarEventRequest) (*CalendarEventInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return nil, fmt.Errorf("not authenticated")
	}
	if calendarID == "" {
		return nil, fmt.Errorf("calendar ID is required")
	}
	if req.StartTime == 0 || req.EndTime == 0 {
		return nil, fmt.Errorf("start_time and end_time are required")
	}

	calKR, addrKR, memberID, err := c.calendarKeyRing(ctx, calendarID)
	if err != nil {
		return nil, err
	}

	sharedSK, err := crypto.GenerateSessionKey()
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	// Both cards share the same UID so Proton links them together.
	uid, err := newCalendarUID()
	if err != nil {
		return nil, fmt.Errorf("generate event UID: %w", err)
	}
	now := time.Now().UTC()

	// The signed (clear) card carries the timing data the server indexes on;
	// the encrypted card carries the sensitive content.
	signedVEVENT := buildSignedVEVENT(uid, now, req)
	encryptedVEVENT := buildEncryptedVEVENT(uid, now, req)

	signedCard, err := encryptCard(signedVEVENT, addrKR, nil)
	if err != nil {
		return nil, fmt.Errorf("sign shared card: %w", err)
	}
	encryptedCard, err := encryptCard(encryptedVEVENT, addrKR, sharedSK)
	if err != nil {
		return nil, fmt.Errorf("encrypt shared card: %w", err)
	}

	sharedKeyPacket, err := calKR.EncryptSessionKey(sharedSK)
	if err != nil {
		return nil, fmt.Errorf("encrypt shared session key: %w", err)
	}

	payload := syncRequest{MemberID: memberID}
	payload.Events = append(payload.Events, struct {
		Overwrite int          `json:"Overwrite"`
		Event     eventPayload `json:"Event"`
	}{
		Overwrite: 0,
		Event: eventPayload{
			Permissions:          1, // SEE
			IsPersonalSingleEdit: false,
			SharedKeyPacket:      base64.StdEncoding.EncodeToString(sharedKeyPacket),
			SharedEventContent:   []CalendarEventPart{signedCard, encryptedCard},
			Notifications:        nil,
			Color:                nil,
		},
	})

	var resp syncResponse
	if err := c.rawPut(ctx, "/calendar/v1/"+calendarID+"/events/sync", payload, &resp); err != nil {
		return nil, fmt.Errorf("create calendar event: %w", err)
	}

	if len(resp.Responses) == 0 {
		return nil, fmt.Errorf("create calendar event: empty sync response")
	}
	first := resp.Responses[0].Response
	if first.Error != "" || first.Event == nil {
		return nil, fmt.Errorf("create calendar event: %s (code %d)", first.Error, first.Code)
	}

	return &CalendarEventInfo{
		ID:         first.Event.ID,
		UID:        first.Event.UID,
		CalendarID: calendarID,
	}, nil
}

// deleteSyncRequest is the body of a delete operation on the events/sync
// endpoint (Proton has no direct HTTP DELETE for calendar events).
type deleteSyncRequest struct {
	MemberID string `json:"MemberID"`
	Events   []struct {
		ID             string `json:"ID"`
		DeletionReason int    `json:"DeletionReason"`
	} `json:"Events"`
}

// DeleteCalendarEvent removes an event from a calendar. Deletion goes through
// the events/sync endpoint (same as the web client) — Proton exposes no direct
// HTTP DELETE for calendar events.
func (c *Client) DeleteCalendarEvent(ctx context.Context, calendarID, eventID string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return fmt.Errorf("not authenticated")
	}
	if calendarID == "" || eventID == "" {
		return fmt.Errorf("calendar ID and event ID are required")
	}

	// The sync payload requires the member ID; fetch it (also raises the
	// elevated scope the calendar endpoints need).
	_, _, memberID, err := c.calendarKeyRing(ctx, calendarID)
	if err != nil {
		return err
	}

	payload := deleteSyncRequest{MemberID: memberID}
	payload.Events = append(payload.Events, struct {
		ID             string `json:"ID"`
		DeletionReason int    `json:"DeletionReason"`
	}{ID: eventID, DeletionReason: 0})

	var resp syncResponse
	if err := c.rawPut(ctx, "/calendar/v1/"+calendarID+"/events/sync", payload, &resp); err != nil {
		return fmt.Errorf("delete calendar event: %w", err)
	}
	// Proton returns Code 1001 ("success, no data") with an empty Responses
	// array for deletions — that is a success.
	if len(resp.Responses) > 0 {
		if first := resp.Responses[0].Response; first.Error != "" {
			return fmt.Errorf("delete calendar event: %s (code %d)", first.Error, first.Code)
		}
	}
	return nil
}

// buildSignedVEVENT serializes the shared "timing" card: UID, DTSTAMP, DTSTART
// and DTEND are signed but stored clear so the server can index the event.
func buildSignedVEVENT(uid string, now time.Time, req CreateCalendarEventRequest) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:" + prodID + "\r\nBEGIN:VEVENT\r\n")
	b.WriteString("UID:" + uid + "\r\n")
	b.WriteString("DTSTAMP:" + icsUTCDateTime(now) + "\r\n")
	b.WriteString(icsDateProperty("DTSTART", req.StartTime, req.Timezone, req.FullDay) + "\r\n")
	b.WriteString(icsDateProperty("DTEND", req.EndTime, req.Timezone, req.FullDay) + "\r\n")
	b.WriteString("END:VEVENT\r\nEND:VCALENDAR\r\n")
	return b.String()
}

// buildEncryptedVEVENT serializes the shared "content" card: the summary,
// description and location, which are encrypted with the session key.
func buildEncryptedVEVENT(uid string, now time.Time, req CreateCalendarEventRequest) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:" + prodID + "\r\nBEGIN:VEVENT\r\n")
	b.WriteString("UID:" + uid + "\r\n")
	b.WriteString("DTSTAMP:" + icsUTCDateTime(now) + "\r\n")
	b.WriteString("CREATED:" + icsUTCDateTime(now) + "\r\n")
	b.WriteString("SUMMARY:" + icsEscape(req.Summary) + "\r\n")
	if req.Description != "" {
		b.WriteString("DESCRIPTION:" + icsEscape(req.Description) + "\r\n")
	}
	if req.Location != "" {
		b.WriteString("LOCATION:" + icsEscape(req.Location) + "\r\n")
	}
	b.WriteString("END:VEVENT\r\nEND:VCALENDAR\r\n")
	return b.String()
}

// encryptCard signs (and optionally encrypts) a VEVENT card.
//   - with a nil session key, the card is stored clear and signed (Type 2);
//   - with a session key, it is encrypted with that key and signed (Type 3).
func encryptCard(vevent string, addrKR *crypto.KeyRing, sk *crypto.SessionKey) (CalendarEventPart, error) {
	plain := crypto.NewPlainMessageFromString(vevent)

	sig, err := addrKR.SignDetached(plain)
	if err != nil {
		return CalendarEventPart{}, err
	}
	armored, err := sig.GetArmored()
	if err != nil {
		return CalendarEventPart{}, err
	}

	part := CalendarEventPart{Signature: armored}
	if sk == nil {
		part.Type = eventTypeSigned
		part.Data = vevent
		return part, nil
	}

	dataPacket, err := sk.Encrypt(plain)
	if err != nil {
		return CalendarEventPart{}, err
	}
	part.Type = eventTypeEncryptedSigned
	part.Data = base64.StdEncoding.EncodeToString(dataPacket)
	return part, nil
}

// newCalendarUID returns a Proton-style UID: 21 random bytes in base64url
// (28 chars) followed by the @proton.me domain.
func newCalendarUID() (string, error) {
	s, err := generateRandomString(21)
	if err != nil {
		return "", err
	}
	return s + "@proton.me", nil
}

// generateRandomString returns the base64url (no padding) encoding of n random
// bytes.
func generateRandomString(n int) (string, error) {
	rb := make([]byte, n)
	if _, err := rand.Read(rb); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(rb), nil
}

// icsUTCDateTime formats a time as an iCalendar UTC datetime (YYYYMMDDTHHMMSSZ).
func icsUTCDateTime(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

// icsDateProperty serializes a DTSTART/DTEND property: date-only for full-day
// events, TZID-annotated for timezone events, UTC otherwise.
func icsDateProperty(name string, unix int64, tz string, fullDay bool) string {
	t := time.Unix(unix, 0)
	if fullDay {
		// Derive the calendar date in the event's timezone so a timestamp near
		// midnight does not land on the wrong day (UTC otherwise).
		d := t.UTC()
		if tz != "" {
			if loc, err := time.LoadLocation(tz); err == nil {
				d = t.In(loc)
			}
		}
		return name + ";VALUE=DATE:" + d.Format("20060102")
	}
	if tz != "" {
		loc, err := time.LoadLocation(tz)
		if err == nil {
			return name + ";TZID=" + tz + ":" + t.In(loc).Format("20060102T150405")
		}
	}
	return name + ":" + t.UTC().Format("20060102T150405Z")
}

// icsEscape escapes text for use in an iCalendar property value.
func icsEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, ";", "\\;")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "\r\n", "\\n")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}
