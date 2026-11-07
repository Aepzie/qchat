package tui

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Identity ID format: "qc1-" followed by 52 lowercase base32 characters.
const (
	idPrefix     = "qc1-"
	idChars      = 52
	idGroup      = 4
	maxNameRunes = 64
)

// convKind distinguishes the pseudo-conversations from contacts.
type convKind uint8

const (
	convSystem convKind = iota
	convRequests
	convContact
	convGroup
)

// Keys of the pseudo-conversations. They start with a NUL byte, which no
// identity ID contains.
const (
	systemKey   = "\x00system"
	requestsKey = "\x00requests"
)

// conversation is one entry of the sidebar with its history.
type conversation struct {
	key     string
	kind    convKind
	contact ContactInfo
	group   GroupInfo
	unread  int
	entries []entry
	// loaded reports that the stored history was fetched; loading that a
	// fetch is in flight.
	loaded, loading bool
	// senders lists the distinct unknown senders of a message-requests
	// conversation, oldest first.
	senders []string
}

// title is the name shown in the sidebar and header.
func (c *conversation) title() string {
	switch c.kind {
	case convSystem:
		return "System"
	case convRequests:
		return "Message requests"
	case convGroup:
		return "# " + c.group.Name
	}
	return c.contact.label()
}

// label is the display name, or the short ID when there is none.
func (c ContactInfo) label() string {
	if c.DisplayName != "" {
		return c.DisplayName
	}
	return c.ShortID
}

// cleanLine sanitises untrusted single-line text: everything sanitizeText
// removes, plus line breaks, collapsed whitespace and a rune limit.
func cleanLine(s string, maxRunes int) string {
	s = strings.Join(strings.Fields(sanitizeText(s)), " ")
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	return string([]rune(s)[:maxRunes])
}

// cleanContact sanitises every string of a contact.
func cleanContact(c ContactInfo) ContactInfo {
	c.ID = cleanLine(c.ID, 128)
	c.ShortID = cleanLine(c.ShortID, 32)
	if c.ShortID == "" {
		c.ShortID = shortID(c.ID)
	}
	c.DisplayName = cleanLine(c.DisplayName, maxNameRunes)
	c.Unread = max(c.Unread, 0)
	return c
}

// cleanSelf sanitises the local identity description.
func cleanSelf(s SelfInfo) SelfInfo {
	s.DisplayName = cleanLine(s.DisplayName, maxNameRunes)
	s.ID = cleanLine(s.ID, 128)
	s.ShortID = cleanLine(s.ShortID, 32)
	if s.ShortID == "" {
		s.ShortID = shortID(s.ID)
	}
	return s
}

// shortID abbreviates a full ID to its prefix and first two groups.
func shortID(id string) string {
	body, ok := strings.CutPrefix(id, idPrefix)
	if !ok || len(body) < 2*idGroup {
		return truncate(id, 16)
	}
	return idPrefix + body[:idGroup] + "-" + body[idGroup:2*idGroup]
}

// groupID writes an ID as its prefix followed by space-separated groups of
// four, the form people read aloud and compare.
func groupID(id string) string {
	body, ok := strings.CutPrefix(id, idPrefix)
	if !ok {
		return id
	}
	var groups []string
	for i := 0; i < len(body); i += idGroup {
		groups = append(groups, body[i:min(i+idGroup, len(body))])
	}
	return idPrefix + strings.Join(groups, " ")
}

// errAddUsage is returned by parseAddArgs when no ID was given.
var errAddUsage = errors.New("usage: /add <qc1-id> [name]")

// parseAddArgs parses the arguments of /add: an identity ID, optionally
// written in groups separated by dashes or spaces, followed by an optional
// display name. It returns the ID in canonical form.
func parseAddArgs(args []string) (string, string, error) {
	if len(args) == 0 {
		return "", "", errAddUsage
	}
	first := strings.ToLower(args[0])
	rest, ok := strings.CutPrefix(first, idPrefix)
	if !ok {
		return "", "", fmt.Errorf("qchat IDs start with %s; %q does not", idPrefix, truncate(args[0], 24))
	}
	body := strings.ReplaceAll(rest, "-", "")
	used := 1
	for len(body) < idChars && used < len(args) {
		group := strings.ToLower(strings.ReplaceAll(args[used], "-", ""))
		if len(group) != idGroup || !isBase32(group) {
			break
		}
		body += group
		used++
	}
	for _, r := range body {
		if !isBase32Rune(r) {
			return "", "", fmt.Errorf("qchat IDs contain only letters and the digits 2 to 7; %q is not allowed", string(r))
		}
	}
	if len(body) != idChars {
		return "", "", fmt.Errorf("a qchat ID has %d characters after %s; this one has %d", idChars, idPrefix, len(body))
	}
	name := cleanLine(strings.Join(args[used:], " "), maxNameRunes)
	return idPrefix + body, name, nil
}

func isBase32(s string) bool {
	for _, r := range s {
		if !isBase32Rune(r) {
			return false
		}
	}
	return true
}

func isBase32Rune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '2' && r <= '7')
}
