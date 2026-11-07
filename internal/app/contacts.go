package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/tui"
)

// Errors returned to the interface. Their text is shown to the user.
var (
	ErrInvalidID       = errors.New("that is not a valid qchat ID")
	ErrOwnID           = errors.New("that is your own ID")
	ErrNotContact      = errors.New("not in your contacts")
	ErrUnknownIdentity = errors.New("no identity with this ID is registered on this server")
	ErrBadKey          = errors.New("the server returned a key that does not belong to this ID")
	ErrOffline         = errors.New("not connected to the server")
)

// parseContactID parses an ID coming from the interface.
func parseContactID(s string) (identity.ID, error) {
	id, err := identity.ParseID(s)
	if err != nil {
		return identity.ID{}, ErrInvalidID
	}
	return id, nil
}

// getContact returns the stored contact, or ErrNotContact.
func (a *App) getContact(ctx context.Context, id identity.ID) (clientdb.Contact, error) {
	c, err := a.prof.DB.GetContact(ctx, id)
	if errors.Is(err, clientdb.ErrNotFound) {
		return clientdb.Contact{}, ErrNotContact
	}
	return c, err
}

// fetchBundle asks the relay for the bundle of id and verifies that it
// belongs to id.
func (a *App) fetchBundle(ctx context.Context, id identity.ID) (*identity.Bundle, error) {
	sess := a.session()
	if sess == nil {
		return nil, ErrOffline
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	frame, err := sess.Request(ctx, protocol.TypeKeyRequest, protocol.KeyRequest{ID: id[:]})
	var remote *client.RemoteError
	switch {
	case errors.As(err, &remote) && remote.Code == protocol.ErrCodeNotFound:
		return nil, ErrUnknownIdentity
	case errors.Is(err, client.ErrNotConnected):
		return nil, ErrOffline
	case err != nil:
		return nil, err
	}
	resp, err := protocol.DecodeBody[protocol.KeyResponse](frame, protocol.TypeKeyResponse)
	if err != nil {
		return nil, fmt.Errorf("unexpected answer from the server: %w", err)
	}
	b, err := identity.ParseBundleForID(resp.Bundle, id)
	if err != nil {
		return nil, ErrBadKey
	}
	return b, nil
}

// Contacts returns every contact, sorted by display name.
func (a *App) Contacts() ([]tui.ContactInfo, error) {
	list, err := a.prof.DB.ListContacts(context.Background())
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]tui.ContactInfo, 0, len(list))
	for _, c := range list {
		out = append(out, a.contactInfoLocked(c))
	}
	return out, nil
}

func (a *App) contactInfoLocked(c clientdb.Contact) tui.ContactInfo {
	id := identity.ID(c.ID)
	return tui.ContactInfo{
		ID:          canonicalID(id),
		ShortID:     id.ShortString(),
		DisplayName: shownName(c),
		Verified:    c.Verified,
		KeyChanged:  !c.KeyChangedAt.IsZero(),
		Unread:      a.unread[id],
	}
}

// AddContact fetches the bundle for id from the relay and stores the
// contact. For an existing contact it refreshes the bundle and, when
// displayName is not empty, renames the contact. Pending message requests
// from id are persisted.
func (a *App) AddContact(ctx context.Context, idText, displayName string) (tui.ContactInfo, error) {
	id, err := parseContactID(idText)
	if err != nil {
		return tui.ContactInfo{}, err
	}
	if id == a.prof.Identity.ID() {
		return tui.ContactInfo{}, ErrOwnID
	}
	if err := validateName(displayName); err != nil {
		return tui.ContactInfo{}, err
	}
	fresh, err := a.fetchBundle(ctx, id)
	if err != nil {
		return tui.ContactInfo{}, err
	}

	info, keyChanged, err := a.storeContact(id, displayName, fresh)
	if err != nil {
		return tui.ContactInfo{}, err
	}
	if keyChanged {
		a.emit(tui.ContactKeyChanged{ContactID: info.ID})
	}
	return info, nil
}

// storeContact inserts or refreshes the contact id with a bundle fresh from
// the relay and persists its pending message requests. It reports whether
// the contact's encryption key changed.
func (a *App) storeContact(id identity.ID, displayName string, fresh *identity.Bundle) (tui.ContactInfo, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx := context.Background()
	now := a.now()
	c, err := a.getContact(ctx, id)
	keyChanged := false
	switch {
	case errors.Is(err, ErrNotContact):
		c = clientdb.Contact{ID: id, DisplayName: storedName(id, displayName), Bundle: fresh.Raw, BundleSerial: fresh.Serial, AddedAt: now}
	case err != nil:
		return tui.ContactInfo{}, false, err
	default:
		if displayName != "" {
			c.DisplayName = displayName
		}
		keyChanged = applyBundle(&c, fresh, now)
	}
	if err := a.prof.DB.PutContact(ctx, c); err != nil {
		return tui.ContactInfo{}, false, err
	}
	if err := a.persistRequestsLocked(ctx, id); err != nil {
		return tui.ContactInfo{}, false, err
	}
	return a.contactInfoLocked(c), keyChanged, nil
}

// applyBundle replaces the stored bundle of c with fresh if fresh is newer
// and reports whether the encryption key changed. Bundles with an equal or
// lower serial are ignored: a legitimate key rotation always raises it.
func applyBundle(c *clientdb.Contact, fresh *identity.Bundle, now time.Time) bool {
	if bytes.Equal(c.Bundle, fresh.Raw) || fresh.Serial <= c.BundleSerial {
		return false
	}
	changed := true
	if stored, err := identity.ParseBundleForID(c.Bundle, c.ID); err == nil {
		changed = !stored.KEMKey.Equal(fresh.KEMKey)
	}
	c.Bundle, c.BundleSerial = fresh.Raw, fresh.Serial
	if changed {
		c.KeyChangedAt = now
		c.Verified, c.VerifiedAt = false, time.Time{}
	}
	return changed
}

// validateName checks a display name from the interface; empty means none.
func validateName(name string) error {
	if name == "" {
		return nil
	}
	return clientdb.ValidateDisplayName(name)
}

// storedName returns the name to store for a contact. The database
// requires a name, so "no name" is stored as the contact's short ID and
// reported back as empty by shownName.
func storedName(id identity.ID, name string) string {
	if name == "" {
		return id.ShortString()
	}
	return name
}

// shownName returns the display name of c, or "" if it has none.
func shownName(c clientdb.Contact) string {
	if c.DisplayName == identity.ID(c.ID).ShortString() {
		return ""
	}
	return c.DisplayName
}

// RenameContact changes the local display name of a contact.
func (a *App) RenameContact(contactID, displayName string) error {
	id, err := parseContactID(contactID)
	if err != nil {
		return err
	}
	if err := validateName(displayName); err != nil {
		return err
	}
	return a.updateContact(id, func(c *clientdb.Contact) { c.DisplayName = storedName(id, displayName) })
}

// RemoveContact deletes a contact and its messages.
func (a *App) RemoveContact(contactID string) error {
	id, err := parseContactID(contactID)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	err = a.prof.DB.DeleteContact(context.Background(), id)
	if errors.Is(err, clientdb.ErrNotFound) {
		return ErrNotContact
	}
	if err != nil {
		return err
	}
	delete(a.unread, id)
	return nil
}

// Verification returns the safety number shared with a contact.
func (a *App) Verification(contactID string) (tui.VerificationInfo, error) {
	id, err := parseContactID(contactID)
	if err != nil {
		return tui.VerificationInfo{}, err
	}
	c, err := a.getContact(context.Background(), id)
	if err != nil {
		return tui.VerificationInfo{}, err
	}
	theirs, err := identity.ParseBundleForID(c.Bundle, id)
	if err != nil {
		return tui.VerificationInfo{}, fmt.Errorf("stored key of this contact is invalid: %w", err)
	}
	return tui.VerificationInfo{
		SafetyNumber: identity.SafetyNumber(a.self, theirs),
		QRPayload:    identity.SafetyQR(a.self, theirs),
		Verified:     c.Verified,
		KeyChanged:   !c.KeyChangedAt.IsZero(),
	}, nil
}

// MarkVerified records the user's verification decision and clears the
// key-changed flag.
func (a *App) MarkVerified(contactID string, verified bool) error {
	id, err := parseContactID(contactID)
	if err != nil {
		return err
	}
	now := a.now()
	return a.updateContact(id, func(c *clientdb.Contact) {
		c.Verified, c.VerifiedAt, c.KeyChangedAt = verified, time.Time{}, time.Time{}
		if verified {
			c.VerifiedAt = now
		}
	})
}

// MarkRead resets the unread count of a contact or group.
func (a *App) MarkRead(contactID string) error {
	if isGroupKey(contactID) {
		return a.markGroupRead(contactID)
	}
	id, err := parseContactID(contactID)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.unread, id)
	return nil
}

func (a *App) updateContact(id identity.ID, change func(*clientdb.Contact)) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx := context.Background()
	c, err := a.getContact(ctx, id)
	if err != nil {
		return err
	}
	change(&c)
	return a.prof.DB.PutContact(ctx, c)
}
