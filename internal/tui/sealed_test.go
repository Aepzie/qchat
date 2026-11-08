package tui

import (
	"strings"
	"testing"
)

func TestStatusBarShowsSealedSender(t *testing.T) {
	m := connected(t, newTestModel(t, 140, 30))
	top := func() string { return strings.SplitN(screen(m), "\n", 2)[0] }
	if strings.Contains(top(), "sealed") {
		t.Fatalf("sealed shown before the anonymous connection is up: %q", top())
	}
	m = update(t, m, chatEventMsg{SealedSenderChanged{Connected: true}})
	if !strings.Contains(top(), "sealed") {
		t.Fatalf("status bar %q lacks sealed", top())
	}
	m = update(t, m, chatEventMsg{SealedSenderChanged{Connected: false}})
	if strings.Contains(top(), "sealed") {
		t.Fatalf("sealed still shown after the anonymous connection dropped: %q", top())
	}
}

func TestMessageMetaShowsSendRoute(t *testing.T) {
	st := newStyles(DefaultTheme())
	cases := []struct {
		route       SendRoute
		long, short string
	}{
		{RouteSealed, "✓ sent sealed", "✓ sealed"},
		{RouteIdentified, "✓ sent identified", "✓ identified"},
		{RouteUnknown, "✓ sent · stored by relay", "✓ sent"},
	}
	for _, tc := range cases {
		meta := messageMeta(entry{kind: entryMessage, outgoing: true, status: StatusSent, route: tc.route}, st)
		if len(meta) != 2 {
			t.Fatalf("route %d: meta %q", tc.route, meta)
		}
		if long, short := stripANSI(meta[0]), stripANSI(meta[1]); !strings.Contains(long, tc.long) || short != tc.short {
			t.Errorf("route %d: meta %q / %q, want %q / %q", tc.route, long, short, tc.long, tc.short)
		}
	}
	e := messageEntry(MessageInfo{ID: "m1", Outgoing: true, Status: StatusSent, Route: RouteSealed}, "Alice")
	if e.route != RouteSealed {
		t.Errorf("messageEntry dropped the route: %+v", e)
	}
}
