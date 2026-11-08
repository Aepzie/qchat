package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeFileBackend adds files and timers to fakeBackend.
type fakeFileBackend struct {
	*fakeBackend
	sentFiles []string
	saved     []string
	timers    map[string]time.Duration
	saveErr   error
}

func newFakeFileBackend() *fakeFileBackend {
	return &fakeFileBackend{fakeBackend: newFakeBackend(), timers: map[string]time.Duration{}}
}

func (f *fakeFileBackend) SendFile(_ context.Context, id, path string) (MessageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sentFiles = append(f.sentFiles, id+"|"+path)
	return MessageInfo{ID: "f1", Outgoing: true, Text: "report.pdf", Sent: testClock, Status: StatusSent,
		File: &FileInfo{Name: "report.pdf", Size: 3 << 20, State: FileSending, Total: 64}}, nil
}

func (f *fakeFileBackend) SaveFile(_ context.Context, id, msgID, dir string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved = append(f.saved, id+"|"+msgID+"|"+dir)
	if f.saveErr != nil {
		return "", f.saveErr
	}
	return dir + "/report.pdf", nil
}

func (f *fakeFileBackend) SetTimer(_ context.Context, id string, d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.timers[id] = d
	return nil
}

func (f *fakeFileBackend) Timer(id string) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.timers[id], nil
}

func TestSendFileShowsProgress(t *testing.T) {
	fb := newFakeFileBackend()
	m := newChatModel(t, fb, 100, 24)
	m = do(t, m, keyCtrlN)
	m = typeText(t, m, "/send ~/docs/report.pdf")
	m, cmd := updateCmd(t, m, keyEnter)
	if s := screen(m); !strings.Contains(s, "report.pdf") || !strings.Contains(s, "sending") {
		t.Fatalf("no sending entry:\n%s", s)
	}
	m = drain(t, m, cmd)
	if len(fb.sentFiles) != 1 || !strings.HasPrefix(fb.sentFiles[0], aliceID+"|") || strings.Contains(fb.sentFiles[0], "~") {
		t.Fatalf("SendFile calls %q", fb.sentFiles)
	}
	m = do(t, m, chatEventMsg{FileChanged{ConversationID: aliceID, MessageID: "f1", File: FileInfo{Name: "report.pdf", Size: 3 << 20, State: FileSending, Done: 16, Total: 64}}})
	if s := screen(m); !strings.Contains(s, "📄 report.pdf") || !strings.Contains(s, "file 1 · 3.0 MiB · sending 16/64") || !strings.Contains(s, "25%") {
		t.Fatalf("progress not shown:\n%s", s)
	}
	m = do(t, m, chatEventMsg{FileChanged{ConversationID: aliceID, MessageID: "f1", File: FileInfo{Name: "report.pdf", Size: 3 << 20, State: FileComplete, Done: 64, Total: 64}}})
	if s := screen(m); !strings.Contains(s, "file 1 · 3.0 MiB · done") || !strings.Contains(s, "/save 1") || !strings.Contains(s, "100%") {
		t.Fatalf("completion not shown:\n%s", s)
	}
	m = say(t, m, "/file")
	if s := screen(m); !strings.Contains(s, "usage: /file <path>") {
		t.Errorf("no usage for an empty /file:\n%s", s)
	}
}

func TestIncomingFileAndSave(t *testing.T) {
	fb := newFakeFileBackend()
	m := newChatModel(t, fb, 120, 30)
	m = do(t, m, keyCtrlN)
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: aliceID, Message: MessageInfo{ID: "o1", Text: "x", Received: testClock,
		File: &FileInfo{Name: "evil\x1b[2J\u202Ename.txt", Size: 1536, State: FileReceiving, Done: 1, Total: 4}}}})
	s := screen(m)
	if !strings.Contains(s, "📄 evil[2Jname.txt") || !strings.Contains(s, "file 1 · 1.5 KiB · receiving 1/4") {
		t.Fatalf("incoming file not shown:\n%s", s)
	}
	if strings.Contains(m.View().Content, "\x1b[2J") || strings.Contains(m.View().Content, "\u202E") {
		t.Fatal("control characters from the file name reached the terminal")
	}
	m = say(t, m, "/save")
	if s := screen(m); !strings.Contains(s, "files") || !strings.Contains(s, "receiving 1/4") {
		t.Fatalf("/save does not list files:\n%s", s)
	}
	m = say(t, m, "/save 2")
	if s := screen(m); !strings.Contains(s, "No file 2 here") {
		t.Fatalf("bad number accepted:\n%s", s)
	}
	m = say(t, m, `/save 1 "C:\My Files"`)
	if len(fb.saved) != 1 || fb.saved[0] != aliceID+`|o1|C:\My Files` {
		t.Fatalf("SaveFile calls %q", fb.saved)
	}
	if s := screen(m); !strings.Contains(s, "Saved") || !strings.Contains(s, "not encrypted") {
		t.Fatalf("no confirmation:\n%s", s)
	}
	fb.saveErr = errors.New("this file has not arrived completely")
	m = say(t, m, "/save 1")
	if s := screen(m); !strings.Contains(s, "Cannot save") || !strings.Contains(s, "has not arrived completely") {
		t.Fatalf("no error:\n%s", s)
	}
	if fb.saved[1] != aliceID+"|o1|" {
		t.Errorf("default directory not left to the backend: %q", fb.saved[1])
	}
}

func TestExpiredMessagesAreRemoved(t *testing.T) {
	fb := newFakeFileBackend()
	m := newChatModel(t, fb, 100, 24)
	m = do(t, m, keyCtrlN)
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: aliceID, Message: MessageInfo{ID: "gone1", Text: "self destructing", Received: testClock}}})
	m = do(t, m, chatEventMsg{IncomingMessage{ContactID: aliceID, Message: MessageInfo{ID: "kept1", Text: "still here", Received: testClock}}})
	if !strings.Contains(screen(m), "self destructing") {
		t.Fatal("message not shown")
	}
	m = do(t, m, chatEventMsg{MessagesExpired{ConversationID: aliceID, MessageIDs: []string{"gone1", "h1"}}})
	s := screen(m)
	if strings.Contains(s, "self destructing") || strings.Contains(s, "hi, it's Alice") {
		t.Fatalf("expired messages still shown:\n%s", s)
	}
	if !strings.Contains(s, "still here") {
		t.Fatalf("unexpired message removed:\n%s", s)
	}
}

func TestTimerCommand(t *testing.T) {
	fb := newFakeFileBackend()
	m := newChatModel(t, fb, 120, 30)
	m = do(t, m, keyCtrlN)
	m = say(t, m, "/timer")
	if s := screen(m); !strings.Contains(s, "Disappearing messages are off") {
		t.Fatalf("current timer not shown:\n%s", s)
	}
	m = say(t, m, "/timer 5m")
	if fb.timers[aliceID] != 5*time.Minute {
		t.Fatalf("timer %v", fb.timers[aliceID])
	}
	if s := screen(m); !strings.Contains(s, "You set disappearing messages to 5m") {
		t.Fatalf("no confirmation:\n%s", s)
	}
	m = say(t, m, "/timer soon")
	if s := screen(m); !strings.Contains(s, "usage: /timer") {
		t.Fatalf("bad timer accepted:\n%s", s)
	}
	m = say(t, m, "/timer off")
	if d, ok := fb.timers[aliceID]; !ok || d != 0 {
		t.Fatalf("timer not turned off: %v", d)
	}
	m = do(t, m, chatEventMsg{ConversationNotice{ConversationID: aliceID, Notice: "Alice set disappearing messages to 1h.\x1b[31m"}})
	s := screen(m)
	if !strings.Contains(s, "Alice set disappearing messages to 1h.") || strings.Contains(m.View().Content, "\x1b[31m") {
		t.Fatalf("notice not shown safely:\n%s", s)
	}
	m = do(t, m, keyCtrlP)
	m = say(t, m, "/timer 1h")
	if s := screen(m); !strings.Contains(s, "Open a contact or group first") {
		t.Fatalf("/timer in System accepted:\n%s", s)
	}
}

func TestParseAndFormatTimer(t *testing.T) {
	for in, want := range map[string]time.Duration{"off": 0, "0": 0, "30s": 30 * time.Second, "5m": 5 * time.Minute, "1h": time.Hour, "1d": 24 * time.Hour, "1W": 7 * 24 * time.Hour} {
		got, ok := parseTimer(in)
		if !ok || got != want {
			t.Errorf("parseTimer(%q) = %v, %v", in, got, ok)
		}
		if in != "0" && in != "1W" && formatTimer(got) != in {
			t.Errorf("formatTimer(%v) = %q", got, formatTimer(got))
		}
	}
	for _, in := range []string{"", "5", "m", "-5m", "5y", "1.5h", "99999d"} {
		if _, ok := parseTimer(in); ok {
			t.Errorf("parseTimer(%q) accepted", in)
		}
	}
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 3 << 20: "3.0 MiB", 64 << 20: "64.0 MiB"} {
		if got := formatSize(n); got != want {
			t.Errorf("formatSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestFilesWithoutFileBackend(t *testing.T) {
	m := newChatModel(t, newFakeBackend(), 100, 24)
	m = do(t, m, keyCtrlN)
	m = say(t, m, "/send x.txt")
	if s := screen(m); !strings.Contains(s, "Sending files is not available") {
		t.Fatalf("no explanation:\n%s", s)
	}
	m = say(t, m, "/timer 5m")
	if s := screen(m); !strings.Contains(s, "Disappearing messages are not available") {
		t.Fatalf("no explanation:\n%s", s)
	}
}
