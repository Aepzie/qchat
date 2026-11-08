# TUI redesign: tabs, neon themes, animation

Goal: a striking, modern terminal UI. Everything stays in `internal/tui`
(Bubble Tea v2, Lip Gloss v2); the `Backend` interfaces do not change.

## Visual direction

- Default theme **"neon"**: near-black background, electric accents
  (magenta `#ff2bd6`, cyan `#00e5ff`, violet `#8a5cff`, lime `#b6ff3b` for
  success, amber `#ffb020` warnings, hot red `#ff3355` danger). Additional
  bold themes: **"synthwave"** (purple/orange sunset), **"matrix"** (green on
  black), **"ice"** (blue/white), plus the existing calm themes kept.
- **Gradients**: tab bar underline, header title, panel borders and the
  splash logo use horizontal colour gradients (interpolate per rune with
  `lipgloss` colours; a `Theme.Gradient []color.Color` field).
- Rounded heavy borders around panels; the focused panel has a glowing
  (accent) border, unfocused panels a dim one.
- Unicode glyphs: `◆ ◇ ● ○ ◉ ✦ ✧ ⚡ 🔒 ⇄ ▸ ▾ ━ ┃ ╭ ╮ ╰ ╯ ░ ▒ ▓ █`.

## Layout

```
╭─ ⚡ qchat ─────── [1 Chats ●3] [2 Requests ✦2] [3 Groups] [4 Contacts] [5 Files] [6 System] ─ 🔒 PQ · sealed · Tor:off · 12ms ╮
│ ┃ CHATS              │  ◉ Bob  ✓ verified · qc1-25ie-urlg      E2E · forward secrecy                │
│ ┃▸ (B) Bob        2  │ ─────────────── Today ───────────────                                         │
│ ┃  (C) Carol         │   ╭──────────────────────╮                                                     │
│ ┃  # Team         ●  │   │ hey Bob              │ 14:02 ✓ sealed                                    │
│ ┃                    │   ╰──────────────────────╯                                                     │
│ ┃                    │                         ╭─────────────────────────╮                            │
│ ┃                    │            (B) 14:03    │ hi! ready to test?      │                            │
│ ┃                    │                         ╰─────────────────────────╯                            │
│ ┣━━━━━━━━━━━━━━━━━━━━┫ ╭─ ✎ message Bob ─────────────────────────────────────────────────────────╮  │
│ ┃ ● online           │ │ ›                                                                      │  │
╰──────────────────────────────────────────────────────────────────────────────── INSERT · tab/1-6 ╯
```

- **Tab bar** (top): Chats (contacts with history), Requests (message
  requests from unknown senders and group invitations, with ✦ badge count
  and a pulsing badge while unseen), Groups, Contacts (all contacts with
  verified/key-changed state and quick actions), Files (all transfers with
  progress bars, `/save` from there), System (connection log, security info,
  fingerprint, sealed/Tor status). Switch with `1`–`6` in NORMAL mode,
  `alt+1`–`alt+6` anywhere, `ctrl+left/right` or `[`/`]` to cycle, mouse click
  on a tab.
- **Requests tab** shows each request as a card: sender short ID, first
  message preview, time, and actions `a` accept (adds contact with prompt
  for a name, same as `/add`), `d` dismiss, `v` view full; group invitations
  with `a` accept / `l` decline. A banner in Chats points to unseen requests.
- **Own messages right-aligned bubbles** in accent colour, peer messages
  left-aligned bubbles with a coloured avatar circle `(B)` (stable colour per
  contact from the ID hash), date separators, delivery icons (◌ sending,
  ✓ sent sealed, ✓ identified, ✓✓ delivered, ✕ failed) and a ⏱ marker for
  disappearing messages. File messages are cards with name, size and a
  gradient progress bar. Group messages show sender name in its colour.
- Security moments are loud: key change → red flashing banner (⚠ KEY
  CHANGED) until /verify; verified contact → lime ✓ badge in header.
- Input box: bordered, title shows target, glows when focused.
- Footer: mode pill (INSERT/NORMAL), contextual key hints.

## Animation

Driven by one `tea.Tick` at ~12 fps (`AnimInterval = 80 * time.Millisecond`)
that only runs while something animates (splash, spinners, pulsing badges,
new-message fade-in, flashing warning) to save CPU; no animation when the
terminal is small or `ui.animations` setting is `off` (`/animations on|off`).

- Splash on start: gradient ASCII logo "qchat" with a short scan-line reveal
  (≤ 1.2 s, any key skips).
- Connecting spinner in status bar (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`).
- New incoming message slides/fades in over ~5 frames (colour ramp from dim
  to full).
- Unread / request badges pulse (brightness cycle).
- Sending bubble shows a small spinner until the relay answers.

## Ownership (implementation)

- `theme.go`, `anim.go` (new), `splash.go` (new), `onboarding.go`: themes,
  gradient helpers, animation state & frames, splash, restyled
  onboarding/unlock cards.
- `model.go`, `view.go`, `tabs.go` (new), `requests.go` (new), `contacts.go`,
  `groups.go`, `chat.go`, `commands.go`, `overlay.go`, `help.go`: shell,
  tabs, requests, sidebar lists, status/footer, key handling, tick wiring.
- `history.go`, `bubble.go` (new), `files.go`: conversation rendering
  (bubbles, avatars, separators, file cards, banners).

Invariants that must hold: every rendered line fits the terminal width,
small-terminal fallback, all untrusted text sanitised, no terminal escape
injection, existing commands keep working.
