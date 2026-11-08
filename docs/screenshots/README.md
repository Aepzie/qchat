# Screenshots

The SVG images in this directory are rendered from the real terminal interface (`internal/tui`) by the generator in [`tools/screenshots`](../../tools/screenshots). They are used by the [README](../../README.md).

## Regenerating

From the repository root:

```sh
go run ./tools/screenshots
```

This rewrites every `*.svg` file here. Useful flags:

- `-only <name>` renders a single screenshot, for example `-only verify`.
- `-out <dir>` writes the images to another directory.
- `-ansi <dir>` also writes the raw ANSI capture of each screen (`<name>.ans`), which can be printed with `cat` in a terminal.

The generator needs no network access and no profile. It drives the interface with an in-memory demo backend, a fixed clock and animations off (except for the start screen, which is captured at its last frame), so the output only changes when the interface or the demo data change.

## How the images are made

1. The generator implements `tui.Backend` and its optional interfaces (settings, search, files, timers) with fictional data, starts `tui.New`, sends a window size, connection events and chat events, and types keys and commands such as `/verify`, `/search` and `/help`, exactly as a user would.
2. It captures `View()` as ANSI text.
3. Its own ANSI-to-SVG renderer parses the SGR colors and attributes (truecolor, 256-color, the 16 basic colors, bold, italic, underline), measures every character with the same width functions as the interface, and draws a terminal window. Text runs are stretched to whole cells so columns line up in any monospace font; box-drawing and block characters, including the QR codes, are drawn as shapes so borders join and QR modules stay square.

## Content

Everything shown is made up: the people (Robin, Mara, Jonas, Lena, Theo), the group "Team Nordlicht", the relay `relay.nordlicht.example`, the server pin and every message. The `qc1-…` IDs are well-formed but derived from fixed seeds; they belong to no real identity, and the safety numbers and QR codes are computed from made-up keys.
