package server

import (
	"bytes"
	"reflect"
	"testing"
)

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("listen = \"127.0.0.1:9000\"\ntls_cert = \"a.crt\"\ntls_key = \"b.key\"\n"))
	f.Add([]byte(`
listen = "[::]:8443"
tls_cert = "a.crt"
tls_key  = "b.key"
database = "state/q.db"
registration = "open"
undelivered_ttl = "48h"
[limits]
max_frame_size = 65536
max_message_size = 4096
frames_per_second = 2.5
burst = 7
handshake_timeout = "1500ms"
ping_interval = "1m"
[log]
level = "debug"
`))
	f.Add([]byte("[limits]\nframes_per_second = nan\n"))
	f.Add([]byte("unknown = 1\n"))
	f.Fuzz(func(t *testing.T, content []byte) {
		cfg, err := ParseConfig(content)
		if err != nil {
			return
		}
		if cfg.Validate() != nil {
			return
		}
		var buf bytes.Buffer
		if err := cfg.WriteTOML(&buf); err != nil {
			t.Fatalf("WriteTOML of a valid config: %v", err)
		}
		again, err := ParseConfig(buf.Bytes())
		if err != nil {
			t.Fatalf("re-parse of a valid config: %v\n%s", err, buf.String())
		}
		if err := again.Validate(); err != nil {
			t.Fatalf("re-parsed config no longer valid: %v", err)
		}
		if !reflect.DeepEqual(again, cfg) {
			t.Fatalf("round trip = %+v, want %+v", again, cfg)
		}
	})
}
