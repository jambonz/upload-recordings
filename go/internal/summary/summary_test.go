package summary

import (
	"testing"
	"time"
)

func TestStamp(t *testing.T) {
	audioStart := time.Date(2026, 4, 16, 18, 24, 45, 5e6, time.UTC) // 18:24:45.005
	cases := []struct{ name, in, want string }{
		{"appends, keeps order and number text",
			`{"z":1.50,"call_start":"2026-04-16T18:24:43.955Z","a":[1, 2]}`,
			`{"z":1.50,"call_start":"2026-04-16T18:24:43.955Z","a":[1,2],"recording_key":"k.wav","recording_started_at_ms":1050}`},
		{"replaces in place",
			`{"recording_key":"old","call_start":"2026-04-16T18:24:44Z"}`,
			`{"recording_key":"k.wav","call_start":"2026-04-16T18:24:44Z","recording_started_at_ms":1005}`},
		{"leading zero in fraction",
			`{"call_start":"2026-04-16T18:24:44.055Z"}`,
			`{"call_start":"2026-04-16T18:24:44.055Z","recording_key":"k.wav","recording_started_at_ms":950}`},
		{"short and long fractions",
			`{"call_start":"2026-04-16T18:24:44.5Z","x":"2026-04-16T18:24:44.123456Z"}`,
			`{"call_start":"2026-04-16T18:24:44.5Z","x":"2026-04-16T18:24:44.123456Z","recording_key":"k.wav","recording_started_at_ms":505}`},
		{"no call_start", `{"a":"b"}`, `{"a":"b","recording_key":"k.wav"}`},
		{"unparseable call_start", `{"call_start":"yesterday"}`, `{"call_start":"yesterday","recording_key":"k.wav"}`},
	}
	for _, c := range cases {
		got, err := Stamp([]byte(c.in), "k.wav", audioStart)
		if err != nil || string(got) != c.want {
			t.Errorf("%s:\n got %s (%v)\nwant %s", c.name, got, err, c.want)
		}
	}
	for _, bad := range []string{`[1]`, `null`, `{"a":`} {
		if _, err := Stamp([]byte(bad), "k", audioStart); err == nil {
			t.Errorf("%s: expected an error", bad)
		}
	}
}
