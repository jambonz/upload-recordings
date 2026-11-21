// Package summary stamps the session summary that feature-server sends at the
// end of a call before it is stored next to the recording as session.json.
package summary

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

type member struct {
	key   string
	value json.RawMessage
}

// Stamp sets recording_key and, when the summary carries a parseable
// call_start, recording_started_at_ms (how long after call_start the audio
// began). Existing members keep their order and their exact text; new
// members are appended. It returns compact JSON.
func Stamp(summaryJSON []byte, recordingKey string, audioStart time.Time) ([]byte, error) {
	members, err := parseObject(summaryJSON)
	if err != nil {
		return nil, err
	}
	key, _ := json.Marshal(recordingKey)
	members = set(members, "recording_key", key)

	for _, m := range members {
		if m.key != "call_start" {
			continue
		}
		var callStart string
		if json.Unmarshal(m.value, &callStart) == nil {
			if startMs, ok := parseCallStart(callStart); ok {
				offset := audioStart.UnixMilli() - startMs
				members = set(members, "recording_started_at_ms", []byte(strconv.FormatInt(offset, 10)))
			}
		}
		break
	}

	var out bytes.Buffer
	out.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			out.WriteByte(',')
		}
		k, _ := json.Marshal(m.key)
		out.Write(k)
		out.WriteByte(':')
		if err := json.Compact(&out, m.value); err != nil {
			return nil, err
		}
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func parseObject(data []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("session summary is not a JSON object")
	}
	var members []member
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		members = append(members, member{k.(string), v})
	}
	return members, nil
}

func set(members []member, key string, value json.RawMessage) []member {
	for i := range members {
		if members[i].key == key {
			members[i].value = value
			return members
		}
	}
	return append(members, member{key, value})
}

// parseCallStart reads an ISO-8601 UTC timestamp such as
// "2026-04-16T18:24:43.955Z" and returns milliseconds since the epoch. The
// fraction may have any number of digits.
func parseCallStart(s string) (int64, bool) {
	const layout = "2006-01-02T15:04:05"
	if len(s) < len(layout) {
		return 0, false
	}
	t, err := time.Parse(layout, s[:len(layout)])
	if err != nil {
		return 0, false
	}
	ms := int64(0)
	if rest := s[len(layout):]; len(rest) > 1 && rest[0] == '.' {
		digits := 0
		for _, c := range rest[1:] {
			if c < '0' || c > '9' {
				break
			}
			if digits < 3 {
				ms = ms*10 + int64(c-'0')
			}
			digits++
		}
		for ; digits < 3 && digits > 0; digits++ {
			ms *= 10
		}
	}
	return t.Unix()*1000 + ms, true
}
