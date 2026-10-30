// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/auditsink/syslogtest"
)

func newTestSyslog(t *testing.T, srv *syslogtest.Server, batch time.Duration) *syslogSink {
	t.Helper()
	roots, err := rootsOf(srv.CA)
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := parseSyslogAddress(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	k := &syslogSink{address: srv.Addr, host: host, roots: roots, hostname: "h", batchTimeout: batch}
	k.policy.Internal = true
	t.Cleanup(func() { _ = k.Close() })
	return k
}

func testItem(seq int64, body string) Item {
	return Item{ID: "aud_1", Type: EventEntry, Chain: "instance", Seq: seq, Time: time.Now(), Body: []byte(body)}
}

// TestRootsOf_Empty (#936): an empty bundle holds no certificate, so it is refused here, whatever
// the settings code does with "no bundle".
func TestRootsOf_Empty(t *testing.T) {
	for _, ca := range []string{"", "   ", "\n"} {
		if _, err := rootsOf(ca); err == nil || !strings.Contains(err.Error(), "no certificate") {
			t.Errorf("%q: %v", ca, err)
		}
	}
}

// TestSyslogMessage_Marker (#936): an item that stays too long once everything that can be spared
// is gone becomes a marker that keeps its ID, type, seq and hash, is valid JSON and fits.
func TestSyslogMessage_Marker(t *testing.T) {
	k := &syslogSink{hostname: "h"}
	hash := strings.Repeat("ab", 32)
	for name, extra := range map[string]string{
		"a long action":       `"action":"` + strings.Repeat("a", 20000) + `"`,
		"a long target":       `"target_id":"` + strings.Repeat("t", MaxSyslogMessage) + `"`,
		"a long diff too":     `"diff":"` + strings.Repeat("d", 20000) + `","reason":"` + strings.Repeat("r", 9000) + `"`,
		"just over the limit": `"action":"` + strings.Repeat("a", MaxSyslogMessage-170) + `"`,
		"a multi-byte value":  `"actor_id":"` + strings.Repeat("é", 10000) + `"`,
	} {
		it := testItem(7, `{"id":"aud_1","type":"audit.entry","time":"2026-01-02T03:04:05Z","chain":"instance","seq":7,"hash":"`+hash+`",`+extra+`}`)
		msg, err := k.message(it)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(msg) > MaxSyslogMessage {
			t.Errorf("%s: %d octets", name, len(msg))
		}
		var m map[string]any
		if err := json.Unmarshal(msg[strings.Index(string(msg), "{"):], &m); err != nil {
			t.Fatalf("%s: not JSON: %v", name, err)
		}
		if m["truncated"] != true || m["id"] != "aud_1" || m["type"] != "audit.entry" || m["seq"] != float64(7) {
			t.Errorf("%s: %v", name, m)
		}
		if name != "just over the limit" && m["hash"] != hash {
			t.Errorf("%s: the hash is %v", name, m["hash"])
		}
		if !strings.Contains(string(msg[:strings.Index(string(msg), "{")]), "audit.entry") {
			t.Errorf("%s: the header lost the type", name)
		}
	}
	// An item that is no JSON cannot be shortened and is refused, not shipped.
	if _, err := k.message(testItem(1, strings.Repeat("x", 9000))); err == nil {
		t.Error("an item that is no JSON was shipped")
	}
}

// TestSyslogSink_BatchDeadline (#936): a batch has one deadline for all of it, beside the deadline
// of each write. A receiver that never closes the connection ends the batch at the deadline, not
// after the drain's; an item sent after the deadline fails the batch; a batch inside its
// deadline succeeds.
func TestSyslogSink_BatchDeadline(t *testing.T) {
	ctx := context.Background()
	body := `{"id":"aud_1","type":"audit.entry","seq":1}`

	t.Run("a stalled receiver ends the batch at the deadline", func(t *testing.T) {
		srv := syslogtest.New(t, 0)
		srv.SetStall(true)
		// The deadline also covers the dial and the handshake: long enough for both on a busy runner.
		k := newTestSyslog(t, srv, time.Second)
		start := time.Now()
		if err := k.Ship(ctx, testItem(1, body)); err != nil {
			t.Fatal(err)
		}
		err := k.Flush(ctx)
		elapsed := time.Since(start)
		if err == nil || !strings.Contains(err.Error(), "longer than the time allowed for a batch") {
			t.Fatalf("flush: %v", err)
		}
		if elapsed < 900*time.Millisecond || elapsed > SyslogDrainTimeout-time.Second {
			t.Errorf("the batch ended after %v, want about 1s (drain %v)", elapsed, SyslogDrainTimeout)
		}
		if k.conn != nil {
			t.Error("the connection is still open")
		}
	})

	t.Run("an item after the deadline fails the batch", func(t *testing.T) {
		srv := syslogtest.New(t, 0)
		k := newTestSyslog(t, srv, time.Second)
		if err := k.Ship(ctx, testItem(1, body)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1200 * time.Millisecond)
		if err := k.Ship(ctx, testItem(2, body)); err == nil || !strings.Contains(err.Error(), "time allowed") {
			t.Fatalf("ship after the deadline: %v", err)
		}
		if err := k.Flush(ctx); err == nil {
			t.Fatal("the batch that ran out of time was confirmed")
		}
		// The next batch has a deadline of its own.
		if err := k.Ship(ctx, testItem(1, body)); err != nil {
			t.Fatalf("the next batch: %v", err)
		}
		if err := k.Flush(ctx); err != nil {
			t.Fatalf("the next batch's flush: %v", err)
		}
	})

	t.Run("a batch inside its deadline is confirmed", func(t *testing.T) {
		srv := syslogtest.New(t, 0)
		k := newTestSyslog(t, srv, 10*time.Second)
		for i := int64(1); i <= 3; i++ {
			if err := k.Ship(ctx, testItem(i, body)); err != nil {
				t.Fatal(err)
			}
		}
		if err := k.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		if n := len(srv.Messages()); n != 3 {
			t.Fatalf("%d messages", n)
		}
	})
}
