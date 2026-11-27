// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/objstore/objstoretest"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// s3Boot writes the credentials file of g and returns the boot file's revocation_log section for
// the sink s3://<bucket>/revocations.
func s3Boot(t *testing.T, g objstoretest.Target) config.RevocationLog {
	t.Helper()
	file := filepath.Join(t.TempDir(), "s3-credentials")
	body := fmt.Sprintf("access_key_id: %s\nsecret_access_key: %s\n", g.AccessKeyID, g.SecretKey)
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.RevocationLog{Sink: "s3://" + g.Bucket + "/revocations",
		S3: config.RevocationLogS3{Endpoint: g.Endpoint, Region: g.Region, CredentialsFile: file}}
}

func logTo(buf *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(buf, nil)) }

// TestOpenRevocationSink_S3: the sink of the boot file is probed and takes the entries of the
// local log; the probe leaves its object, and a directory sink needs no backend of its own.
func TestOpenRevocationSink_S3(t *testing.T) {
	g := objstoretest.NewTarget(t)
	rl := s3Boot(t, g)
	var logs bytes.Buffer
	b, err := controller.OpenRevocationSink(t.Context(), rl, logTo(&logs))
	if err != nil || b == nil {
		t.Fatalf("open: %v, %v", b, err)
	}
	logPath := filepath.Join(t.TempDir(), "revocations.log")
	l, err := revlog.Open(logPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"ses_1", "ses_2"} {
		if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: s}); err != nil {
			t.Fatal(err)
		}
	}
	r := &controller.RevocationShipper{Path: logPath, Sink: rl.Sink, Backend: b, Replica: "ctn_a", Logger: logTo(&logs)}
	if err := r.Ship(); err != nil {
		t.Fatal(err)
	}
	if st := r.Status(); !st.Sink || st.Unshipped != 0 {
		t.Errorf("status %+v", st)
	}
	entries, err := revlog.NewSink(b).Read()
	if err != nil || len(entries) != 2 {
		t.Fatalf("the sink: %d entries, %v", len(entries), err)
	}
	if strings.Contains(logs.String(), g.SecretKey) {
		t.Error("the secret key is in the log")
	}

	if b, err := controller.OpenRevocationSink(t.Context(), config.RevocationLog{Sink: "/mnt/sink"}, logTo(&logs)); b != nil || err != nil {
		t.Errorf("a directory sink: %v, %v", b, err)
	}
}

// TestOpenRevocationSink_RefusesStoreWithoutConditionalCreate: a store that does not refuse a
// second create with If-None-Match: * keeps the controller from starting, and the error names the
// sink.
func TestOpenRevocationSink_RefusesStoreWithoutConditionalCreate(t *testing.T) {
	s := objstoretest.New(t)
	s.NoConditional = true
	rl := s3Boot(t, s.Target())
	b, err := controller.OpenRevocationSink(t.Context(), rl, logTo(&bytes.Buffer{}))
	if !errors.Is(err, revlog.ErrNoConditionalCreate) || b != nil || !strings.Contains(err.Error(), rl.Sink) {
		t.Fatalf("open: %v, %v", b, err)
	}
}

// TestOpenRevocationSink_StoreDown: a store that cannot be reached does not keep the controller from
// starting, since revocations are enforced without the sink; the shipper probes before it writes,
// and ships once the store answers.
func TestOpenRevocationSink_StoreDown(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		reason string
	}{"503": {503, revlog.ReasonUnreachable}, "403": {403, revlog.ReasonRefused}} {
		status := tc.status
		t.Run(name, func(t *testing.T) {
			s := objstoretest.New(t)
			down := true
			s.Fault = func(method, key string) (int, time.Duration) {
				if down {
					return status, 0
				}
				return 0, 0
			}
			rl := s3Boot(t, s.Target())
			var logs bytes.Buffer
			b, err := controller.OpenRevocationSink(t.Context(), rl, logTo(&logs))
			if err != nil || b == nil || !strings.Contains(logs.String(), "could not be probed") {
				t.Fatalf("open: %v, %v, log %q", b, err, logs.String())
			}
			logPath := filepath.Join(t.TempDir(), "revocations.log")
			l, err := revlog.Open(logPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: "ses_1"}); err != nil {
				t.Fatal(err)
			}
			r := &controller.RevocationShipper{Path: logPath, Sink: rl.Sink, Backend: b, Replica: "ctn_a", Logger: logTo(&logs)}
			if err := r.Ship(); err == nil || r.Status().Unshipped != 1 {
				t.Fatalf("a round while the store is down: %v, %+v", err, r.Status())
			}
			if got := r.Status().Reason; got != tc.reason {
				t.Errorf("the reason is %q, want %q", got, tc.reason)
			}
			if len(s.Keys()) != 0 {
				t.Errorf("the store holds %v", s.Keys())
			}
			down = false
			if err := r.Ship(); err != nil || r.Status().Unshipped != 0 {
				t.Fatalf("a round after it recovered: %v, %+v", err, r.Status())
			}
			if got := r.Status().Reason; got != "" {
				t.Errorf("the reason after a success is %q", got)
			}
			if strings.Contains(logs.String(), s.Target().SecretKey) {
				t.Errorf("the log holds the secret key: %s", logs.String())
			}
		})
	}
}

// TestOpenRevocationSink_Credentials: a credentials file that is missing, readable by others, not
// the two keys, or holds no printable key is an error that names the file and not the secret.
func TestOpenRevocationSink_Credentials(t *testing.T) {
	const secretKey = "sekrit-key-0000" //nolint:gosec // G101: a test value
	s := objstoretest.New(t)
	for name, tc := range map[string]struct {
		body string
		mode os.FileMode
		want string
	}{
		"missing":        {"", 0, "credentials_file"},
		"group-readable": {"access_key_id: AKIA0000\nsecret_access_key: " + secretKey + "\n", 0o640, "mode"},
		"other keys":     {"access_key_id: AKIA0000\nsecret_access_key: " + secretKey + "\nextra: 1\n", 0o600, "credentials_file"},
		"not YAML":       {"access_key_id: [" + secretKey + "\n", 0o600, "credentials_file"},
		"no secret":      {"access_key_id: AKIA0000\n", 0o600, "credentials_file"},
	} {
		t.Run(name, func(t *testing.T) {
			rl := s3Boot(t, s.Target())
			if tc.mode != 0 {
				if err := os.WriteFile(rl.S3.CredentialsFile, []byte(tc.body), tc.mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(rl.S3.CredentialsFile, tc.mode); err != nil {
					t.Fatal(err)
				}
			} else {
				rl.S3.CredentialsFile = filepath.Join(t.TempDir(), "absent")
			}
			_, err := controller.OpenRevocationSink(t.Context(), rl, logTo(&bytes.Buffer{}))
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), secretKey) {
				t.Fatalf("open: %v", err)
			}
		})
	}
	// An endpoint that is not https, or a bucket the store would refuse, fails the same way.
	rl := s3Boot(t, s.Target())
	rl.S3.Endpoint = "http://203.0.113.9:9000"
	if _, err := controller.OpenRevocationSink(t.Context(), rl, logTo(&bytes.Buffer{})); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("an http endpoint on a public address: %v", err)
	}
	rl = s3Boot(t, s.Target())
	rl.Sink = "s3://B/p"
	if _, err := controller.OpenRevocationSink(t.Context(), rl, logTo(&bytes.Buffer{})); err == nil || !strings.Contains(err.Error(), "bucket") {
		t.Errorf("a bad bucket name: %v", err)
	}
}

// TestRestore_ReadsS3Sink: a restore reads an s3:// source with the boot file's store, verifies its
// chain and refuses a broken one.
func TestRestore_ReadsS3Sink(t *testing.T) {
	g := objstoretest.NewTarget(t)
	rl := s3Boot(t, g)
	b, err := controller.OpenRevocationSink(t.Context(), rl, logTo(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "revocations.log")
	l, err := revlog.Open(logPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"ses_1", "ses_2", "ses_3"} {
		if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: s}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := revlog.NewSink(b).Ship(logPath, "ctn_a"); err != nil {
		t.Fatal(err)
	}
	got, err := controller.ReadSource(t.Context(), rl.Sink, rl)
	if err != nil || len(got) != 3 || got[2].Subject != "ses_3" {
		t.Fatalf("read: %v, %v", got, err)
	}
	// A gap, as a deleted object leaves, breaks the chain.
	if err := b.CreateIfAbsent(revlog.Key(5), []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ReadSource(t.Context(), rl.Sink, rl); !errors.Is(err, revlog.ErrBroken) {
		t.Errorf("a sink with a gap: %v", err)
	}
	// Without the store in the boot file there is nothing to read it with.
	if _, err := controller.ReadSource(t.Context(), rl.Sink, config.RevocationLog{}); err == nil || !strings.Contains(err.Error(), "revocation_log.s3") {
		t.Errorf("no store configured: %v", err)
	}
}

// TestRevocationShipper_StoreUnfitAtRuntime (security review): a store that could not be probed at
// start and then turns out to overwrite is logged at Error level with its reason, and nothing is
// written to it.
func TestRevocationShipper_StoreUnfitAtRuntime(t *testing.T) {
	s := objstoretest.New(t)
	s.NoConditional = true
	var down atomic.Bool
	down.Store(true)
	s.Fault = func(method, key string) (int, time.Duration) {
		if down.Load() {
			return 503, 0
		}
		return 0, 0
	}
	rl := s3Boot(t, s.Target())
	var logs bytes.Buffer
	b, err := controller.OpenRevocationSink(t.Context(), rl, logTo(&logs))
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "revocations.log")
	l, err := revlog.Open(logPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: "ses_1"}); err != nil {
		t.Fatal(err)
	}
	down.Store(false)
	r := &controller.RevocationShipper{Path: logPath, Sink: rl.Sink, Backend: b, Replica: "ctn_a", Logger: logTo(&logs)}
	if err := r.Ship(); !errors.Is(err, revlog.ErrNoConditionalCreate) {
		t.Fatalf("ship: %v", err)
	}
	if got := r.Status().Reason; got != revlog.ReasonNoConditional || r.Status().Unshipped != 1 {
		t.Errorf("status %+v", r.Status())
	}
	if out := logs.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "no_conditional_create") {
		t.Errorf("the log: %s", out)
	}
	for _, k := range s.Keys() {
		if !strings.Contains(k, "_probe/") {
			t.Errorf("an entry reached the unfit store: %s", k)
		}
	}
}

// TestOpenRevocationSink_LockDays (review item 6): the lock_days of the boot file reach the
// backend, so that the shipped entries are locked in compliance mode; without it they are not.
func TestOpenRevocationSink_LockDays(t *testing.T) {
	for name, days := range map[string]int{"locked": 90, "not locked": 0} {
		t.Run(name, func(t *testing.T) {
			s := objstoretest.New(t)
			rl := s3Boot(t, s.Target())
			rl.S3.LockDays = days
			b, err := controller.OpenRevocationSink(t.Context(), rl, logTo(&bytes.Buffer{}))
			if err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(t.TempDir(), "revocations.log")
			l, err := revlog.Open(logPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: "ses_1"}); err != nil {
				t.Fatal(err)
			}
			r := &controller.RevocationShipper{Path: logPath, Sink: rl.Sink, Backend: b, Replica: "ctn_a", Logger: logTo(&bytes.Buffer{})}
			if err := r.Ship(); err != nil {
				t.Fatal(err)
			}
			mode, retain := s.Lock("revocations/" + revlog.Key(1))
			if (days > 0) != (mode == "COMPLIANCE") || (days > 0) != (retain != "") {
				t.Errorf("lock_days %d: mode %q until %q", days, mode, retain)
			}
		})
	}
}
