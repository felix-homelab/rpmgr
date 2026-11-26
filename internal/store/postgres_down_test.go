// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store"
)

// A server that is down, or does not answer, stops OpenPostgres with an error that says so, within
// the timeout of docs/03-connections.md; the tests need no server.

func TestOpenPostgres_ServerDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close() // nothing listens on the port now
	for _, lock := range []bool{false, true} {
		_, err := store.OpenPostgres(context.Background(), "postgres://rpmgr@127.0.0.1:"+strconv.Itoa(addr.Port)+"/rpmgr",
			store.PostgresOptions{Lock: lock})
		if err == nil || !strings.Contains(err.Error(), "PostgreSQL") {
			t.Errorf("lock=%v: err = %v, want one that names PostgreSQL", lock, err)
		}
	}
}

func TestOpenPostgres_ServerSilent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { // accepts and never answers
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	store.SetConnectTimeout(t.Cleanup, 300*time.Millisecond)
	start := time.Now()
	_, err = store.OpenPostgres(context.Background(), "postgres://rpmgr@"+ln.Addr().String()+"/rpmgr", store.PostgresOptions{Lock: true})
	if err == nil || !strings.Contains(err.Error(), "did not answer within") {
		t.Fatalf("err = %v, want the timeout named", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("OpenPostgres took %s with a 300 ms timeout", d)
	}
}
