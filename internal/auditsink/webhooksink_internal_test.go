// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// A receiver that answers every delivery, but slowly, cannot keep a pass busy for longer than the
// batch time: the item in hand is left for the next pass and the batch fails with a plain reason.
func TestWebhookSink_BatchDeadline(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond) // long enough that a slow runner's handshake leaves time for one
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	sender := &webhook.Sender{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Now: time.Now}
	k := &webhookSink{sender: sender, url: "https://example.com:" + port, secret: secret.New("test-secret"), batchTimeout: time.Second}
	ctx := context.Background()
	shipped := 0
	var err error
	for seq := int64(1); seq <= 20 && err == nil; seq++ {
		if err = k.Ship(ctx, cpItem("org_a", seq)); err == nil {
			shipped++
		}
	}
	if !errors.Is(err, errWebhookBatchTime) || shipped < 1 || shipped > 4 {
		t.Fatalf("shipped %d, error %v", shipped, err)
	}
	var perm *PermanentError
	if errors.As(err, &perm) {
		t.Fatal("running out of time is not a refusal of the receiver")
	}
	if err := k.Ship(ctx, cpItem("org_a", 99)); !errors.Is(err, errWebhookBatchTime) {
		t.Fatalf("after the deadline: %v", err)
	}
	// A cancelled pass is not blamed on the receiver's speed.
	k2 := &webhookSink{sender: sender, url: k.url, secret: secret.New("test-secret"), batchTimeout: time.Minute}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := k2.Ship(cctx, cpItem("org_a", 1)); err == nil || errors.Is(err, errWebhookBatchTime) {
		t.Fatalf("a cancelled pass: %v", err)
	}
}
