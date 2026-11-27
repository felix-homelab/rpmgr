// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/objstore/objstoretest"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// TestRevocation_EnforcedWhileSinkDown (docs/12-testing-and-quality.md, "Security testing"): with
// the shared sink unavailable, revoking a connector, removing a member and changing a password are
// committed and enforced immediately; the entries are in the replica's fsync'd local log; the
// "revocation log not yet off-host" alert fires and clears after shipping; the sink's sequence
// numbers have no gaps.
//
// It runs for the filesystem sink and for the S3 sink; with the build tag objstoreit the S3 sink is
// SILO in a container.
func TestRevocation_EnforcedWhileSinkDown(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		enforcedWhileSinkDown(t, func(e *env) sinkUnderTest {
			sink := filepath.Join(t.TempDir(), "share") // not mounted yet
			return sinkUnderTest{
				shipper: &controller.RevocationShipper{Path: e.log, Sink: sink, Replica: "ctn_a", Now: func() time.Time { return e.clock }, Logger: quietLogger()},
				up:      func() { _ = os.Mkdir(sink, 0o750) },
				read:    revlog.NewSink(revlog.DirBackend{Dir: sink}).Read,
			}
		})
	})
	t.Run("s3", func(t *testing.T) {
		enforcedWhileSinkDown(t, func(e *env) sinkUnderTest {
			g := objstoretest.NewTarget(t)
			// The store sits behind a proxy that answers 503 while the sink is down.
			var down atomic.Bool
			down.Store(true)
			u, _ := url.Parse(g.Endpoint)
			rp := httputil.NewSingleHostReverseProxy(u)
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if down.Load() {
					http.Error(w, "down", http.StatusServiceUnavailable)
					return
				}
				rp.ServeHTTP(w, r)
			}))
			t.Cleanup(proxy.Close)
			gp := g
			gp.Endpoint = proxy.URL
			b := revlog.NewS3Backend(gp.Client(t, 0), "revocations")
			direct := revlog.NewS3Backend(g.Client(t, 0), "revocations")
			return sinkUnderTest{
				shipper: &controller.RevocationShipper{Path: e.log, Sink: "s3://" + g.Bucket + "/revocations", Backend: b, Replica: "ctn_a",
					Now: func() time.Time { return e.clock }, Logger: quietLogger()},
				up:   func() { down.Store(false) },
				read: revlog.NewSink(direct).Read,
			}
		})
	})
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// sinkUnderTest is a sink that is down until up is called.
type sinkUnderTest struct {
	shipper *controller.RevocationShipper
	up      func()
	read    func() ([]revlog.SinkEntry, error) // verifies the sink from entry 1
}

func enforcedWhileSinkDown(t *testing.T, mk func(*env) sinkUnderTest) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	su := mk(e)
	shipper := su.shipper
	e.revlogStatus = shipper.Status

	// A connector revoked: committed, and the deny-list applied at once.
	nas := e.addConnector(t, org, "nas", nil)
	denied := e.denied.Load()
	if _, err := ada.con.DecommissionConnector(ctx, connect.NewRequest(&rpmgrv1.DecommissionConnectorRequest{ConnectorId: nas.ID})); err != nil {
		t.Fatal(err)
	}
	if e.denied.Load() == denied {
		t.Error("the connector's revocation did not reach the deny-list")
	}
	// A member removed: their session ends at once.
	vwr, vwrID := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := ada.org.RemoveMember(ctx, connect.NewRequest(&rpmgrv1.RemoveMemberRequest{OrgId: org, UserId: vwrID})); err != nil {
		t.Fatal(err)
	}
	if s, err := vwr.session(); err == nil && len(s.GetMemberships()) > 0 {
		t.Errorf("the removed member still belongs to the org: %v", s)
	}
	// A password changed: the old one no longer signs in.
	if _, err := ada.user.ChangePassword(ctx, connect.NewRequest(&rpmgrv1.ChangePasswordRequest{CurrentPassword: pw,
		NewPassword: "another correct horse battery"})); err != nil {
		t.Fatal(err)
	}
	if err := e.browser().login("ada@example.com", pw); err == nil {
		t.Error("the old password still signs in")
	}

	local, err := revlog.Read(e.log)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[revlog.Kind]bool{}
	for _, l := range local {
		kinds[l.Kind] = true
	}
	for _, k := range []revlog.Kind{revlog.IdentityRevoked, revlog.MemberRemoved, revlog.CredentialSuperseded} {
		if !kinds[k] {
			t.Errorf("the local log has no %s entry: %v", k, kinds)
		}
	}

	status := func() *rpmgrv1.RevocationLogStatus {
		t.Helper()
		r, err := ada.set.GetInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.GetInstanceSettingsRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetRevocationLog()
	}
	if err := shipper.Ship(); err == nil {
		t.Fatal("shipped to an unmounted sink")
	}
	if st := status(); !st.GetSink() || st.GetUnshipped() != int64(len(local)) || st.GetAlert() {
		t.Errorf("a fresh backlog: %v", st)
	}
	e.clock = e.clock.Add(revlog.OffHostAlert + time.Second)
	if st := status(); !st.GetAlert() || st.GetOldestUnshippedTime() == nil {
		t.Errorf("a backlog older than 5 min does not alert: %v", st)
	}

	su.up()
	if err := shipper.Ship(); err != nil {
		t.Fatal(err)
	}
	if st := status(); st.GetUnshipped() != 0 || st.GetAlert() {
		t.Errorf("after shipping: %v", st)
	}
	shipped, err := su.read() // also verifies 1..n without gaps
	if err != nil || len(shipped) != len(local) {
		t.Fatalf("the sink: %d entries, %v", len(shipped), err)
	}
	for i, s := range shipped {
		if s.Seq != uint64(i)+1 || s.Entry.Hash != local[i].Hash {
			t.Errorf("sink entry %d: %+v", i+1, s)
		}
	}
}
