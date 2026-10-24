// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

var (
	relRoot    = releasetest.Key("apisvc test root")
	relSigning = releasetest.Key("apisvc test signing")
)

func testReleaseRoot() release.PublicKey {
	k, err := release.ParsePublicKey(relRoot.Public())
	if err != nil {
		panic(err)
	}
	return k
}

// signedRelease is the upload of a release of version with seq, signed by the test keys; the
// statement is valid from a day before now for a year.
func signedRelease(t *testing.T, now time.Time, version string, seq uint64, channel string) *rpmgrv1.UploadReleaseRequest {
	t.Helper()
	st, err := json.Marshal(release.Statement{Statement: 1, SigningKey: relSigning.Public(), NotBefore: now.Add(-24 * time.Hour).UTC(),
		NotAfter: now.Add(300 * 24 * time.Hour).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(version))
	man, err := json.Marshal(release.Manifest{Seq: seq, Version: version, Floor: "1.0.0", Channel: channel, IssuedAt: now.UTC(),
		Artifacts: []release.Artifact{{OS: "linux", Arch: "amd64", Variant: "full", Size: 1, SHA256: hex.EncodeToString(sum[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	return &rpmgrv1.UploadReleaseRequest{SigningKeyStatement: st, StatementSignature: relRoot.Sign(st), Manifest: man,
		ManifestSignature: relSigning.Sign(man)}
}

// TestReleases (docs/04-security.md, "Over-the-air updates"): the Instance Admin uploads signed
// releases after a step-up, and a release that does not verify is refused; an older manifest of a
// version does not replace a newer one; the releases list the newest version first, page by page,
// and say which one the controller runs and which are newer; each upload is audited; an org Owner
// sees and uploads nothing.
func TestReleases(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	upload := func(b *browser, r *rpmgrv1.UploadReleaseRequest) (*rpmgrv1.Release, error) {
		resp, err := b.rel.UploadRelease(ctx, connect.NewRequest(r))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetRelease(), nil
	}
	if _, err := upload(ada, signedRelease(t, e.clock, "1.4.2", 10, release.Stable)); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("an upload without a step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	forged := signedRelease(t, e.clock, "1.4.2", 10, release.Stable)
	forged.ManifestSignature = releasetest.Key("someone else").Sign(forged.GetManifest())
	if _, err := upload(ada, forged); code(err) != connect.CodeInvalidArgument || reason(err) != apisvc.ReasonReleaseDoesNotVerify {
		t.Errorf("a manifest signed by another key: %v", err)
	}
	notRoot := signedRelease(t, e.clock, "1.4.2", 10, release.Stable)
	notRoot.StatementSignature = relSigning.Sign(notRoot.GetSigningKeyStatement()) // the signing key vouching for itself
	if _, err := upload(ada, notRoot); reason(err) != apisvc.ReasonReleaseDoesNotVerify {
		t.Errorf("a statement signed by a key that is no root: %v", err)
	}
	expired := signedRelease(t, e.clock.Add(-400*24*time.Hour), "1.4.2", 10, release.Stable)
	if _, err := upload(ada, expired); reason(err) != apisvc.ReasonReleaseDoesNotVerify {
		t.Errorf("an expired signing-key statement: %v", err)
	}
	if _, err := upload(ada, &rpmgrv1.UploadReleaseRequest{SigningKeyStatement: []byte("{}"), StatementSignature: []byte("x"),
		Manifest: make([]byte, 1<<20+1), ManifestSignature: []byte("x")}); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a manifest above 1 MiB: %v", err)
	}
	old, err := upload(ada, signedRelease(t, e.clock, "1.4.2", 10, release.Stable))
	if err != nil || old.GetVersion() != "1.4.2" || old.GetSource() != rpmgrv1.ReleaseSource_RELEASE_SOURCE_UPLOAD || old.GetMirrored() ||
		old.GetNewerThanController() || old.GetControllerVersion() || old.GetManifestSeq() != 10 {
		t.Fatalf("an upload: %v %v", old, err)
	}
	if again, err := upload(ada, signedRelease(t, e.clock, "1.4.2", 9, release.Stable)); err != nil || again.GetManifestSeq() != 10 ||
		again.GetId() != old.GetId() {
		t.Errorf("an older manifest of the same version replaced the newer: %v %v", again, err)
	}
	newer := signedRelease(t, e.clock, "1.4.2", 11, release.Stable)
	if got, err := upload(ada, newer); err != nil || got.GetManifestSeq() != 11 || got.GetId() != old.GetId() {
		t.Errorf("a newer manifest of the same version: %v %v", got, err)
	}
	if row := c.Release.GetX(e.sys, old.GetId()); string(row.Manifest) != string(newer.GetManifest()) {
		t.Error("the newer manifest was not recorded")
	}
	sum := sha256.Sum256(newer.GetManifest())
	entries := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.ReleaseService.UploadRelease")).Order(ent.Desc(auditentry.FieldID)).AllX(e.sys)
	if d := entries[0].Diff; !strings.Contains(d, `"version":"1.4.2"`) || !strings.Contains(d, `"seq":11`) ||
		!strings.Contains(d, hex.EncodeToString(sum[:])) || len(d) > 400 {
		t.Errorf("the audit entry of an upload: %s", d)
	}
	for _, v := range []string{"1.6.0", "1.5.0", "1.10.0-rc.1"} {
		ch := release.Stable
		if v == "1.10.0-rc.1" {
			ch = release.Prerelease
		}
		if _, err := upload(ada, signedRelease(t, e.clock, v, 20, ch)); err != nil {
			t.Fatal(v, err)
		}
	}

	var versions []string
	for page := ""; ; {
		resp, err := ada.rel.ListReleases(ctx, connect.NewRequest(&rpmgrv1.ListReleasesRequest{PageSize: 2, PageToken: page}))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Msg.GetControllerVersion() != "1.5.0" {
			t.Errorf("the controller's version: %q", resp.Msg.GetControllerVersion())
		}
		for _, r := range resp.Msg.GetReleases() {
			versions = append(versions, r.GetVersion())
			if r.GetNewerThanController() != (r.GetVersion() == "1.6.0" || r.GetVersion() == "1.10.0-rc.1") ||
				r.GetControllerVersion() != (r.GetVersion() == "1.5.0") {
				t.Errorf("a listed release: %v", r)
			}
		}
		if page = resp.Msg.GetNextPageToken(); page == "" {
			break
		}
	}
	if want := []string{"1.10.0-rc.1", "1.6.0", "1.5.0", "1.4.2"}; !equalStrings(versions, want) {
		t.Errorf("the releases %v, want %v", versions, want)
	}
	if _, err := ada.rel.ListReleases(ctx, connect.NewRequest(&rpmgrv1.ListReleasesRequest{PageToken: "not a token"})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("an altered page token: %v", err)
	}
	if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.ReleaseService.UploadRelease"), auditentry.ResultEQ(auditentry.ResultSuccess)).
		CountX(e.sys); n != 6 {
		t.Errorf("%d audit entries of a successful upload, want 6", n)
	}

	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.rel.ListReleases(ctx, connect.NewRequest(&rpmgrv1.ListReleasesRequest{})); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner lists the releases: %v", err)
	}
	if _, err := upload(bob, signedRelease(t, e.clock, "1.3.0", 1, release.Stable)); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner uploads: %v", err)
	}
}

// fakeChecks is a release check that answers what the test sets.
type fakeChecks struct {
	status *rpmgrv1.ReleaseCheck
	wait   time.Duration
	err    error
	asked  int
}

func (f *fakeChecks) Status() *rpmgrv1.ReleaseCheck { return f.status }
func (f *fakeChecks) CheckNow() (*rpmgrv1.ReleaseCheck, time.Duration, error) {
	f.asked++
	return f.status, f.wait, f.err
}

// TestReleases_CheckNow (#890): the Instance Admin asks for a release check without a step-up and
// gets its state, which ListReleases also returns; it is refused with the time to wait within the
// gap, and with a reason while the release check is off or the build checks for no releases; each
// request is audited; an org Owner asks for nothing.
func TestReleases_CheckNow(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t)
	ctx := context.Background()
	check := func(b *browser) (*rpmgrv1.ReleaseCheck, error) {
		resp, err := b.rel.CheckReleases(ctx, connect.NewRequest(&rpmgrv1.CheckReleasesRequest{}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetReleaseCheck(), nil
	}
	listed := func() *rpmgrv1.ReleaseCheck {
		t.Helper()
		resp, err := ada.rel.ListReleases(ctx, connect.NewRequest(&rpmgrv1.ListReleasesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg.GetReleaseCheck()
	}

	if _, err := check(ada); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonReleaseCheckOff {
		t.Errorf("a build without a release check: %v", err)
	}
	if got := listed(); got.GetOutcome() != rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_NONE {
		t.Errorf("listed without a release check: %v", got)
	}

	at := timestamppb.New(e.clock)
	f := &fakeChecks{status: &rpmgrv1.ReleaseCheck{Running: true, CheckTime: at, Outcome: rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_FAILED, Error: "dial tcp: no route to host"}}
	e.rel.Checks = f
	got, err := check(ada)
	if err != nil || !got.GetRunning() || got.GetError() != "dial tcp: no route to host" || f.asked != 1 {
		t.Fatalf("check now: %v %v", got, err)
	}
	if got := listed(); !got.GetRunning() || !got.GetCheckTime().AsTime().Equal(e.clock) {
		t.Errorf("listed while it runs: %v", got)
	}
	f.wait = 42 * time.Second
	if _, err := check(ada); code(err) != connect.CodeResourceExhausted || retryAfter(err) != 42*time.Second {
		t.Errorf("within the gap: %v", err)
	}
	f.wait, f.err = 0, release.ErrDevelopment
	if _, err := check(ada); reason(err) != apisvc.ReasonReleaseCheckOff {
		t.Errorf("a development build: %v", err)
	}
	f.err = nil
	if _, err := settings.UpdateInstance(e.sys, e.db, &rpmgrv1.InstanceSettings{ReleaseCheck: new(false)},
		&fieldmaskpb.FieldMask{Paths: []string{"release_check"}}, 0); err != nil {
		t.Fatal(err)
	}
	asked := f.asked
	if _, err := check(ada); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonReleaseCheckOff ||
		!strings.Contains(err.Error(), "off") || f.asked != asked {
		t.Errorf("the release check off: %v", err)
	}

	c := e.db.Client()
	if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.ReleaseService.CheckReleases")).CountX(e.sys); n != 5 {
		t.Errorf("%d audit entries of a release check, want 5", n)
	}
	if n := c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.ReleaseService.CheckReleases"), auditentry.ResultEQ(auditentry.ResultSuccess)).
		CountX(e.sys); n != 1 {
		t.Errorf("%d audit entries of a successful release check, want 1", n)
	}

	bob, _ := e.addOwner(t, storetest.Org(t, e.db, "org-b"), "bob@example.com")
	asked = f.asked
	if _, err := check(bob); code(err) != connect.CodePermissionDenied || f.asked != asked {
		t.Errorf("an Owner asks for a release check: %v", err)
	}
}

// TestReleases_DevelopmentController: a controller without a release version lists every release
// as newer than itself.
func TestReleases_DevelopmentController(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t)
	e.rel.Version = "dev"
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	resp, err := ada.rel.UploadRelease(context.Background(), connect.NewRequest(signedRelease(t, e.clock, "1.4.2", 1, release.Stable)))
	if err != nil || !resp.Msg.GetRelease().GetNewerThanController() {
		t.Fatalf("an upload: %v %v", resp, err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
