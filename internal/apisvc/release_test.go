// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
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
		CountX(e.sys); n != 5 {
		t.Errorf("%d audit entries of a successful upload, want 5", n)
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
