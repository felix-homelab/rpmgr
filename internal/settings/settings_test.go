// SPDX-License-Identifier: Apache-2.0

package settings_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

const day = 24 * time.Hour

func mask(paths ...string) *fieldmaskpb.FieldMask { return &fieldmaskpb.FieldMask{Paths: paths} }

func TestInstanceDefaults(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		s, etag, err := settings.Instance(storetest.SystemCtx(t), db.Client())
		if err != nil {
			t.Fatal(err)
		}
		if etag != 0 || !proto.Equal(s, settings.InstanceDefaults()) {
			t.Errorf("before any update: etag %d, settings %v; want the defaults", etag, s)
		}
		if s.GetDefaultTransport() != rpmgrv1.TransportPolicy_TRANSPORT_POLICY_AUTO ||
			s.GetLeafCertificateLifetime().AsDuration() != 7*day || s.GetExpiredCertificateGrace().AsDuration() != 30*day ||
			!s.GetReleaseCheck() || s.GetUpdateChannel() != rpmgrv1.UpdateChannel_UPDATE_CHANNEL_STABLE {
			t.Errorf("defaults differ from D4, D8 and D45: %v", s)
		}
	})
}

func TestUpdateInstance(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		ctx := storetest.SystemCtx(t)
		upd := &rpmgrv1.InstanceSettings{
			DefaultTransport:        rpmgrv1.TransportPolicy_TRANSPORT_POLICY_H2.Enum(),
			LeafCertificateLifetime: durationpb.New(14 * day), // not in the mask: ignored
		}
		rev, err := settings.UpdateInstance(ctx, db, upd, mask("default_transport"), 0)
		if err != nil || rev.Seq != 1 {
			t.Fatalf("UpdateInstance: %+v, %v", rev, err)
		}
		s, etag, _ := settings.Instance(ctx, db.Client())
		if s.GetDefaultTransport() != rpmgrv1.TransportPolicy_TRANSPORT_POLICY_H2 || s.GetLeafCertificateLifetime().AsDuration() != 7*day || etag != 1 {
			t.Errorf("after update: %v, etag %d", s, etag)
		}
		// A named field that the update leaves unset returns to its default.
		if _, err := settings.UpdateInstance(ctx, db, &rpmgrv1.InstanceSettings{}, mask("default_transport"), etag); err != nil {
			t.Fatal(err)
		}
		if s, etag, _ = settings.Instance(ctx, db.Client()); s.GetDefaultTransport() != rpmgrv1.TransportPolicy_TRANSPORT_POLICY_AUTO || etag != 2 {
			t.Errorf("after clearing: %v, etag %d", s.GetDefaultTransport(), etag)
		}
		// A stale etag is refused and changes nothing.
		if _, err := settings.UpdateInstance(ctx, db, upd, mask("default_transport"), 1); !errors.Is(err, settings.ErrEtagMismatch) {
			t.Errorf("stale etag: %v, want ErrEtagMismatch", err)
		}
		if n := db.Client().ConfigRevision.Query().CountX(ctx); n != 2 {
			t.Errorf("%d revisions, want 2: a refused update must not create one", n)
		}
	})
}

func TestUpdateInstanceValidation(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		ctx := storetest.SystemCtx(t)
		lifetime := func(d time.Duration) *rpmgrv1.InstanceSettings {
			return &rpmgrv1.InstanceSettings{LeafCertificateLifetime: durationpb.New(d)}
		}
		grace := func(d time.Duration) *rpmgrv1.InstanceSettings {
			return &rpmgrv1.InstanceSettings{ExpiredCertificateGrace: durationpb.New(d)}
		}
		for _, tt := range []struct {
			name string
			upd  *rpmgrv1.InstanceSettings
			path string
			ok   bool
		}{
			{"lifetime 0", lifetime(0), "leaf_certificate_lifetime", false},
			{"lifetime 1 day", lifetime(day), "leaf_certificate_lifetime", true},
			{"lifetime 30 days", lifetime(30 * day), "leaf_certificate_lifetime", true},
			{"lifetime 31 days", lifetime(31 * day), "leaf_certificate_lifetime", false},
			{"grace 0 disables", grace(0), "expired_certificate_grace", true},
			{"grace 90 days", grace(90 * day), "expired_certificate_grace", true},
			{"grace 91 days", grace(91 * day), "expired_certificate_grace", false},
			{"grace negative", grace(-time.Second), "expired_certificate_grace", false},
			{"transport unspecified", &rpmgrv1.InstanceSettings{DefaultTransport: rpmgrv1.TransportPolicy_TRANSPORT_POLICY_UNSPECIFIED.Enum()}, "default_transport", false},
			{"transport unknown value", &rpmgrv1.InstanceSettings{DefaultTransport: rpmgrv1.TransportPolicy(9).Enum()}, "default_transport", false},
			{"alias not a URI", &rpmgrv1.InstanceSettings{PublicUrlAliases: []string{"not a uri"}}, "public_url_aliases", false},
			{"alias twice", &rpmgrv1.InstanceSettings{PublicUrlAliases: []string{"https://a.example", "https://a.example"}}, "public_url_aliases", false},
			{"alias ok", &rpmgrv1.InstanceSettings{PublicUrlAliases: []string{"https://a.example"}}, "public_url_aliases", true},
			{"too many endpoints", &rpmgrv1.InstanceSettings{ControllerEndpoints: strings.Split(strings.Repeat("https://x.example ", 9)+"https://y.example", " ")[:9]}, "controller_endpoints", false},
		} {
			_, err := settings.UpdateInstance(ctx, db, tt.upd, mask(tt.path), 0)
			if (err == nil) != tt.ok {
				t.Errorf("%s: %v, want ok=%v", tt.name, err, tt.ok)
			}
		}
		for _, bad := range []*fieldmaskpb.FieldMask{mask(), mask("no_such_field"), mask("leaf_certificate_lifetime.seconds"), nil} {
			if _, err := settings.UpdateInstance(ctx, db, lifetime(day), bad, 0); err == nil {
				t.Errorf("mask %v accepted", bad.GetPaths())
			}
		}
		if _, err := settings.UpdateInstance(context.Background(), db, lifetime(day), mask("leaf_certificate_lifetime"), 0); err == nil {
			t.Error("update without a scope accepted")
		}
	})
}

func TestOrgSettingsAreScoped(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		a, b := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		ctxA, ctxB := storetest.OrgCtx(t, a), storetest.OrgCtx(t, b)
		upd := &rpmgrv1.OrgSettings{RequireMfa: proto.Bool(true)}
		if _, err := settings.UpdateOrg(ctxA, db, a, upd, mask("require_mfa"), 0); err != nil {
			t.Fatal(err)
		}
		if s, etag, err := settings.Org(ctxA, db.Client(), a); err != nil || !s.GetRequireMfa() || etag != 1 {
			t.Errorf("org A: %v, etag %d, %v", s, etag, err)
		}
		// Org B sees only its own settings, the defaults, and cannot change org A's.
		if s, etag, err := settings.Org(ctxB, db.Client(), a); err != nil || s.GetRequireMfa() || etag != 0 {
			t.Errorf("org B reading org A: %v, etag %d, %v; want defaults", s, etag, err)
		}
		if _, err := settings.UpdateOrg(ctxB, db, a, &rpmgrv1.OrgSettings{}, mask("require_mfa"), 0); err == nil {
			t.Error("org B changed org A's settings")
		}
		if s, _, _ := settings.Org(ctxA, db.Client(), a); !s.GetRequireMfa() {
			t.Error("org A's settings changed by org B")
		}
		if _, err := settings.UpdateOrg(ctxA, db, a, &rpmgrv1.OrgSettings{DefaultGatewayGroupId: "nonsense"}, mask("default_gateway_group_id"), 0); err == nil {
			t.Error("invalid gateway group ID accepted")
		}
	})
}
