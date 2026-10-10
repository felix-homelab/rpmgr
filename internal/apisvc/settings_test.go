// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestInstanceSettings (docs/10-operations.md, "Runtime settings"; docs/04-security.md, "Leaf
// certificates"): the Instance Admin reads the settings with their defaults and changes the
// fields a mask names, within their ranges, under the etag; a revision of the instance belongs to
// no org; the SMTP password is write-only, kept under the KEK and recorded for KEK rotation; no
// one else reads or changes them.
func TestInstanceSettings(t *testing.T) {
	e, ada, _, _ := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	got, err := ada.set.GetInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.GetInstanceSettingsRequest{}))
	if err != nil || got.Msg.GetSettings().GetDefaultTransport() != rpmgrv1.TransportPolicy_TRANSPORT_POLICY_AUTO ||
		got.Msg.GetSettings().GetLeafCertificateLifetime().AsDuration() != 7*24*time.Hour || got.Msg.GetSmtpPasswordSet() {
		t.Fatalf("the defaults: %v %v", got, err)
	}
	etag := got.Msg.GetEtag()
	update := func(paths []string, in *rpmgrv1.InstanceSettings, etag string) (*rpmgrv1.UpdateInstanceSettingsResponse, error) {
		r, err := ada.set.UpdateInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.UpdateInstanceSettingsRequest{Settings: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	days := func(n int) *durationpb.Duration { return durationpb.New(time.Duration(n) * 24 * time.Hour) }
	for _, c := range []struct {
		field string
		in    *rpmgrv1.InstanceSettings
		ok    bool
	}{
		{"leaf_certificate_lifetime", &rpmgrv1.InstanceSettings{LeafCertificateLifetime: days(0)}, false},
		{"leaf_certificate_lifetime", &rpmgrv1.InstanceSettings{LeafCertificateLifetime: days(1)}, true},
		{"leaf_certificate_lifetime", &rpmgrv1.InstanceSettings{LeafCertificateLifetime: days(30)}, true},
		{"leaf_certificate_lifetime", &rpmgrv1.InstanceSettings{LeafCertificateLifetime: days(31)}, false},
		{"expired_certificate_grace", &rpmgrv1.InstanceSettings{ExpiredCertificateGrace: days(0)}, true},
		{"expired_certificate_grace", &rpmgrv1.InstanceSettings{ExpiredCertificateGrace: days(90)}, true},
		{"expired_certificate_grace", &rpmgrv1.InstanceSettings{ExpiredCertificateGrace: days(91)}, false},
	} {
		_, err := update([]string{c.field}, c.in, "")
		if c.ok != (err == nil) || !c.ok && code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s %v: %v", c.field, c.in, err)
		}
	}
	up, err := update([]string{"default_transport"}, &rpmgrv1.InstanceSettings{DefaultTransport: rpmgrv1.TransportPolicy_TRANSPORT_POLICY_H2.Enum()}, "")
	if err != nil || up.GetSettings().GetDefaultTransport() != rpmgrv1.TransportPolicy_TRANSPORT_POLICY_H2 ||
		up.GetSettings().GetExpiredCertificateGrace().AsDuration() != 90*24*time.Hour || up.GetEtag() == etag {
		t.Fatalf("a new default transport: %v %v", up, err)
	}
	if r := c.ConfigRevision.GetX(e.sys, up.GetRevision().GetSeq()); r.OrgID != nil {
		t.Errorf("an instance setting's revision belongs to org %s", *r.OrgID)
	}
	// A field the mask names but the request does not set returns to its default.
	if up, err := update([]string{"default_transport"}, &rpmgrv1.InstanceSettings{}, up.GetEtag()); err != nil ||
		up.GetSettings().GetDefaultTransport() != rpmgrv1.TransportPolicy_TRANSPORT_POLICY_AUTO {
		t.Fatalf("back to the default: %v %v", up, err)
	}
	if _, err := update([]string{"release_check"}, &rpmgrv1.InstanceSettings{}, etag); code(err) != connect.CodeFailedPrecondition ||
		reason(err) != api.ReasonEtagMismatch {
		t.Errorf("a stale etag: %v", err)
	}
	if _, err := update([]string{"no_such_field"}, &rpmgrv1.InstanceSettings{}, ""); code(err) != connect.CodeInvalidArgument {
		t.Errorf("an unknown field: %v", err)
	}

	// The SMTP password: write-only, under the KEK, recorded for KEK rotation.
	const smtpPW = "relay password 42"
	setPW := func(b *browser, pw string) error {
		_, err := b.set.SetSmtpPassword(ctx, connect.NewRequest(&rpmgrv1.SetSmtpPasswordRequest{Password: pw}))
		return err
	}
	if err := setPW(ada, smtpPW); err != nil {
		t.Fatal(err)
	}
	recorded := func() int {
		return c.SecretMeta.Query().Where(secretmeta.TableName("instance_secrets"), secretmeta.RowID("smtp_password")).CountX(e.sys)
	}
	if got, err := ada.set.GetInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.GetInstanceSettingsRequest{})); err != nil ||
		!got.Msg.GetSmtpPasswordSet() || strings.Contains(got.Msg.String(), smtpPW) || recorded() != 1 {
		t.Fatalf("a password set: %v %v, %d records", got, err, recorded())
	}
	if err := setPW(ada, ""); err != nil {
		t.Fatal(err)
	}
	if got, err := ada.set.GetInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.GetInstanceSettingsRequest{})); err != nil ||
		got.Msg.GetSmtpPasswordSet() || recorded() != 0 {
		t.Fatalf("a password removed: %v %v, %d records", got, err, recorded())
	}
	for _, a := range c.AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.SettingsService.SetSmtpPassword")).AllX(e.sys) {
		if strings.Contains(a.Diff, smtpPW) {
			t.Fatal("the audit log holds the SMTP password")
		}
	}

	// An Owner who is no Instance Admin.
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := bob.set.GetInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.GetInstanceSettingsRequest{})); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner reads the instance settings: %v", err)
	}
	if err := setPW(bob, smtpPW); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Owner sets the SMTP password: %v", err)
	}
}

// TestOrgSettings (docs/10-operations.md, "Runtime settings"; docs/04-security.md, "Roles"): an
// Owner changes the org's settings, a change of the MFA requirement after a step-up; members
// read them; an Admin changes nothing; a default gateway group must be one of the org's.
func TestOrgSettings(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	update := func(b *browser, paths []string, in *rpmgrv1.OrgSettings) (*rpmgrv1.UpdateOrgSettingsResponse, error) {
		r, err := b.set.UpdateOrgSettings(ctx, connect.NewRequest(&rpmgrv1.UpdateOrgSettingsRequest{OrgId: org, Settings: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	up, err := update(ada, []string{"operators_may_enroll", "default_gateway_group_id"},
		&rpmgrv1.OrgSettings{OperatorsMayEnroll: proto.Bool(true), DefaultGatewayGroupId: group})
	if err != nil || !up.GetSettings().GetOperatorsMayEnroll() || up.GetSettings().GetDefaultGatewayGroupId() != group || up.GetRevision().GetSeq() == 0 {
		t.Fatalf("an Owner's change: %v %v", up, err)
	}
	if _, err := update(ada, []string{"require_mfa"}, &rpmgrv1.OrgSettings{RequireMfa: proto.Bool(true)}); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("the MFA requirement without a step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if up, err := update(ada, []string{"require_mfa"}, &rpmgrv1.OrgSettings{RequireMfa: proto.Bool(true)}); err != nil || !up.GetSettings().GetRequireMfa() {
		t.Fatalf("the MFA requirement after a step-up: %v %v", up, err)
	}

	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	theirs, err := bob.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: orgB,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "b"}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := update(ada, []string{"default_gateway_group_id"}, &rpmgrv1.OrgSettings{DefaultGatewayGroupId: theirs.Msg.GetGatewayGroup().GetId()}); code(err) != connect.CodeNotFound {
		t.Errorf("another org's gateway group: %v", err)
	}
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if _, err := update(adm, []string{"operators_may_enroll"}, &rpmgrv1.OrgSettings{}); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Admin's change: %v", err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	got, err := vwr.set.GetOrgSettings(ctx, connect.NewRequest(&rpmgrv1.GetOrgSettingsRequest{OrgId: org}))
	if err != nil || !got.Msg.GetSettings().GetRequireMfa() || got.Msg.GetEtag() != "2" {
		t.Fatalf("a Viewer reads: %v %v", got, err)
	}
}
