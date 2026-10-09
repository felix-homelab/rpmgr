// SPDX-License-Identifier: Apache-2.0

// Package settings reads and changes the runtime settings of the instance and of each org
// (docs/10-operations.md, "Runtime settings"). Settings are typed protobuf messages with
// protovalidate rules; a field that is not set has its default. Every change is a configuration
// transaction with a revision, because settings such as the default transport reach agents.
package settings

import (
	"context"
	"errors"
	"fmt"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/orgsetting"
)

// ErrEtagMismatch is returned when the settings changed since the caller read them
// (docs/07-api.md, "Concurrency").
var ErrEtagMismatch = errors.New("settings: changed since they were read")

const day = 24 * time.Hour

// InstanceDefaults returns the default instance settings (D4, D8, D45; docs/06-data-model.md).
func InstanceDefaults() *rpmgrv1.InstanceSettings {
	return &rpmgrv1.InstanceSettings{
		DefaultTransport:        rpmgrv1.TransportPolicy_TRANSPORT_POLICY_AUTO.Enum(),
		LeafCertificateLifetime: durationpb.New(7 * day),
		ExpiredCertificateGrace: durationpb.New(30 * day),
		PasswordHashProfile:     rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_DEFAULT.Enum(),
		ReleaseCheck:            proto.Bool(true),
		UpdateChannel:           rpmgrv1.UpdateChannel_UPDATE_CHANNEL_STABLE.Enum(),
		HourlyRollupRetention:   durationpb.New(30 * day),
		DailyRollupRetention:    durationpb.New(400 * day),
		AcmeDirectoryUrl:        proto.String(LetsEncrypt),
	}
}

// LetsEncrypt is Let's Encrypt's production ACME directory, the default CA of route certificates
// [F certmagic v0.25.6 acmeissuer.go:664].
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// OrgDefaults returns the default settings of an org.
func OrgDefaults() *rpmgrv1.OrgSettings {
	return &rpmgrv1.OrgSettings{RequireMfa: proto.Bool(false), OperatorsMayEnroll: proto.Bool(false)}
}

// Instance returns the effective instance settings, stored values over defaults, and their etag
// (0 while nothing is stored).
func Instance(ctx context.Context, c *ent.Client) (*rpmgrv1.InstanceSettings, int64, error) {
	stored := &rpmgrv1.InstanceSettings{}
	var version int64
	row, err := c.InstanceSetting.Get(ctx, 1)
	switch {
	case ent.IsNotFound(err):
	case err != nil:
		return nil, 0, err
	default:
		if err := proto.Unmarshal(row.Value, stored); err != nil {
			return nil, 0, fmt.Errorf("settings: stored instance settings: %w", err)
		}
		version = row.Version
	}
	return effective(InstanceDefaults(), stored).(*rpmgrv1.InstanceSettings), version, nil
}

// UpdateInstance applies the fields of upd that mask names; a named field that upd does not set
// returns to its default. etag must be the version the caller read, or 0 to skip the check.
func UpdateInstance(ctx context.Context, db *store.DB, upd *rpmgrv1.InstanceSettings, mask *fieldmaskpb.FieldMask, etag int64) (store.Revision, error) {
	return store.ConfigTx(ctx, db, func(tx *ent.Tx) ([]string, error) {
		stored := &rpmgrv1.InstanceSettings{}
		var version int64
		row, err := tx.InstanceSetting.Get(ctx, 1)
		switch {
		case ent.IsNotFound(err):
		case err != nil:
			return nil, err
		default:
			if err := proto.Unmarshal(row.Value, stored); err != nil {
				return nil, err
			}
			version = row.Version
		}
		value, err := apply(InstanceDefaults(), stored, upd, mask, etag, version)
		if err != nil {
			return nil, err
		}
		actor := actorOf(ctx)
		if version == 0 {
			err = tx.InstanceSetting.Create().SetID(1).SetValue(value).SetVersion(1).SetUpdatedBy(actor).Exec(ctx)
		} else {
			err = tx.InstanceSetting.UpdateOneID(1).SetValue(value).SetVersion(version + 1).SetUpdatedBy(actor).Exec(ctx)
		}
		return []string{"settings/instance"}, err
	})
}

// Org returns the effective settings of an org and their etag; the org comes from the scope.
func Org(ctx context.Context, c *ent.Client, orgID string) (*rpmgrv1.OrgSettings, int64, error) {
	stored := &rpmgrv1.OrgSettings{}
	var version int64
	row, err := c.OrgSetting.Query().Where(orgsetting.OrgID(orgID)).Only(ctx)
	switch {
	case ent.IsNotFound(err):
	case err != nil:
		return nil, 0, err
	default:
		if err := proto.Unmarshal(row.Value, stored); err != nil {
			return nil, 0, fmt.Errorf("settings: stored org settings: %w", err)
		}
		version = row.Version
	}
	return effective(OrgDefaults(), stored).(*rpmgrv1.OrgSettings), version, nil
}

// UpdateOrg is UpdateInstance for the settings of one org.
func UpdateOrg(ctx context.Context, db *store.DB, orgID string, upd *rpmgrv1.OrgSettings, mask *fieldmaskpb.FieldMask, etag int64) (store.Revision, error) {
	return store.ConfigTx(ctx, db, func(tx *ent.Tx) ([]string, error) {
		stored := &rpmgrv1.OrgSettings{}
		var version int64
		row, err := tx.OrgSetting.Query().Where(orgsetting.OrgID(orgID)).Only(ctx)
		switch {
		case ent.IsNotFound(err):
		case err != nil:
			return nil, err
		default:
			if err := proto.Unmarshal(row.Value, stored); err != nil {
				return nil, err
			}
			version = row.Version
		}
		value, err := apply(OrgDefaults(), stored, upd, mask, etag, version)
		if err != nil {
			return nil, err
		}
		actor := actorOf(ctx)
		if version == 0 {
			err = tx.OrgSetting.Create().SetOrgID(orgID).SetValue(value).SetVersion(1).SetUpdatedBy(actor).Exec(ctx)
		} else {
			err = tx.OrgSetting.UpdateOneID(row.ID).SetValue(value).SetVersion(version + 1).SetUpdatedBy(actor).Exec(ctx)
		}
		return []string{"settings/org/" + orgID}, err
	})
}

// apply returns the serialised stored settings after the masked update, once the effective
// settings pass validation.
func apply(defaults, stored, upd proto.Message, mask *fieldmaskpb.FieldMask, etag, version int64) ([]byte, error) {
	if etag != 0 && etag != version {
		return nil, ErrEtagMismatch
	}
	if len(mask.GetPaths()) == 0 {
		return nil, errors.New("settings: the update mask names no field")
	}
	fields := stored.ProtoReflect().Descriptor().Fields()
	next := proto.Clone(stored).ProtoReflect()
	src := upd.ProtoReflect()
	for _, path := range mask.GetPaths() {
		fd := fields.ByName(protoreflect.Name(path))
		if fd == nil {
			return nil, fmt.Errorf("settings: unknown field %q in the update mask", path)
		}
		if src.Has(fd) {
			next.Set(fd, src.Get(fd))
		} else {
			next.Clear(fd)
		}
	}
	if err := protovalidate.Validate(effective(defaults, next.Interface())); err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(next.Interface())
}

// effective returns defaults with every field that stored sets replaced by the stored value.
func effective(defaults, stored proto.Message) proto.Message {
	out := proto.Clone(defaults).ProtoReflect()
	stored.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		out.Set(fd, v)
		return true
	})
	return out.Interface()
}

func actorOf(ctx context.Context) string {
	if s, ok := authz.FromContext(ctx); ok {
		return s.Actor()
	}
	return "unknown"
}
