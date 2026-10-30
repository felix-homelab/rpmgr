// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net/url"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	eauditsink "github.com/felix-homelab/rpmgr/internal/store/ent/auditsink"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// AuditSinks is AuditSinkService. A sink is an instance row, which its methods read and write in
// the controller's system scope; the interceptor audits every change in the instance chain, with
// the secret redacted.
type AuditSinks struct {
	rpmgrv1connect.UnimplementedAuditSinkServiceHandler
	DB     *store.DB
	API    *api.Server
	Sys    context.Context
	Sealer *secret.Sealer
	// Sender delivers the test item, as the job's sender delivers the sink's items.
	Sender *webhook.Sender
	Now    func() time.Time
	Logger *slog.Logger
}

func (a *AuditSinks) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// sinkSecretContext binds a sealed secret to its row (docs/04-security.md, "Secrets at rest").
func sinkSecretContext(id string) secret.Context {
	return secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: id}
}

// sinkVersion is a number that changes with every change of the sink's fields, which an etag
// carries; the secret counts through its sealed bytes, which differ at every seal.
func sinkVersion(r *ent.AuditSink) int64 {
	h := sha256.New()
	for _, s := range []string{r.ID, r.Name, r.Settings["url"], r.Settings["address"], r.Settings["ca"], r.Settings["endpoint"], r.Settings["region"],
		r.Settings["bucket"], r.Settings["access_key_id"], r.Settings["lock_days"], fmt.Sprint(r.Entries, r.Enabled)} {
		_, _ = fmt.Fprintf(h, "%d:%s", len(s), s)
	}
	if r.SecretEnc != nil {
		h.Write(*r.SecretEnc)
	}
	return int64(binary.BigEndian.Uint64(h.Sum(nil)) >> 1)
}

// sinkOf is the API's sink: the secret never leaves the row.
func sinkOf(r *ent.AuditSink, b *auditsink.Backlog) *rpmgrv1.AuditSink {
	kind := rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_WEBHOOK
	switch r.Kind {
	case eauditsink.KindSyslog:
		kind = rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_SYSLOG
	case eauditsink.KindS3:
		kind = rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_S3
	}
	s3 := auditsink.S3SettingsOf(r.Settings)
	out := &rpmgrv1.AuditSink{Id: r.ID, Name: r.Name, Kind: kind, Url: r.Settings["url"], Address: r.Settings["address"],
		CaBundle: r.Settings["ca"], Endpoint: s3.Endpoint, Region: s3.Region, Bucket: s3.Bucket, AccessKeyId: s3.AccessKeyID,
		RetentionDays: lockDays(s3.LockDays), SecretSet: r.SecretEnc != nil && len(*r.SecretEnc) > 0, Entries: r.Entries, Enabled: r.Enabled,
		CreateTime: timestamppb.New(r.CreatedAt), Etag: etagOf(sinkVersion(r))}
	st := &rpmgrv1.AuditSinkStatus{LastError: r.LastError}
	if r.LastSuccessAt != nil {
		st.LastSuccessTime = timestamppb.New(*r.LastSuccessAt)
	}
	if b != nil {
		st.Backlog = b.Items
		if !b.Oldest.IsZero() {
			st.OldestUnshippedTime = timestamppb.New(b.Oldest)
		}
		for _, c := range b.Chains {
			cs := &rpmgrv1.AuditSinkChainStatus{Chain: c.Chain, CheckpointSeq: c.CheckpointSeq, EntrySeq: c.EntrySeq, Backlog: c.Items}
			if !c.Oldest.IsZero() {
				cs.OldestUnshippedTime = timestamppb.New(c.Oldest)
			}
			st.Chains = append(st.Chains, cs)
		}
	}
	out.Status = st
	return out
}

// lockDays is a retention in days for the API; a value outside the int32 range, which the lock
// rules never allow, shows as zero.
func lockDays(n int) int32 {
	if n < 0 || n > math.MaxInt32 {
		return 0
	}
	return int32(n)
}

func badSink(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: "+format, args...))
}

// checkWebhookURL refuses a URL a delivery can never use: the sender only posts to https:// URLs
// without credentials. Where the host lies is the egress guard's concern, at delivery.
func checkWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case raw == "":
		return badSink("a webhook sink needs a url")
	case err != nil || u.Host == "" || u.Hostname() == "":
		return badSink("the url does not parse")
	case u.Scheme != "https" || u.User != nil:
		return badSink("only https:// URLs without credentials are delivered to")
	}
	return nil
}

// checkSyslog refuses an address or CA bundle a syslog sink can never use, and a field of another
// kind.
func checkSyslog(address, ca, url, secret string) error {
	if url != "" || secret != "" {
		return badSink("a syslog sink has no url and no secret")
	}
	if err := auditsink.CheckSyslogSettings(address, ca); err != nil {
		return badSink("%v", err)
	}
	return nil
}

// s3Fields reports whether a request sets a field only an object-storage sink has.
func s3Fields(in *rpmgrv1.AuditSink) bool {
	return in.GetEndpoint() != "" || in.GetRegion() != "" || in.GetBucket() != "" || in.GetAccessKeyId() != "" || in.GetRetentionDays() != 0
}

// s3SettingsOf is the object-storage settings a message holds.
func s3SettingsOf(in *rpmgrv1.AuditSink) auditsink.S3Settings {
	return auditsink.S3Settings{Endpoint: in.GetEndpoint(), Region: in.GetRegion(), Bucket: in.GetBucket(), AccessKeyID: in.GetAccessKeyId(),
		CA: in.GetCaBundle(), LockDays: int(in.GetRetentionDays())}
}

// checkS3 refuses what an object-storage sink cannot use, then checks the bucket: one without Object
// Lock or without conditional create is refused and nothing is saved. A store that cannot be
// reached is Unavailable, not a verdict on the settings.
func (a *AuditSinks) checkS3(ctx context.Context, set auditsink.S3Settings, key secret.Value) error {
	if err := checkSecretLen(key.Len()); err != nil {
		return err
	}
	err := auditsink.CheckSettingsAndBucket(ctx, set, key, a.now)
	var unreachable *auditsink.UnreachableError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &unreachable) || ctx.Err() != nil:
		return connect.NewError(connect.CodeUnavailable, fmt.Errorf("apisvc: the sink was not saved: %s", auditsink.Describe(err)))
	}
	return badSink("%s", auditsink.Describe(err))
}

// checkSecret refuses a secret too short to sign with.
func checkSecret(s string) error { return checkSecretLen(len(s)) }

func checkSecretLen(n int) error {
	if n < 16 {
		return badSink("the secret must be at least 16 bytes")
	}
	return nil
}

// backlogs returns the status of the sinks by ID.
func (a *AuditSinks) backlogs(ctx context.Context) (map[string]*auditsink.Backlog, error) {
	bs, err := auditsink.Backlogs(ctx, a.DB)
	if err != nil {
		return nil, storeError(err)
	}
	out := make(map[string]*auditsink.Backlog, len(bs))
	for i := range bs {
		out[bs[i].SinkID] = &bs[i]
	}
	return out, nil
}

// CreateAuditSink implements AuditSinkService.
func (a *AuditSinks) CreateAuditSink(ctx context.Context, req *connect.Request[rpmgrv1.CreateAuditSinkRequest]) (
	*connect.Response[rpmgrv1.CreateAuditSinkResponse], error) {
	in := req.Msg.GetAuditSink()
	if in.GetName() == "" && in.GetKind() != rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_UNSPECIFIED {
		return nil, badSink("a sink needs a name")
	}
	id := ids.New("ask")
	var sealed []byte
	var kind eauditsink.Kind
	settings := map[string]string{}
	if in.GetKind() != rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_S3 && s3Fields(in) {
		return nil, badSink("only an object-storage sink has an endpoint, region, bucket, access key ID and lock period")
	}
	switch in.GetKind() {
	case rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_WEBHOOK:
		if err := checkWebhookURL(in.GetUrl()); err != nil {
			return nil, err
		}
		if in.GetAddress() != "" || in.GetCaBundle() != "" {
			return nil, badSink("a webhook sink has no address and no CA bundle")
		}
		if err := checkSecret(in.GetSecret()); err != nil {
			return nil, err
		}
		var err error
		if sealed, err = a.Sealer.Seal(sinkSecretContext(id), secret.New(in.GetSecret())); err != nil {
			return nil, err
		}
		kind, settings["url"] = eauditsink.KindWebhook, in.GetUrl()
	case rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_SYSLOG:
		if err := checkSyslog(in.GetAddress(), in.GetCaBundle(), in.GetUrl(), in.GetSecret()); err != nil {
			return nil, err
		}
		kind, settings["address"] = eauditsink.KindSyslog, in.GetAddress()
		if in.GetCaBundle() != "" {
			settings["ca"] = in.GetCaBundle()
		}
	case rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_S3:
		if in.GetUrl() != "" || in.GetAddress() != "" {
			return nil, badSink("an object-storage sink has no url and no address")
		}
		set := s3SettingsOf(in)
		if err := a.checkS3(ctx, set, secret.New(in.GetSecret())); err != nil {
			return nil, err
		}
		var err error
		if sealed, err = a.Sealer.Seal(sinkSecretContext(id), secret.New(in.GetSecret())); err != nil {
			return nil, err
		}
		kind, settings = eauditsink.KindS3, set.Map()
	default:
		return nil, badSink("the kind must be a sink kind this controller offers: webhook, syslog or s3")
	}
	sys := store.CarryTxHook(a.Sys, ctx)
	var row *ent.AuditSink
	err := store.WriteTx(sys, a.DB, func(tx *ent.Tx) (err error) {
		q := tx.AuditSink.Create().SetID(id).SetKind(kind).SetName(in.GetName()).SetSettings(settings).SetEntries(in.GetEntries()).SetEnabled(true)
		if sealed != nil {
			q.SetSecretEnc(sealed)
		}
		row, err = q.Save(sys)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.CreateAuditSinkResponse{AuditSink: sinkOf(row, nil)}), nil
}

// GetAuditSink implements AuditSinkService.
func (a *AuditSinks) GetAuditSink(ctx context.Context, req *connect.Request[rpmgrv1.GetAuditSinkRequest]) (
	*connect.Response[rpmgrv1.GetAuditSinkResponse], error) {
	sys := store.CarryTxHook(a.Sys, ctx)
	row, err := a.DB.ReadClient().AuditSink.Get(sys, req.Msg.GetAuditSinkId())
	if err != nil {
		return nil, storeError(err)
	}
	bs, err := a.backlogs(sys)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.GetAuditSinkResponse{AuditSink: sinkOf(row, bs[row.ID])}), nil
}

// ListAuditSinks implements AuditSinkService.
func (a *AuditSinks) ListAuditSinks(ctx context.Context, req *connect.Request[rpmgrv1.ListAuditSinksRequest]) (
	*connect.Response[rpmgrv1.ListAuditSinksResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := a.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	sys := store.CarryTxHook(a.Sys, ctx)
	q := a.DB.ReadClient().AuditSink.Query().Order(ent.Asc(eauditsink.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(eauditsink.IDGT(after))
	}
	rows, err := q.All(sys)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListAuditSinksResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = a.API.PageToken(rows[size-1].ID, m)
	}
	bs, err := a.backlogs(sys)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out.AuditSinks = append(out.AuditSinks, sinkOf(r, bs[r.ID]))
	}
	return connect.NewResponse(out), nil
}

// sinkMask is the fields an update may name.
var sinkMask = []string{"name", "url", "secret", "address", "ca_bundle", "entries", "enabled", "endpoint", "region", "bucket", "access_key_id", "retention_days"}

// mergeSink applies the update to the sink as it is and returns the result with the settings the
// row keeps; the checks that need no store are made here.
func mergeSink(cur *ent.AuditSink, m *rpmgrv1.UpdateAuditSinkRequest) (*rpmgrv1.AuditSink, map[string]string, error) {
	in := m.GetAuditSink()
	if err := api.CheckEtag(m.GetEtag(), sinkVersion(cur), api.Redact(sinkOf(cur, nil))); err != nil {
		return nil, nil, err
	}
	next := sinkOf(cur, nil)
	if err := api.ApplyMask(next, in, m.GetUpdateMask(), sinkMask...); err != nil {
		return nil, nil, err
	}
	if next.GetName() == "" {
		return nil, nil, badSink("a sink needs a name")
	}
	paths := m.GetUpdateMask().GetPaths()
	has := func(fields ...string) bool {
		return slices.ContainsFunc(fields, func(f string) bool { return slices.Contains(paths, f) })
	}
	settings := map[string]string{}
	switch cur.Kind {
	case eauditsink.KindSyslog:
		if has("url", "secret") || has("endpoint", "region", "bucket", "access_key_id", "retention_days") {
			return nil, nil, badSink("a syslog sink has only an address and a CA bundle")
		}
		if err := checkSyslog(next.GetAddress(), next.GetCaBundle(), "", ""); err != nil {
			return nil, nil, err
		}
		settings["address"] = next.GetAddress()
		if next.GetCaBundle() != "" {
			settings["ca"] = next.GetCaBundle()
		}
	case eauditsink.KindS3:
		if has("url", "address") {
			return nil, nil, badSink("an object-storage sink has no url and no address")
		}
		settings = s3SettingsOf(next).Map()
	default:
		if has("address", "ca_bundle", "endpoint", "region", "bucket", "access_key_id", "retention_days") {
			return nil, nil, badSink("a webhook sink has only a url and a secret")
		}
		if err := checkWebhookURL(next.GetUrl()); err != nil {
			return nil, nil, err
		}
		settings["url"] = next.GetUrl()
	}
	return next, settings, nil
}

// UpdateAuditSink implements AuditSinkService. A new secret replaces the stored one; the etag is
// checked in the transaction that writes. An object-storage sink whose settings or secret key
// change is checked against its bucket first, outside the transaction, which must then find the
// sink as it was checked.
func (a *AuditSinks) UpdateAuditSink(ctx context.Context, req *connect.Request[rpmgrv1.UpdateAuditSinkRequest]) (
	*connect.Response[rpmgrv1.UpdateAuditSinkResponse], error) {
	m := req.Msg
	in := m.GetAuditSink()
	sys := store.CarryTxHook(a.Sys, ctx)
	paths := m.GetUpdateMask().GetPaths()
	var checked int64
	if pre, err := a.DB.ReadClient().AuditSink.Get(sys, in.GetId()); err == nil && pre.Kind == eauditsink.KindS3 {
		next, settings, err := mergeSink(pre, m)
		if err != nil {
			return nil, err
		}
		newSecret := slices.Contains(paths, "secret")
		if newSecret || !maps.Equal(settings, pre.Settings) {
			key := secret.New(in.GetSecret())
			if !newSecret {
				v, err := a.Sealer.Open(sinkSecretContext(pre.ID), *pre.SecretEnc)
				if err != nil {
					return nil, badSink("the stored secret key cannot be opened; set it again")
				}
				key = v
			}
			if err := a.checkS3(ctx, s3SettingsOf(next), key); err != nil {
				return nil, err
			}
			checked = sinkVersion(pre)
		}
	}
	var row *ent.AuditSink
	err := store.WriteTx(sys, a.DB, func(tx *ent.Tx) error {
		cur, err := tx.AuditSink.Get(sys, in.GetId())
		if err != nil {
			return err
		}
		if checked != 0 && sinkVersion(cur) != checked {
			return connect.NewError(connect.CodeAborted, errors.New("apisvc: the sink changed while its bucket was checked; try again"))
		}
		next, settings, err := mergeSink(cur, m)
		if err != nil {
			return err
		}
		u := tx.AuditSink.UpdateOneID(cur.ID).SetName(next.GetName()).SetSettings(settings).
			SetEntries(next.GetEntries()).SetEnabled(next.GetEnabled())
		if slices.Contains(paths, "secret") {
			if err := checkSecret(in.GetSecret()); err != nil {
				return err
			}
			sealed, err := a.Sealer.Seal(sinkSecretContext(cur.ID), secret.New(in.GetSecret()))
			if err != nil {
				return err
			}
			u.SetSecretEnc(sealed)
		}
		row, err = u.Save(sys)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	bs, err := a.backlogs(sys)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&rpmgrv1.UpdateAuditSinkResponse{AuditSink: sinkOf(row, bs[row.ID])}), nil
}

// DeleteAuditSink implements AuditSinkService; the sink's cursors go with it.
func (a *AuditSinks) DeleteAuditSink(ctx context.Context, req *connect.Request[rpmgrv1.DeleteAuditSinkRequest]) (
	*connect.Response[rpmgrv1.DeleteAuditSinkResponse], error) {
	sys := store.CarryTxHook(a.Sys, ctx)
	err := store.WriteTx(sys, a.DB, func(tx *ent.Tx) error {
		cur, err := tx.AuditSink.Get(sys, req.Msg.GetAuditSinkId())
		if err != nil {
			return err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), sinkVersion(cur), api.Redact(sinkOf(cur, nil))); err != nil {
			return err
		}
		return tx.AuditSink.DeleteOneID(cur.ID).Exec(sys)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteAuditSinkResponse{}), nil
}

// TestAuditSink implements AuditSinkService: the answer says whether the receiver acknowledged a
// test item; a failure is the answer, not an error of the call.
func (a *AuditSinks) TestAuditSink(ctx context.Context, req *connect.Request[rpmgrv1.TestAuditSinkRequest]) (
	*connect.Response[rpmgrv1.TestAuditSinkResponse], error) {
	sys := store.CarryTxHook(a.Sys, ctx)
	row, err := a.DB.ReadClient().AuditSink.Get(sys, req.Msg.GetAuditSinkId())
	if err != nil {
		return nil, storeError(err)
	}
	logger := a.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	r := auditsink.NewRunner(auditsink.Options{DB: a.DB, Sealer: a.Sealer, Sender: a.Sender, Now: a.now, Logger: logger})
	if err := r.Test(ctx, row); err != nil {
		var cerr *connect.Error
		if errors.As(err, &cerr) {
			return nil, err
		}
		return connect.NewResponse(&rpmgrv1.TestAuditSinkResponse{Error: auditsink.Describe(err)}), nil
	}
	return connect.NewResponse(&rpmgrv1.TestAuditSinkResponse{Ok: true}), nil
}
