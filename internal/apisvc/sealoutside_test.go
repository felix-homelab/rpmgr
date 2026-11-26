// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/kms"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
)

// gateWrapper is a local KEK whose Wrap can be made to wait or fail, as a Transit that does not
// answer does. The call that waits is the one numbered blockAt since arm, counted from 1.
type gateWrapper struct {
	secret.Wrapper
	armed   atomic.Bool
	calls   atomic.Int32
	blockAt int32
	entered chan struct{}
	release chan struct{}
	down    atomic.Bool
}

func newGate(kek secret.KEK, blockAt int32) *gateWrapper {
	return &gateWrapper{Wrapper: secret.NewLocalWrapper(kek), blockAt: blockAt, entered: make(chan struct{}, 1), release: make(chan struct{})}
}

func (g *gateWrapper) arm() { g.calls.Store(0); g.armed.Store(true) }

func (g *gateWrapper) Wrap(ctx context.Context, dk, aad []byte) ([]byte, error) {
	if g.down.Load() {
		return nil, fmt.Errorf("%w: test outage", kms.ErrUnavailable)
	}
	if g.armed.Load() && g.calls.Add(1) == g.blockAt && g.armed.CompareAndSwap(true, false) {
		g.entered <- struct{}{}
		select {
		case <-g.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return g.Wrapper.Wrap(ctx, dk, aad)
}

func (g *gateWrapper) Unwrap(ctx context.Context, wr, aad []byte) ([]byte, error) {
	if g.down.Load() {
		return nil, fmt.Errorf("%w: test outage", kms.ErrUnavailable)
	}
	return g.Wrapper.Unwrap(ctx, wr, aad)
}

func gateFor(t *testing.T, blockAt int32) *gateWrapper {
	t.Helper()
	kek, err := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return newGate(kek, blockAt)
}

// unrelatedWriteGoesThrough fails the test if a write of another row waits while a seal does.
func unrelatedWriteGoesThrough(t *testing.T, e *env) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
			return tx.InstanceSecret.Create().SetID("unrelated").SetValueEnc([]byte("x")).SetUpdatedAt(time.Now()).Exec(e.sys)
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an unrelated write waits for a seal that waits for the key service")
	}
}

// TestAuditSinkUpdateSealsOutsideTheTransaction: a new secret of a sink is sealed before the write
// transaction, so a key service that does not answer holds no writer; the sink then has the secret
// and its KEK version is recorded.
func TestAuditSinkUpdateSealsOutsideTheTransaction(t *testing.T) {
	e := newEnv(t)
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	recv := newSinkReceiver(t, e)
	r, err := ada.sink.CreateAuditSink(ctx, connect.NewRequest(&rpmgrv1.CreateAuditSinkRequest{AuditSink: &rpmgrv1.AuditSink{Name: "siem",
		Kind: rpmgrv1.AuditSinkKind_AUDIT_SINK_KIND_WEBHOOK, Url: recv.url, Secret: sinkKey, Entries: true}}))
	if err != nil {
		t.Fatal(err)
	}
	id := r.Msg.GetAuditSink().GetId()
	if n := e.db.Client().SecretMeta.Query().Where(secretmeta.TableName("audit_sinks"), secretmeta.RowID(id)).CountX(e.sys); n != 1 {
		t.Fatalf("%d secrets_meta rows of the new sink, want 1 for `kek status`", n)
	}
	g := gateFor(t, 1)
	sealer, err := secret.NewSealerWith(g)
	if err != nil {
		t.Fatal(err)
	}
	e.sinks.Sealer = sealer
	g.arm()
	upd := make(chan error, 1)
	go func() {
		_, err := ada.sink.UpdateAuditSink(ctx, connect.NewRequest(&rpmgrv1.UpdateAuditSinkRequest{
			AuditSink:  &rpmgrv1.AuditSink{Id: id, Secret: "another-signing-secret-for-tests"},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"secret"}}}))
		upd <- err
	}()
	<-g.entered
	unrelatedWriteGoesThrough(t, e)
	close(g.release)
	if err := <-upd; err != nil {
		t.Fatal(err)
	}
	row := e.db.Client().AuditSink.GetX(e.sys, id)
	if v, err := sealer.Open(ctx, secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: id}, *row.SecretEnc); err != nil || v.Reveal() != "another-signing-secret-for-tests" { //nolint:forbidigo // the test reads back what it stored
		t.Fatalf("the new secret is not stored: %v", err)
	}
	// Deleting the sink drops its record.
	if _, err := ada.sink.DeleteAuditSink(ctx, connect.NewRequest(&rpmgrv1.DeleteAuditSinkRequest{AuditSinkId: id})); err != nil {
		t.Fatal(err)
	}
	if n := e.db.Client().SecretMeta.Query().Where(secretmeta.TableName("audit_sinks"), secretmeta.RowID(id)).CountX(e.sys); n != 0 {
		t.Errorf("%d secrets_meta rows of a deleted sink", n)
	}
}

// TestWebhookRotationVersionGuard: a rotation that read an endpoint before another rotation
// finished is refused with ABORTED and changes nothing, so the first one's secret, the one shown
// to its caller, stays the endpoint's; a key service that is down is UNAVAILABLE, not INTERNAL; the
// endpoint's sealed values are recorded for `kek status`.
func TestWebhookRotationVersionGuard(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	w, _ := newHook(t, e, ada, org, hookURL)
	id := w.GetId()
	if n := e.db.Client().SecretMeta.Query().Where(secretmeta.TableName("webhooks"), secretmeta.RowID(id)).CountX(e.sys); n != 1 {
		t.Fatalf("%d secrets_meta rows of the new endpoint, want 1", n)
	}
	rotate := func() (string, error) {
		r, err := ada.wh.RotateWebhookSecret(ctx, connect.NewRequest(&rpmgrv1.RotateWebhookSecretRequest{WebhookId: id}))
		if err != nil {
			return "", err
		}
		return r.Msg.GetSecret(), nil
	}
	// Rotation A seals the new secret (call 1), reads the endpoint, opens it and seals the old one
	// (call 2): it waits there, between its read and its write.
	g := gateFor(t, 2)
	sealer, err := secret.NewSealerWith(g)
	if err != nil {
		t.Fatal(err)
	}
	// The endpoint's current secret is sealed under the test KEK of the env; the gate must open it.
	old := e.db.Client().Webhook.GetX(e.sys, id)
	plain, err := e.sealer.Open(ctx, secret.Context{Table: "webhooks", Column: "secret_enc", RowID: id}, old.SecretEnc)
	if err != nil {
		t.Fatal(err)
	}
	resealed, err := sealer.Seal(ctx, secret.Context{Table: "webhooks", Column: "secret_enc", RowID: id}, plain)
	if err != nil {
		t.Fatal(err)
	}
	e.db.Client().Webhook.UpdateOneID(id).SetSecretEnc(resealed).ExecX(e.sys)
	e.webhooks.Sealer = sealer
	g.arm()
	type result struct {
		secret string
		err    error
	}
	a := make(chan result, 1)
	go func() { s, err := rotate(); a <- result{s, err} }()
	<-g.entered
	second, err := rotate() // rotation B, from the same version, finishes first
	if err != nil {
		t.Fatal(err)
	}
	close(g.release)
	if res := <-a; connect.CodeOf(res.err) != connect.CodeAborted {
		t.Fatalf("the rotation that read the old version: %v, want ABORTED", res.err)
	}
	row := e.db.Client().Webhook.GetX(e.sys, id)
	if v, err := sealer.Open(ctx, secret.Context{Table: "webhooks", Column: "secret_enc", RowID: id}, row.SecretEnc); err != nil || v.Reveal() != second { //nolint:forbidigo // the test compares with the secret it was shown
		t.Fatalf("the endpoint's secret is not the one the first rotation showed: %v", err)
	}
	if n := e.db.Client().SecretMeta.Query().Where(secretmeta.TableName("webhooks"), secretmeta.RowID(id), secretmeta.ColumnName("previous_secret_enc")).CountX(e.sys); n != 1 {
		t.Errorf("%d secrets_meta rows of the previous secret", n)
	}
	g.down.Store(true)
	if _, err := rotate(); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a rotation with the key service down: %v, want UNAVAILABLE", err)
	}
}

