// SPDX-License-Identifier: Apache-2.0

package settings_test

import (
	"context"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// hungWrapper is a local KEK whose Wrap waits until release is closed, as a Transit that does not
// answer does.
type hungWrapper struct {
	secret.Wrapper
	entered chan struct{}
	release chan struct{}
}

func (w *hungWrapper) Wrap(ctx context.Context, dk, aad []byte) ([]byte, error) {
	select {
	case w.entered <- struct{}{}:
	default:
	}
	select {
	case <-w.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return w.Wrapper.Wrap(ctx, dk, aad)
}

// TestSealIsOutsideTheWriteTransaction: a secret whose seal waits for the key service holds no
// write transaction, so an unrelated write goes through meanwhile (on SQLite there is one writer),
// and the secret is stored once the key service answers.
func TestSealIsOutsideTheWriteTransaction(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		sys := storetest.SystemCtx(t)
		kek, err := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		w := &hungWrapper{Wrapper: secret.NewLocalWrapper(kek), entered: make(chan struct{}, 1), release: make(chan struct{})}
		sealer, err := secret.NewSealerWith(w)
		if err != nil {
			t.Fatal(err)
		}
		set := make(chan error, 1)
		go func() { set <- settings.SetInstanceSecret(sys, db, sealer, settings.SMTPPassword, secret.New("pw")) }()
		<-w.entered
		other := make(chan error, 1)
		go func() {
			other <- store.WriteTx(sys, db, func(tx *ent.Tx) error {
				return tx.InstanceSecret.Create().SetID("unrelated").SetValueEnc([]byte("x")).SetUpdatedAt(time.Now()).Exec(sys)
			})
		}()
		select {
		case err := <-other:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("an unrelated write waits for a seal that waits for the key service")
		}
		close(w.release)
		if err := <-set; err != nil {
			t.Fatal(err)
		}
		if v, err := settings.InstanceSecret(sys, db.Client(), sealer, settings.SMTPPassword); err != nil || v.Reveal() != "pw" { //nolint:forbidigo // the test reads back what it stored
			t.Fatalf("read back: %q %v", v.Reveal(), err) //nolint:forbidigo // as above
		}
	})
}
