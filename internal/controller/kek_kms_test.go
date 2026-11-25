// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/kms"
	"github.com/felix-homelab/rpmgr/internal/kms/kmstest"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

const kmsVersion1 = kmstest.Mount + "/" + kmstest.Key + "@v1"

// kmsSection is the kek section of a boot file for the fake Transit with a token file.
func kmsSection(srv *kmstest.Server, token string) string {
	return "kek:\n  source: kms\n  kms:\n    address: " + srv.URL + "\n    key: " + kmstest.Key +
		"\n    ca_file: " + srv.CAFile() + "\n    token_file: " + srv.WriteCredential("token", token) + "\n"
}

// bootAt writes a boot file at path for the host's database with the given kek section.
func (h host) bootAt(t *testing.T, path, kek string) {
	t.Helper()
	boot := "version: 1\npublic_url: https://panel.example.com\ndatabase: {dsn: " + h.db + "}\n" + kek
	if err := os.WriteFile(path, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
}

// kmsHost is a controller host initialised with a Transit key as its KEK.
func kmsHost(t *testing.T) (host, *kmstest.Server) {
	t.Helper()
	h := newHost(t)
	srv := kmstest.New(t)
	h.writeBoot(t, kmsSection(srv, kmstest.Token))
	if _, err := controller.Init(context.Background(), h.opts()); err != nil {
		t.Fatalf("init with a Transit KEK: %v", err)
	}
	return h, srv
}

// kmsSealer returns a Sealer for the Transit key of srv, as a controller builds it.
func kmsSealer(t *testing.T, srv *kmstest.Server) *secret.Sealer {
	t.Helper()
	c, err := kms.New(kms.Config{Address: srv.URL, Key: kmstest.Key, CAFile: srv.CAFile(),
		TokenFile: srv.WriteCredential("token", kmstest.Token)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := secret.NewSealerWith(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// opens reports whether the CA of the database at dbPath opens with s.
func opens(t *testing.T, dbPath string, s *secret.Sealer) bool {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), dbPath, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	_, err = castore.LoadCA(storetest.SystemCtx(t), db, s, time.Now)
	return err == nil
}

// TestKMS_RotationRewrapsAll: after Transit rotated the key, which keeps its identifier and changes
// its version, `kek status` lists every value as on an older version without calling the boot file
// the wrong KEK, and `kek rotate` re-wraps every one to the latest version, so that raising the
// minimum decryption version afterwards locks nothing. A second run changes nothing and calls
// Transit no more.
func TestKMS_RotationRewrapsAll(t *testing.T) {
	ctx := context.Background()
	h, srv := kmsHost(t)
	st, err := controller.StatusKEK(ctx, h.cfg, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	sealed := st.Versions[kmsVersion1]
	if st.Current != kmsVersion1 || sealed < 4 || len(st.Old) != 0 || st.Mismatch() {
		t.Fatalf("status after init: %+v", st)
	}

	srv.Rotate()
	st, err = controller.StatusKEK(ctx, h.cfg, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if st.Current != kmsVersion2 || len(st.Old) != sealed || st.Mismatch() || st.Versions[kmsVersion1] != sealed {
		t.Fatalf("status after the key rotated in Transit: %+v", st)
	}

	n, v, err := controller.RotateKEK(ctx, h.cfg, controller.PreviousKEK{}, noEnv)
	if err != nil || n != sealed || v != kmsVersion2 {
		t.Fatalf("rotate: %d %s %v; want %d values on %s", n, v, err, sealed, kmsVersion2)
	}
	calls := srv.Calls("POST " + kmstest.Mount + "/rewrap/" + kmstest.Key)
	if calls != sealed {
		t.Errorf("%d rewrap calls for %d values", calls, sealed)
	}
	st, err = controller.StatusKEK(ctx, h.cfg, noEnv)
	if err != nil || st.Versions[kmsVersion2] != sealed || st.Versions[kmsVersion1] != 0 || len(st.Old) != 0 {
		t.Fatalf("status after the rotation: %+v %v", st, err)
	}

	// The last step of the operator: nothing may be left on version 1.
	srv.SetMinDecryptionVersion(2)
	if !opens(t, h.db, kmsSealer(t, srv)) {
		t.Error("the CA does not open after the minimum decryption version was raised")
	}
	if n, _, err := controller.RotateKEK(ctx, h.cfg, controller.PreviousKEK{}, noEnv); err != nil || n != 0 {
		t.Errorf("rotating again: %d %v", n, err)
	}
	if again := srv.Calls("POST " + kmstest.Mount + "/rewrap/" + kmstest.Key); again != calls {
		t.Errorf("a second rotation made %d rewrap calls", again-calls)
	}
	if got := strings.Join(localActions(t, h), "\n"); !strings.Contains(got, "kek.rotate ") ||
		!strings.Contains(got, "re-wrapped from earlier versions of "+kmsVersion2) {
		t.Errorf("audit log:\n%s", got)
	}
}

const kmsVersion2 = kmstest.Mount + "/" + kmstest.Key + "@v2"

// TestKMS_MoveBetweenSources: a database sealed under a file KEK moves to Transit and back with
// `kek rotate --previous-config`, every value in one transaction; each side opens only with its own
// KEK afterwards. Without the previous boot file, values under another KEK are refused and nothing
// changes.
func TestKMS_MoveBetweenSources(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t) // a file KEK
	k1, err := secret.LoadKEKFile(h.kek)
	if err != nil {
		t.Fatal(err)
	}
	st, err := controller.StatusKEK(ctx, h.cfg, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	sealed := st.Versions[k1.Version()]
	srv := kmstest.New(t)
	toKMS := filepath.Join(h.dir, "kms.yaml")
	h.bootAt(t, toKMS, kmsSection(srv, kmstest.Token))

	// Without the previous KEK the file's values are of an unknown key.
	if _, _, err := controller.RotateKEK(ctx, toKMS, controller.PreviousKEK{}, noEnv); err == nil || !strings.Contains(err.Error(), "neither") {
		t.Fatalf("rotate to Transit without the previous boot file: %v", err)
	}
	if st, _ := controller.StatusKEK(ctx, toKMS, noEnv); st.Versions[k1.Version()] != sealed || st.Versions[kmsVersion1] != 0 {
		t.Fatalf("a refused move changed secrets: %+v", st)
	}

	n, v, err := controller.RotateKEK(ctx, toKMS, controller.PreviousKEK{Config: h.cfg}, noEnv)
	if err != nil || n != sealed || v != kmsVersion1 {
		t.Fatalf("file to kms: %d %s %v; want %d values on %s", n, v, err, sealed, kmsVersion1)
	}
	st, err = controller.StatusKEK(ctx, toKMS, noEnv)
	if err != nil || st.Versions[kmsVersion1] != sealed || len(st.Old) != 0 || st.Mismatch() {
		t.Fatalf("status on Transit: %+v %v", st, err)
	}
	fileSealer, err := secret.NewSealer(k1)
	if err != nil {
		t.Fatal(err)
	}
	if opens(t, h.db, fileSealer) || !opens(t, h.db, kmsSealer(t, srv)) {
		t.Error("after the move to Transit the CA must open with Transit only")
	}

	// Back to a new file KEK.
	back := newHost(t)
	k2 := writeKEK(t, back.kek, 0o600)
	toFile := filepath.Join(h.dir, "file.yaml")
	h.bootAt(t, toFile, "kek: {source: file, path: "+back.kek+"}\n")
	n, v, err = controller.RotateKEK(ctx, toFile, controller.PreviousKEK{Config: toKMS}, noEnv)
	if err != nil || n != sealed || v != k2.Version() {
		t.Fatalf("kms to file: %d %s %v; want %d values under %s", n, v, err, sealed, k2.Version())
	}
	st, err = controller.StatusKEK(ctx, toFile, noEnv)
	if err != nil || st.Versions[k2.Version()] != sealed || len(st.Old) != 0 {
		t.Fatalf("status on the file KEK: %+v %v", st, err)
	}
	newSealer, err := secret.NewSealer(k2)
	if err != nil {
		t.Fatal(err)
	}
	if !opens(t, h.db, newSealer) || opens(t, h.db, kmsSealer(t, srv)) {
		t.Error("after the move back the CA must open with the file KEK only")
	}
	// The file KEK alone cannot move to itself: a file source needs the previous KEK.
	if _, _, err := controller.RotateKEK(ctx, toFile, controller.PreviousKEK{}, noEnv); !errors.Is(err, controller.ErrPreviousNeeded) {
		t.Errorf("a file KEK without the previous one: %v, want ErrPreviousNeeded", err)
	}
	if _, _, err := controller.RotateKEK(ctx, toFile, controller.PreviousKEK{File: "x", Config: "y"}, noEnv); err == nil {
		t.Error("both a previous file and a previous boot file were accepted")
	}
	if _, _, err := controller.RotateKEK(ctx, toFile, controller.PreviousKEK{Config: filepath.Join(h.dir, "none.yaml")}, noEnv); err == nil {
		t.Error("a previous boot file that does not exist was accepted")
	}
}

// TestKMS_RotateWhileTransitIsDown: a rotation with Transit down or refusing changes nothing and
// says why, not that a secret does not open.
func TestKMS_RotateWhileTransitIsDown(t *testing.T) {
	ctx := context.Background()
	h, srv := kmsHost(t)
	srv.Rotate()
	for name, status := range map[string]int{"denied": 403, "failing": 500} {
		srv.FailWith(status, false)
		_, _, err := controller.RotateKEK(ctx, h.cfg, controller.PreviousKEK{}, noEnv)
		if err == nil || strings.Contains(err.Error(), "neither") {
			t.Errorf("rotate with Transit %s: %v", name, err)
		}
		st, err := controller.StatusKEK(ctx, h.cfg, noEnv)
		if err != nil || st.CurrentErr == nil || st.Current != "" || len(st.Old) == 0 {
			t.Errorf("status with Transit %s: %+v %v; want the values counted and the reason given", name, st, err)
		}
	}
	srv.FailWith(0, false)
	if n, _, err := controller.RotateKEK(ctx, h.cfg, controller.PreviousKEK{}, noEnv); err != nil || n == 0 {
		t.Errorf("rotate with Transit back: %d %v", n, err)
	}
}

// TestKMS_RunRefusesToStart: the controller does not start when Transit cannot be reached, the key
// is missing, of the wrong type or not derived, the credential is refused, the key is another
// cluster's, or the database is sealed under another KEK. The error names the reason and no
// credential, and nothing listens.
func TestKMS_RunRefusesToStart(t *testing.T) {
	h, srv := kmsHost(t)
	var cfg config.Controller
	if err := config.Load(h.cfg, &cfg); err != nil {
		t.Fatal(err)
	}
	run := func(cfg config.Controller) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cfg.Listen.HTTPS, cfg.Listen.Admin = freeAddr(t), freeAddr(t)
		none := ""
		cfg.Listen.HTTP = &none
		return controller.Run(ctx, controller.RunOptions{Config: cfg, Getenv: noEnv, Listening: func() { t.Error("Run started") }})
	}
	withKey := func(name string) config.Controller {
		c := cfg
		k := *cfg.KEK.KMS
		k.Key = name
		c.KEK.KMS = &k
		return c
	}
	other := kmstest.New(t) // another cluster's key of the same name
	otherCfg := cfg
	{
		k := *cfg.KEK.KMS
		k.Address, k.CAFile = other.URL, other.CAFile()
		otherCfg.KEK.KMS = &k
	}
	fileHost, _ := initHost(t) // sealed under a file KEK
	fileHost.writeBoot(t, kmsSection(srv, kmstest.Token))
	var fileCfg config.Controller
	if err := config.Load(fileHost.cfg, &fileCfg); err != nil {
		t.Fatal(err)
	}
	wrongToken := cfg
	{
		k := *cfg.KEK.KMS
		k.TokenFile = srv.WriteCredential("token", "kmstest-token-wrong")
		wrongToken.KEK.KMS = &k
	}
	cases := []struct {
		name string
		cfg  func() config.Controller
		prep func()
		want string
	}{
		{"the key is missing", func() config.Controller { return withKey("absent") }, nil, "not found"},
		{"the key is of another type", func() config.Controller { return cfg }, func() { srv.SetKey("chacha20-poly1305", true) }, "chacha20-poly1305"},
		{"the key is not derived", func() config.Controller { return cfg }, func() { srv.SetKey("aes256-gcm96", false) }, "not derived"},
		{"the credential is refused", func() config.Controller { return wrongToken }, nil, "permission denied"},
		{"the key is another cluster's", func() config.Controller { return otherCfg }, nil, "does not open"},
		{"the database is sealed under a file KEK", func() config.Controller { return fileCfg }, nil, "not name"},
		{"Transit is down", func() config.Controller { return cfg }, func() { srv.Close() }, "unavailable"},
	}
	for _, tc := range cases {
		srv.SetKey("aes256-gcm96", true)
		if tc.prep != nil {
			tc.prep()
		}
		err := run(tc.cfg())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v; want an error that says %q", tc.name, err, tc.want)
			continue
		}
		for _, secretText := range []string{kmstest.Token, "kmstest-token-wrong", "vault:v"} {
			if strings.Contains(err.Error(), secretText) {
				t.Errorf("%s: the error holds %q: %v", tc.name, secretText, err)
			}
		}
	}
}

// TestKMS_RunStartsWithTransit: a controller whose KEK is a Transit key starts, exposes the
// metrics of its requests to Transit and answers ready.
func TestKMS_RunStartsWithTransit(t *testing.T) {
	h, _ := kmsHost(t)
	var cfg config.Controller
	if err := config.Load(h.cfg, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Listen.HTTPS, cfg.Listen.Admin = freeAddr(t), freeAddr(t)
	none := ""
	cfg.Listen.HTTP = &none
	reg := telemetry.NewRegistry()
	checks := make(chan func(context.Context) error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	listening := make(chan struct{})
	go func() {
		done <- controller.Run(ctx, controller.RunOptions{Config: cfg, Getenv: noEnv, Registry: reg, NoACME: true,
			Readiness: func(c func(context.Context) error) { checks <- c }, Listening: func() { close(listening) }})
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-listening:
	case err := <-done:
		t.Fatalf("Run: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not start")
	}
	if err := (<-checks)(context.Background()); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	text := gatherText(t, reg)
	for _, want := range []string{"rpmgr_kms_up 1", `rpmgr_kms_requests_total{op="check",result="ok"} 1`} {
		if !strings.Contains(text, want) {
			t.Errorf("the metrics lack %q:\n%s", want, text)
		}
	}
}

// TestKMS_ReadyFollowsTransit: the controller is not ready after Transit could not be reached or
// refused the credential, and is ready after an answer about a request; while it is down each check
// reads the key again, so that it is ready again when Transit is.
func TestKMS_ReadyFollowsTransit(t *testing.T) {
	ctx := context.Background()
	if err := controller.KMSReady(ctx, "unavailable"); err != nil {
		t.Errorf("before any request: %v", err)
	}
	if err := controller.KMSReady(ctx, "unavailable", "ok", "error"); err != nil {
		t.Errorf("after requests that Transit answered: %v", err)
	}
	for _, result := range []string{"unavailable", "denied"} {
		if err := controller.KMSReady(ctx, result, "ok", result); err == nil {
			t.Errorf("ready after %s with Transit still failing", result)
		}
		if err := controller.KMSReady(ctx, "ok", "ok", result); err != nil {
			t.Errorf("not ready after %s although the key can be read again: %v", result, err)
		}
	}
}
