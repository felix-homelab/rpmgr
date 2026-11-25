// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/kms"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// kekWrapper is the Wrapper of a boot file's KEK source and the version a new value carries.
type kekWrapper struct {
	secret.Wrapper
	// Version is the local KEK's version, or "<mount>/<key>@v<n>" for a Transit key's latest.
	Version string
	// Probe asks Transit about the key again; nil for a local KEK.
	Probe func(context.Context) error
}

// kmsConfig is the client's configuration for the kek.kms section.
func kmsConfig(k config.KMS, log *slog.Logger, observe func(op, result string)) kms.Config {
	c := kms.Config{Address: k.Address, Mount: k.Mount, Key: k.Key, CAFile: k.CAFile, TokenFile: k.TokenFile,
		Logger: log, Observe: observe}
	if k.AppRole != nil {
		c.AppRole = &kms.AppRole{Mount: k.AppRole.Mount, RoleIDFile: k.AppRole.RoleIDFile, SecretIDFile: k.AppRole.SecretIDFile}
	}
	return c
}

// openKEK opens the KEK source of cfg. A file or a credential is read; a Transit key is read and
// checked, so that a Transit that is down, a key that is missing, of another type or not derived,
// and a credential that is refused all stop the caller here, with the reason and no credential
// (docs/04-security.md, "KEK in Vault or OpenBao Transit"). local reads a file or a credential,
// which a command run from a shell loads with its own hint.
func openKEK(ctx context.Context, cfg config.Controller, local func(config.Controller) (secret.KEK, error),
	log *slog.Logger, observe func(op, result string)) (kekWrapper, error) {
	if cfg.KEK.Source != config.KEKKMS {
		k, err := local(cfg)
		if err != nil {
			return kekWrapper{}, err
		}
		return kekWrapper{Wrapper: secret.NewLocalWrapper(k), Version: k.Version()}, nil
	}
	c, err := kms.New(kmsConfig(*cfg.KEK.KMS, log, observe))
	if err != nil {
		return kekWrapper{}, fmt.Errorf("controller: kek.source kms: %w", err)
	}
	latest, err := c.Check(ctx)
	if err != nil {
		return kekWrapper{}, fmt.Errorf("controller: kek.source kms: %w", err)
	}
	return kekWrapper{Wrapper: c, Version: string(c.ID()) + "@v" + strconv.Itoa(latest),
		Probe: func(ctx context.Context) error { _, err := c.Check(ctx); return err }}, nil
}

// explainOpen adds to an error of opening the CA's keys at start what it means for the KEK: the
// database was sealed under another KEK, or the key does not open it. It tells the cases apart
// without naming a credential.
func explainOpen(err error) error {
	switch {
	case errors.Is(err, secret.ErrUnknownKey):
		return fmt.Errorf("controller: the database is sealed under a KEK that the boot file does not name "+
			"(see `rpmgr kek status`; move to it with `rpmgr kek rotate --previous-config`): %w", err)
	case errors.Is(err, secret.ErrOpen):
		return fmt.Errorf("controller: the KEK does not open the database's secrets: is it the KEK the database "+
			"was sealed with? With Transit, a key of the same name in another cluster does not: %w", err)
	}
	return err
}

// probeEvery is the least time between two reads of the key that /readyz makes while Transit is
// down; concurrent checks share the answer, so a probe every second does not load Transit.
const probeEvery = time.Second

// kmsHealth is what the controller knows of its requests to Transit: the metrics of docs/10 and the
// answer of /readyz. Transit being unreachable, the credential being refused or the key not being
// usable (missing, of another type, not derived) makes it not ready; a request that Transit answers
// with an error about the request does not.
type kmsHealth struct {
	up       atomic.Bool
	requests *prometheus.CounterVec
	probe    func(context.Context) error

	mu     sync.Mutex
	probed time.Time
	now    func() time.Time
}

func newKMSHealth() *kmsHealth {
	h := &kmsHealth{requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rpmgr_kms_requests_total",
		Help: "Transit requests by operation (encrypt, decrypt, rewrap, check, login) and result (ok, denied, unavailable, error)."},
		[]string{"op", "result"}), now: time.Now}
	h.up.Store(true)
	return h
}

func (h *kmsHealth) observe(op, result string) {
	h.requests.WithLabelValues(op, result).Inc()
	// A check that fails, of whatever kind, means the key cannot be used.
	h.up.Store(result == "ok" || result == "error" && op != "check")
}

// Collectors returns the metrics of the Transit client.
func (h *kmsHealth) Collectors() []prometheus.Collector {
	return []prometheus.Collector{h.requests, prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "rpmgr_kms_up",
		Help: "1 while Transit answers and the key is usable, 0 after it could not be reached, refused the credential or the key failed its check."},
		func() float64 {
			if h.up.Load() {
				return 1
			}
			return 0
		})}
}

// Ready returns why Transit is not usable, or nil. While it is down, a check reads the key again,
// at most once per probeEvery and shared by callers that come at the same time, so that a
// controller that no traffic reaches finds out that Transit is back. The check's own failure keeps
// it down.
func (h *kmsHealth) Ready(ctx context.Context) error {
	if h == nil || h.up.Load() {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.probe != nil && h.now().Sub(h.probed) >= probeEvery {
		h.probed = h.now()
		if err := h.probe(ctx); err != nil {
			h.up.Store(false)
		} else {
			h.up.Store(true)
		}
	}
	if !h.up.Load() {
		return errors.New("key service: Transit cannot be reached, refuses the credential or has no usable key")
	}
	return nil
}

// keyServiceDown reports an error of the KEK's key service being unreachable, refusing the credential
// or not accepting the key version: a state the operator changes, not a fault of the value.
func keyServiceDown(err error) bool {
	return errors.Is(err, kms.ErrUnavailable) || errors.Is(err, kms.ErrPermissionDenied) || errors.Is(err, kms.ErrKeyVersion)
}
