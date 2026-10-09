// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez/v3/acme"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
)

// pushTimeout is how long every gateway of a name has to acknowledge a challenge
// (docs/03-connections.md, "Timeouts, keepalive and backoff"); a variable for tests.
var pushTimeout = 10 * time.Second

// Operator sends an operation to an agent's control session and waits for its OpResult;
// controller.Sessions is one.
type Operator interface {
	Op(ctx context.Context, agentID string, msg func(opID string) *agentv1.ControllerMessage) error
}

// GatewaysFor returns the gateways that serve a DNS name.
type GatewaysFor func(ctx context.Context, name string) ([]string, error)

// ChallengeStorage is Storage for certmagic with its HTTP-01 and TLS-ALPN-01 challenges pushed to
// the gateways (spike S6): certmagic keeps a challenge, key authorization included, under
// "<issuer>/challenge_tokens/<name>.json" before the CA is asked to validate it, and deletes it
// afterwards. Storing such a key first pushes the challenge to every gateway that serves the name
// and fails unless all of them acknowledged within pushTimeout, so the CA never validates a
// challenge a gateway cannot answer; deleting it removes the challenge from them again.
type ChallengeStorage struct {
	*Storage
	op       Operator
	gateways GatewaysFor
}

// NewChallengeStorage wraps s.
func NewChallengeStorage(s *Storage, op Operator, gateways GatewaysFor) *ChallengeStorage {
	return &ChallengeStorage{Storage: s, op: op, gateways: gateways}
}

// IsChallengeKey reports whether key is one of certmagic's challenge keys.
func IsChallengeKey(key string) bool {
	return path.Base(path.Dir(key)) == "challenge_tokens" && strings.HasSuffix(key, ".json")
}

// Store implements certmagic.Storage.
func (s *ChallengeStorage) Store(ctx context.Context, key string, value []byte) error {
	if IsChallengeKey(key) {
		var ch acme.Challenge
		if err := json.Unmarshal(value, &ch); err != nil {
			return fmt.Errorf("acme: challenge %q: %w", key, err)
		}
		if err := s.push(ctx, agentv1.AcmeAction_ACME_ACTION_ADD, ch); err != nil {
			return err
		}
	}
	return s.Storage.Store(ctx, key, value)
}

// Delete implements certmagic.Storage; removing a challenge from the gateways is best effort, as
// a challenge whose authorization is done answers nothing useful.
func (s *ChallengeStorage) Delete(ctx context.Context, key string) error {
	if IsChallengeKey(key) {
		if v, err := s.Load(ctx, key); err == nil {
			var ch acme.Challenge
			if json.Unmarshal(v, &ch) == nil {
				_ = s.push(ctx, agentv1.AcmeAction_ACME_ACTION_REMOVE, ch)
			}
		}
	}
	return s.Storage.Delete(ctx, key)
}

// push sends a challenge to every gateway of its name and waits for all of them.
func (s *ChallengeStorage) push(ctx context.Context, action agentv1.AcmeAction, ch acme.Challenge) error {
	var typ agentv1.AcmeChallengeType
	switch ch.Type {
	case acme.ChallengeTypeHTTP01:
		typ = agentv1.AcmeChallengeType_ACME_CHALLENGE_TYPE_HTTP_01
	case acme.ChallengeTypeTLSALPN01:
		typ = agentv1.AcmeChallengeType_ACME_CHALLENGE_TYPE_TLS_ALPN_01
	default:
		return nil // DNS-01 is answered in DNS, not by gateways
	}
	name := ch.Identifier.Value
	ids, err := s.gateways(ctx, name)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return fmt.Errorf("acme: no gateway serves %q", name)
	}
	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Go(func() {
			err := s.op.Op(ctx, id, func(opID string) *agentv1.ControllerMessage {
				return &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_AcmeChallenge{AcmeChallenge: &agentv1.AcmeChallenge{
					OpId: opID, Action: action, Type: typ, Identifier: name, Token: ch.Token, KeyAuthorization: ch.KeyAuthorization}}}
			})
			if err != nil {
				errs[i] = fmt.Errorf("gateway %s: %w", id, err)
			}
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("acme: the challenge for %q did not reach every gateway: %w", name, err)
	}
	return nil
}

// GatewaysServing returns GatewaysFor over the store: the enabled gateways of every group with an
// enabled http route whose hostname is the name or the wildcard one label up. sys must carry the
// system scope.
func GatewaysServing(db *store.DB, sys context.Context) GatewaysFor {
	return func(_ context.Context, name string) ([]string, error) {
		names := []string{name}
		if _, parent, ok := strings.Cut(name, "."); ok {
			names = append(names, "*."+parent)
		}
		var ids []string
		err := store.ReadTx(sys, db, func(tx *ent.Tx, _ store.Revision) error {
			groups, err := tx.RouteHostname.Query().Where(routehostname.HostnameIn(names...),
				routehostname.RouteTypeEQ(routehostname.RouteTypeHTTP), routehostname.HasRouteWith(route.Enabled(true))).
				Select(routehostname.FieldGatewayGroupID).Strings(sys)
			if err != nil || len(groups) == 0 {
				return err
			}
			ids, err = tx.Gateway.Query().Where(gateway.GatewayGroupIDIn(groups...), gateway.Enabled(true),
				gateway.DecommissionedAtIsNil()).Order(ent.Asc(gateway.FieldID)).IDs(sys)
			return err
		})
		return ids, err
	}
}
