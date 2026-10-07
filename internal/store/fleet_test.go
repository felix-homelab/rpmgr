// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
)

func newGateway(ctx context.Context, c *ent.Client, org, group, name string) (*ent.Gateway, error) {
	return c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group).SetName(name).
		SetTunnelEndpoints([]string{name + ".example.net:443"}).Save(ctx)
}

func activeSlots(t *testing.T, c *ent.Client, group string) []int {
	t.Helper()
	slots := c.Gateway.Query().Where(gateway.GatewayGroupID(group), gateway.DecommissionedAtIsNil()).
		Select(gateway.FieldSlot).IntsX(systemCtx(t))
	sort.Ints(slots)
	return slots
}

// TestGatewayGroup_MaxFourGateways: a group holds at most four active gateways, also when gateways
// are created concurrently; a decommissioned gateway frees its slot.
func TestGatewayGroup_MaxFourGateways(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		a, _ := seed(t, c)
		ctx := orgCtx(t, a.org)
		var second *ent.Gateway
		for i := 1; i <= 4; i++ {
			g, err := newGateway(ctx, c, a.org, a.gwg, fmt.Sprintf("gw-%d", i))
			if err != nil {
				t.Fatal(err)
			}
			if g.Slot != i {
				t.Fatalf("gateway %d got slot %d", i, g.Slot)
			}
			if i == 2 {
				second = g
			}
		}
		if _, err := newGateway(ctx, c, a.org, a.gwg, "gw-5"); !errors.Is(err, schema.ErrGroupFull) {
			t.Fatalf("fifth gateway: %v, want ErrGroupFull", err)
		}
		c.Gateway.UpdateOne(second).SetDecommissionedAt(time.Now()).ExecX(ctx)
		g, err := newGateway(ctx, c, a.org, a.gwg, "gw-5")
		if err != nil || g.Slot != 2 {
			t.Fatalf("after a decommission: slot %v, %v; want slot 2 again", g, err)
		}

		// Concurrent creates in a second group: the unique index keeps it at four.
		other := c.GatewayGroup.Create().SetOrgID(a.org).SetName("us").SaveX(ctx)
		var wg sync.WaitGroup
		var mu sync.Mutex
		created := 0
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, err := newGateway(ctx, c, a.org, other.ID, fmt.Sprintf("us-%d", i)); err == nil {
					mu.Lock()
					created++
					mu.Unlock()
				} else if !errors.Is(err, schema.ErrGroupFull) && !ent.IsConstraintError(err) && !store.IsUniqueViolation(err) {
					t.Errorf("concurrent create: %v", err)
				}
			}(i)
		}
		wg.Wait()
		if slots := activeSlots(t, c, other.ID); created > 4 || len(slots) != created || len(slots) > 4 {
			t.Fatalf("%d creates succeeded, active slots %v", created, slots)
		}
	})
}

// TestFleet_CompositeKeys: plain SQL cannot point an org's gateway or enrollment token at another
// org's group, gateway or connector.
func TestFleet_CompositeKeys(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, db *store.DB) {
		a, b := seed(t, c)
		gwB, err := newGateway(orgCtx(t, b.org), c, b.org, b.gwg, "gw-b")
		if err != nil {
			t.Fatal(err)
		}
		conB := c.Connector.Create().SetOrgID(b.org).SetName("nas").SetSpiffeID("spiffe://x").SetPubkeySha256("h").
			SaveX(orgCtx(t, b.org))
		now := time.Now().UTC().Format("2006-01-02 15:04:05")
		ctx := context.Background()
		for name, q := range map[string]string{
			"gateway in another org's group": "INSERT INTO gateways (id, org_id, gateway_group_id, name, slot, tunnel_endpoints, enabled, created_at) " +
				"VALUES ('" + ids.New("gw") + "', '" + a.org + "', '" + b.gwg + "', 'x', 2, '[]', true, '" + now + "')",
			"token for another org's gateway":   tokenSQL(a.org, "gateway_id", gwB.ID, now),
			"token for another org's connector": tokenSQL(a.org, "connector_id", conB.ID, now),
			"token for another org's group":     tokenSQL(a.org, "gateway_group_id", b.gwg, now),
		} {
			if _, err := db.Writer.ExecContext(ctx, q); !store.IsForeignKeyViolation(err) {
				t.Errorf("%s: want a foreign-key violation, got %v", name, err)
			}
		}
	})
}

func tokenSQL(org, column, id, now string) string {
	return "INSERT INTO enrollment_tokens (id, org_id, token_hash, role, " + column + ", ephemeral, max_uses, use_count, expires_at, created_by, created_at, last_used_ip) " +
		"VALUES ('" + ids.New("enr") + "', '" + org + "', '\\x01', 'connector', '" + id + "', false, 1, 0, '" + now + "', 'u', '" + now + "', '')"
}

func TestFleet_NamesUniquePerOrg(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		a, b := seed(t, c)
		ctxA, ctxB := orgCtx(t, a.org), orgCtx(t, b.org)
		if _, err := newGateway(ctxA, c, a.org, a.gwg, "edge"); err != nil {
			t.Fatal(err)
		}
		if _, err := newGateway(ctxA, c, a.org, a.gwg, "edge"); !ent.IsConstraintError(err) {
			t.Errorf("second gateway named edge in org A: %v", err)
		}
		if _, err := newGateway(ctxB, c, b.org, b.gwg, "edge"); err != nil {
			t.Errorf("gateway named edge in org B: %v", err)
		}
		con := func(ctx context.Context, org string) error {
			return c.Connector.Create().SetOrgID(org).SetName("nas").SetSpiffeID("spiffe://x").SetPubkeySha256("h").Exec(ctx)
		}
		if err := con(ctxA, a.org); err != nil {
			t.Fatal(err)
		}
		if err := con(ctxA, a.org); !ent.IsConstraintError(err) {
			t.Errorf("second connector named nas in org A: %v", err)
		}
		if err := con(ctxB, b.org); err != nil {
			t.Errorf("connector named nas in org B: %v", err)
		}
	})
}

// TestEnrollmentToken_Binding: a gateway token is bound to exactly one gateway, a connector token
// to none, and a re-enrollment token is single-use.
func TestEnrollmentToken_Binding(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		a, _ := seed(t, c)
		ctx := orgCtx(t, a.org)
		gw, err := newGateway(ctx, c, a.org, a.gwg, "gw-1")
		if err != nil {
			t.Fatal(err)
		}
		con := c.Connector.Create().SetOrgID(a.org).SetName("nas").SetSpiffeID("spiffe://x").SetPubkeySha256("h").SaveX(ctx)
		n := 0
		token := func() *ent.EnrollmentTokenCreate {
			n++
			h := sha256.Sum256([]byte(fmt.Sprint(n)))
			return c.EnrollmentToken.Create().SetOrgID(a.org).SetTokenHash(h[:]).
				SetExpiresAt(time.Now().Add(time.Hour)).SetCreatedBy("usr_of_" + a.org)
		}
		bad := map[string]*ent.EnrollmentTokenCreate{
			"gateway token without a gateway":    token().SetRole("gateway"),
			"gateway token with a connector":     token().SetRole("gateway").SetGatewayID(gw.ID).SetConnectorID(con.ID),
			"connector token bound to a gateway": token().SetRole("connector").SetGatewayID(gw.ID),
			"multi-use re-enrollment token":      token().SetRole("connector").SetConnectorID(con.ID).SetMaxUses(2),
			"token without uses":                 token().SetRole("connector").SetMaxUses(0),
		}
		for name, create := range bad {
			if err := create.Exec(ctx); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		good := map[string]*ent.EnrollmentTokenCreate{
			"gateway token":       token().SetRole("gateway").SetGatewayID(gw.ID),
			"connector token":     token().SetRole("connector").SetGatewayGroupID(a.gwg).SetMaxUses(5).SetEphemeral(true),
			"re-enrollment token": token().SetRole("connector").SetConnectorID(con.ID),
		}
		for name, create := range good {
			if err := create.Exec(ctx); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		h := sha256.Sum256([]byte("same"))
		for i := 0; i < 2; i++ {
			err := c.EnrollmentToken.Create().SetOrgID(a.org).SetTokenHash(h[:]).SetRole("connector").
				SetExpiresAt(time.Now()).SetCreatedBy("u").Exec(ctx)
			if (i == 0) != (err == nil) || (i == 1 && !ent.IsConstraintError(err)) {
				t.Errorf("token %d with the same hash: %v", i+1, err)
			}
		}
	})
}

func TestFleet_Validation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		a, _ := seed(t, c)
		ctx := orgCtx(t, a.org)
		cases := map[string]error{
			"CIDR with host bits":   c.GatewayGroup.Create().SetOrgID(a.org).SetName("g1").SetTrustedProxyCidrs([]string{"10.0.0.1/8"}).Exec(ctx),
			"not a CIDR":            c.GatewayGroup.Create().SetOrgID(a.org).SetName("g2").SetTrustedProxyCidrs([]string{"10.0.0.0"}).Exec(ctx),
			"upper-case hostname":   c.GatewayGroup.Create().SetOrgID(a.org).SetName("g3").SetPublicHostnames([]string{"Edge.Example.com"}).Exec(ctx),
			"single-label hostname": c.GatewayGroup.Create().SetOrgID(a.org).SetName("g4").SetPublicHostnames([]string{"edge"}).Exec(ctx),
			"endpoint without port": c.Gateway.Create().SetOrgID(a.org).SetGatewayGroupID(a.gwg).SetName("x1").SetTunnelEndpoints([]string{"edge.example.com"}).Exec(ctx),
			"endpoint with port 0":  c.Gateway.Create().SetOrgID(a.org).SetGatewayGroupID(a.gwg).SetName("x2").SetTunnelEndpoints([]string{"edge.example.com:0"}).Exec(ctx),
			"name that is no slug":  c.Gateway.Create().SetOrgID(a.org).SetGatewayGroupID(a.gwg).SetName("Edge 1").SetTunnelEndpoints([]string{}).Exec(ctx),
		}
		for name, err := range cases {
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		if err := c.GatewayGroup.Create().SetOrgID(a.org).SetName("ok").
			SetPublicHostnames([]string{"edge.example.com", "203.0.113.7", "2001:db8::7"}).
			SetTrustedProxyCidrs([]string{"203.0.113.0/24", "2001:db8::/32"}).Exec(ctx); err != nil {
			t.Errorf("valid group settings: %v", err)
		}
		if err := c.Gateway.Create().SetOrgID(a.org).SetGatewayGroupID(a.gwg).SetName("ok").
			SetTunnelEndpoints([]string{"edge.example.com:443", "[2001:db8::1]:8443", "203.0.113.7:443"}).Exec(ctx); err != nil {
			t.Errorf("valid tunnel endpoints: %v", err)
		}
	})
}

// TestFleet_Tenancy: org B neither sees org A's fleet nor creates in org A's group.
func TestFleet_Tenancy(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, _ *store.DB) {
		a, b := seed(t, c)
		ctxA, ctxB := orgCtx(t, a.org), orgCtx(t, b.org)
		gw, err := newGateway(ctxA, c, a.org, a.gwg, "gw-a")
		if err != nil {
			t.Fatal(err)
		}
		c.Connector.Create().SetOrgID(a.org).SetName("nas").SetSpiffeID("spiffe://x").SetPubkeySha256("h").ExecX(ctxA)
		if n := c.Gateway.Query().CountX(ctxB); n != 0 {
			t.Errorf("org B sees %d gateways", n)
		}
		if n := c.Connector.Query().CountX(ctxB); n != 0 {
			t.Errorf("org B sees %d connectors", n)
		}
		if _, err := c.Gateway.Get(ctxB, gw.ID); !ent.IsNotFound(err) {
			t.Errorf("org B gets org A's gateway: %v", err)
		}
		if _, err := newGateway(ctxB, c, a.org, a.gwg, "intruder"); err == nil {
			t.Error("org B created a gateway in org A")
		}
		if _, err := newGateway(ctxB, c, b.org, a.gwg, "intruder"); err == nil {
			t.Error("org B created a gateway in org A's group")
		}
		if g := c.Gateway.QueryGroup(gw).OnlyX(ctxA); g.ID != a.gwg {
			t.Errorf("the gateway's group is %s", g.ID)
		}
	})
}
