// SPDX-License-Identifier: Apache-2.0

package snapshot_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/org"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

var testAgent = snapshot.Agent{
	Identity:     pki.Identity{TrustDomain: "rpmgr-teststor", Org: "org_1", Kind: pki.KindConnector, ID: "con_1"},
	Capabilities: []string{agentproto.CapTunnelQUIC},
}

// orgSource compiles one resource per org, its size the length of the org's name: a stand-in for
// the resource kinds later slices add.
func orgSource(ctx context.Context, tx *ent.Tx, _ snapshot.Agent) ([]*agentv1.Resource, error) {
	orgs, err := tx.Org.Query().Order(org.ByID()).All(ctx)
	if err != nil {
		return nil, err
	}
	var rs []*agentv1.Resource
	for _, o := range orgs {
		rs = append(rs, ref(o.ID, len(o.Name)))
	}
	return rs, nil
}

func ref(id string, size int) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_Reference{
		Reference: &agentv1.ResourceReference{Size: uint64(size)}}} //nolint:gosec // G115: test sizes are small
}

func hashes(s *agentv1.Snapshot) map[string][]byte {
	m := map[string][]byte{}
	for _, r := range s.GetResources() {
		m[r.GetId()] = r.GetHash()
	}
	return m
}

func TestCompile(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		a, b := storetest.Org(t, db, "alpha"), storetest.Org(t, db, "beta")
		c := &snapshot.Compiler{Sources: []snapshot.Source{orgSource},
			Endpoints: func() []string { return []string{"https://ctl.example", "https://ctl2.example:8443"} }}

		first, err := c.Compile(sys, db, testAgent)
		if err != nil {
			t.Fatal(err)
		}
		if first.GetAgent() != testAgent.Identity.String() || first.GetRevision().GetDbEpoch() == "" {
			t.Fatalf("snapshot header %v", first)
		}
		if !slices.Equal(first.GetControllerEndpoints(), []string{"https://ctl.example", "https://ctl2.example:8443"}) {
			t.Fatalf("endpoints %v", first.GetControllerEndpoints())
		}
		if len(first.GetResources()) != 2 || first.GetResources()[0].GetId() > first.GetResources()[1].GetId() {
			t.Fatalf("resources %v", first.GetResources())
		}

		// The same revision compiles to the same bytes.
		again, err := c.Compile(sys, db, testAgent)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encode(t, first), encode(t, again)) {
			t.Fatal("the same revision compiled to different bytes")
		}

		// An unrelated change gives a new revision and keeps the hash of every unchanged resource.
		rev, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
			o, err := tx.Org.Create().SetName("gamma").SetSlug("gamma").Save(sys)
			return []string{o.ID}, err
		})
		if err != nil {
			t.Fatal(err)
		}
		second, err := c.Compile(sys, db, testAgent)
		if err != nil {
			t.Fatal(err)
		}
		if second.GetRevision().GetSeq() != uint64(rev.Seq) || second.GetRevision().GetSeq() <= first.GetRevision().GetSeq() { //nolint:gosec // G115: positive
			t.Fatalf("revision %v after %v", second.GetRevision(), rev)
		}
		h1, h2 := hashes(first), hashes(second)
		if len(h2) != 3 || !bytes.Equal(h1[a], h2[a]) || !bytes.Equal(h1[b], h2[b]) {
			t.Fatal("an unrelated change changed the hash of an unchanged resource")
		}

		// A change of the resource changes its hash only.
		if _, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
			return []string{a}, tx.Org.UpdateOneID(a).SetName("alpha-renamed").Exec(sys)
		}); err != nil {
			t.Fatal(err)
		}
		third, err := c.Compile(sys, db, testAgent)
		if err != nil {
			t.Fatal(err)
		}
		h3 := hashes(third)
		if bytes.Equal(h2[a], h3[a]) || !bytes.Equal(h2[b], h3[b]) {
			t.Fatal("a changed resource kept its hash, or an unchanged one lost it")
		}
	})
}

// TestCompile_Deterministic is a property test: whatever order the sources return their resources
// in, and however they are split between sources, the snapshot's bytes are the same.
func TestCompile_Deterministic(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: a reproducible test sequence
	var want []byte
	for i := range 50 {
		var all []*agentv1.Resource
		for j := range 20 {
			all = append(all, ref(fmt.Sprintf("rt_%02d", j), j*7))
		}
		rng.Shuffle(len(all), func(x, y int) { all[x], all[y] = all[y], all[x] })
		cut := rng.IntN(len(all) + 1)
		part1, part2 := all[:cut], all[cut:]
		c := &snapshot.Compiler{Sources: []snapshot.Source{
			func(context.Context, *ent.Tx, snapshot.Agent) ([]*agentv1.Resource, error) { return part1, nil },
			func(context.Context, *ent.Tx, snapshot.Agent) ([]*agentv1.Resource, error) { return part2, nil },
		}}
		snap, err := c.Compile(sys, db, testAgent)
		if err != nil {
			t.Fatal(err)
		}
		got := encode(t, snap)
		if i == 0 {
			want = got
		} else if !bytes.Equal(got, want) {
			t.Fatalf("round %d: different bytes for the same resources", i)
		}
	}
}

func TestCompile_CapabilityAware(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	quicOnly := func(_ context.Context, _ *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
		if !a.Has(agentproto.CapTunnelQUIC) {
			return nil, nil
		}
		return []*agentv1.Resource{ref("rt_quic", 1)}, nil
	}
	c := &snapshot.Compiler{Sources: []snapshot.Source{quicOnly}}
	with, err := c.Compile(sys, db, testAgent)
	if err != nil {
		t.Fatal(err)
	}
	without, err := c.Compile(sys, db, snapshot.Agent{Identity: testAgent.Identity})
	if err != nil {
		t.Fatal(err)
	}
	if len(with.GetResources()) != 1 || len(without.GetResources()) != 0 {
		t.Fatalf("with %v, without %v", with.GetResources(), without.GetResources())
	}
	if without.GetControllerEndpoints() != nil {
		t.Fatal("endpoints without an endpoint source")
	}
}

func TestCompile_Errors(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	sys := storetest.SystemCtx(t)
	c := &snapshot.Compiler{Sources: []snapshot.Source{orgSource}}
	if _, err := c.Compile(sys, db, testAgent); err == nil {
		t.Fatal("compiled from a database without an instance")
	}
	storetest.Init(t, db)

	boom := errors.New("boom")
	c = &snapshot.Compiler{Sources: []snapshot.Source{orgSource,
		func(context.Context, *ent.Tx, snapshot.Agent) ([]*agentv1.Resource, error) { return nil, boom }}}
	if _, err := c.Compile(sys, db, testAgent); !errors.Is(err, boom) {
		t.Fatalf("a source error was not returned: %v", err)
	}

	twice := func(context.Context, *ent.Tx, snapshot.Agent) ([]*agentv1.Resource, error) {
		return []*agentv1.Resource{ref("rt_1", 1)}, nil
	}
	c = &snapshot.Compiler{Sources: []snapshot.Source{twice, twice}}
	if _, err := c.Compile(sys, db, testAgent); err == nil {
		t.Fatal("a resource ID twice was compiled")
	}

	// A source reads through the read transaction, which refuses writes.
	writer := func(ctx context.Context, tx *ent.Tx, _ snapshot.Agent) ([]*agentv1.Resource, error) {
		return nil, tx.Org.Create().SetName("w").SetSlug("w").Exec(ctx)
	}
	c = &snapshot.Compiler{Sources: []snapshot.Source{writer}}
	if _, err := c.Compile(sys, db, testAgent); err == nil {
		t.Fatal("a source wrote through the read transaction")
	}

	ctx, cancel := context.WithCancel(sys)
	cancel()
	c = &snapshot.Compiler{Sources: []snapshot.Source{orgSource}}
	if _, err := c.Compile(ctx, db, testAgent); err == nil {
		t.Fatal("compiled with a cancelled context")
	}
}

func encode(t *testing.T, s *agentv1.Snapshot) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
