// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

var (
	hashA = strings.Repeat("a", 64)
	hashB = strings.Repeat("b", 64)
)

// zoneFake is what the fake zone service remembers of the plan, approval, record and sync calls.
type zoneFake struct {
	calls      []string // "plan", "approve", ... in the order the API saw them
	hashes     []string // the hash each PlanZoneSync answers with, in turn; the last one repeats
	planErr    error
	approveErr error
	approved   *rpmgrv1.ApproveZonePlanRequest
	listed     *rpmgrv1.ListZoneRecordsRequest
	listErr    error
	adopted    *rpmgrv1.AdoptRecordsRequest
	adoptErr   error
	released   *rpmgrv1.ReleaseRecordRequest
	warning    string
	synced     *rpmgrv1.SyncZoneRequest
	removeErr  error
	removal    []bool // the delete_records of each PlanZoneSync
}

func withReasonErr(code connect.Code, msg, reason string) error {
	err := connect.NewError(code, errors.New(msg))
	if d, derr := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: "rpmgr.dev"}); derr == nil {
		err.AddDetail(d)
	}
	return err
}

func thePlan(hash string) *rpmgrv1.ZonePlan {
	return &rpmgrv1.ZonePlan{
		Creates:   []*rpmgrv1.PlanRecord{{Name: "app.example.com", Type: "A", Content: "192.0.2.1", Ttl: 300}},
		Updates:   []*rpmgrv1.PlanRecord{{Id: "r1", Name: "www.example.com", Type: "CNAME", Content: "gw.example.net", Ttl: 300, Proxied: true}},
		Deletes:   []*rpmgrv1.PlanRecord{{Id: "r2", Name: "old.example.com", Type: "A", Content: "192.0.2.9", Ttl: 300}},
		Conflicts: []*rpmgrv1.PlanConflict{{Name: "taken.example.com", Kind: "foreign_address", Records: []*rpmgrv1.PlanRecord{{Id: "r3", Type: "A", Content: "192.0.2.7"}}}},
		Orphans:   []*rpmgrv1.PlanRecord{{Id: "r4", Name: "lost.example.com", Type: "TXT", Content: "x", Ttl: 300}},
		Shadows:   []string{"deep.example.com"}, Lost: []string{"r5"}, Hash: hash,
	}
}

func (a *dnsAPI) PlanZoneSync(_ context.Context, req *connect.Request[rpmgrv1.PlanZoneSyncRequest]) (*connect.Response[rpmgrv1.PlanZoneSyncResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	z := &a.zonePlans
	z.calls = append(z.calls, "plan")
	z.removal = append(z.removal, req.Msg.GetDeleteRecords())
	if z.planErr != nil {
		return nil, z.planErr
	}
	hash := hashA
	if n := len(z.hashes); n > 0 {
		hash = z.hashes[0]
		if n > 1 {
			z.hashes = z.hashes[1:]
		}
	}
	return connect.NewResponse(&rpmgrv1.PlanZoneSyncResponse{DnsZone: theZone(), Plan: thePlan(hash)}), nil
}

func (a *dnsAPI) ApproveZonePlan(_ context.Context, req *connect.Request[rpmgrv1.ApproveZonePlanRequest]) (*connect.Response[rpmgrv1.ApproveZonePlanResponse], error) {
	if err := a.stepped(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	z := &a.zonePlans
	z.calls = append(z.calls, "approve")
	z.approved = req.Msg
	if z.approveErr != nil {
		return nil, z.approveErr
	}
	return connect.NewResponse(&rpmgrv1.ApproveZonePlanResponse{DnsZone: theZone()}), nil
}

func (a *dnsAPI) SyncZone(_ context.Context, req *connect.Request[rpmgrv1.SyncZoneRequest]) (*connect.Response[rpmgrv1.SyncZoneResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.zonePlans.synced = req.Msg
	return connect.NewResponse(&rpmgrv1.SyncZoneResponse{DnsZone: theZone()}), nil
}

func (a *dnsAPI) ListZoneRecords(_ context.Context, req *connect.Request[rpmgrv1.ListZoneRecordsRequest]) (*connect.Response[rpmgrv1.ListZoneRecordsResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.zonePlans.listed = req.Msg
	if a.zonePlans.listErr != nil {
		return nil, a.zonePlans.listErr
	}
	out := []*rpmgrv1.DnsRecord{{Id: "dnr_1", ProviderRecordId: "p1", Name: "app.example.com", Type: "A", Content: "192.0.2.1", Ttl: 300, State: rpmgrv1.DnsRecordState_DNS_RECORD_STATE_SYNCED}}
	if req.Msg.GetIncludeForeign() {
		out = append(out, &rpmgrv1.DnsRecord{ProviderRecordId: "p2", Name: "mx.example.com", Type: "MX", Content: "mail.example.net", Ttl: 300, State: rpmgrv1.DnsRecordState_DNS_RECORD_STATE_FOREIGN})
	}
	return connect.NewResponse(&rpmgrv1.ListZoneRecordsResponse{Records: out}), nil
}

func (a *dnsAPI) AdoptRecords(_ context.Context, req *connect.Request[rpmgrv1.AdoptRecordsRequest]) (*connect.Response[rpmgrv1.AdoptRecordsResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.zonePlans.adopted = req.Msg
	if a.zonePlans.adoptErr != nil {
		return nil, a.zonePlans.adoptErr
	}
	var out []*rpmgrv1.DnsRecord
	for i, id := range req.Msg.GetProviderRecordIds() {
		out = append(out, &rpmgrv1.DnsRecord{Id: "dnr_" + string(rune('a'+i)), ProviderRecordId: id, Name: "app.example.com", Type: "A", Content: "192.0.2.1"})
	}
	return connect.NewResponse(&rpmgrv1.AdoptRecordsResponse{Records: out}), nil
}

func (a *dnsAPI) ReleaseRecord(_ context.Context, req *connect.Request[rpmgrv1.ReleaseRecordRequest]) (*connect.Response[rpmgrv1.ReleaseRecordResponse], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.zonePlans.released = req.Msg
	if req.Msg.GetRecordId() == "dnr_missing" {
		return nil, withReasonErr(connect.CodeNotFound, "the zone owns no such record", "RECORD_NOT_FOUND")
	}
	return connect.NewResponse(&rpmgrv1.ReleaseRecordResponse{Warning: a.zonePlans.warning}), nil
}

// TestDNSPlanZone (docs/16-cli.md, #674): the plan shows what is created, changed and deleted, what
// is left alone and why, and the hash; -o json and yaml carry the plan alone.
func TestDNSPlanZone(t *testing.T) {
	a, run, _ := dnsEnv(t, "")
	code, out, _ := run("plan", "zone", "example.com")
	if code != cli.ExitOK {
		t.Fatalf("plan: %d %q", code, out)
	}
	for _, want := range []string{"Plan of zone example.com (dnz_1), now held, imported", "+ A      app.example.com", "~ CNAME  www.example.com", "proxied",
		"- A      old.example.com", "taken.example.com: foreign address", "192.0.2.7", "lost.example.com", "deep.example.com", "Plan hash: " + hashA} {
		if !strings.Contains(out, want) {
			t.Errorf("the plan lacks %q:\n%s", want, out)
		}
	}
	code, out, errOut := run("plan", "zone", "dnz_1", "-o", "json")
	var p struct {
		Hash    string `json:"hash"`
		Creates []any  `json:"creates"`
	}
	if code != cli.ExitOK || json.Unmarshal([]byte(out), &p) != nil || p.Hash != hashA || len(p.Creates) != 1 || errOut != "" {
		t.Fatalf("plan -o json: %d %q %q", code, out, errOut)
	}
	if code, out, _ := run("plan", "zone", "dnz_1", "-o", "yaml"); code != cli.ExitOK || !strings.Contains(out, "hash: "+hashA) {
		t.Errorf("plan -o yaml: %d %q", code, out)
	}
	for name, args := range map[string][]string{"no zone": {"plan", "zone"}, "two zones": {"plan", "zone", "a", "b"}, "an output that is none": {"plan", "zone", "dnz_1", "-o", "xml"}} {
		if code, _, _ := run(args...); code != cli.ExitUsage {
			t.Errorf("%s: %d", name, code)
		}
	}
	a.zonePlans.planErr = withReasonErr(connect.CodeUnavailable, "the provider cannot be reached", "")
	if code, _, errOut := run("plan", "zone", "dnz_1"); code != cli.ExitError || !strings.Contains(errOut, "cannot be reached") {
		t.Errorf("an unreachable provider: %d %q", code, errOut)
	}
}

// TestDNSApproveZone (docs/16-cli.md, #674): the plan is shown before the approval is asked for,
// the approval takes a step-up, and a plan that is not the one read ends with exit code 4 and the
// new plan, whether it changed before the command read it or while it was approving, without
// asking for a step-up in the first case.
func TestDNSApproveZone(t *testing.T) {
	a, run, _ := dnsEnv(t, "")
	code, out, errOut := run("approve", "zone", "--plan-hash", hashA, "example.com")
	if code != cli.ExitOK || errOut != "" {
		t.Fatalf("approve: %d %q %q", code, out, errOut)
	}
	if strings.Join(a.zonePlans.calls, ",") != "plan,approve" || a.zonePlans.approved.GetPlanHash() != hashA || a.zonePlans.approved.GetDnsZoneId() != "dnz_1" {
		t.Fatalf("calls %v, approved %v", a.zonePlans.calls, a.zonePlans.approved)
	}
	if i, j := strings.Index(out, "Plan hash: "+hashA), strings.Index(out, "Approved the plan"); i < 0 || j < 0 || i > j {
		t.Errorf("the plan is not shown before the approval:\n%s", out)
	}
	if len(a.stepUps) != 1 {
		t.Errorf("%d step-ups, want 1", len(a.stepUps))
	}

	// The plan changed before the command looked: exit code 4, the new plan, no step-up, no approval.
	a.zonePlans.calls, a.zonePlans.approved, a.stepUps = nil, nil, nil
	a.zonePlans.hashes = []string{hashB}
	code, out, errOut = run("approve", "zone", "--plan-hash", hashA, "dnz_1")
	if code != ExitPlanChanged || !strings.Contains(out, "Plan hash: "+hashB) || !strings.Contains(errOut, "changed since you read it") || strings.Contains(out, "Approved") {
		t.Fatalf("a stale hash: %d %q %q", code, out, errOut)
	}
	if strings.Join(a.zonePlans.calls, ",") != "plan" || a.zonePlans.approved != nil || len(a.stepUps) != 0 {
		t.Errorf("a stale hash went further: %v %v %d", a.zonePlans.calls, a.zonePlans.approved, len(a.stepUps))
	}

	// It changed while the command approved: the API says PLAN_CHANGED, and the new plan is shown.
	a.zonePlans.calls, a.zonePlans.hashes = nil, []string{hashA, hashB}
	a.zonePlans.approveErr = withReasonErr(connect.CodeFailedPrecondition, "the plan changed since it was shown", "PLAN_CHANGED")
	code, out, errOut = run("approve", "zone", "--plan-hash", hashA, "dnz_1")
	if code != ExitPlanChanged || !strings.Contains(out, "Plan hash: "+hashB) || !strings.Contains(errOut, "while it was being approved") {
		t.Fatalf("a plan that changed meanwhile: %d %q %q", code, out, errOut)
	}
	if strings.Join(a.zonePlans.calls, ",") != "plan,approve,plan" {
		t.Errorf("calls %v", a.zonePlans.calls)
	}

	// Another refusal is an ordinary failure, with the API's reason.
	a.zonePlans.hashes = []string{hashA}
	a.zonePlans.approveErr = withReasonErr(connect.CodeFailedPrecondition, "the zone is not held", "ZONE_NOT_HELD")
	if code, _, errOut := run("approve", "zone", "--plan-hash", hashA, "dnz_1"); code != cli.ExitError || !strings.Contains(errOut, "ZONE_NOT_HELD") {
		t.Errorf("a zone that is not held: %d %q", code, errOut)
	}
	a.zonePlans.approveErr, a.zonePlans.calls = nil, nil
	for name, args := range map[string][]string{
		"no hash":               {"approve", "zone", "dnz_1"},
		"a short hash":          {"approve", "zone", "--plan-hash", "abc", "dnz_1"},
		"a hash in capitals":    {"approve", "zone", "--plan-hash", strings.ToUpper(hashA), "dnz_1"},
		"a hash that is no hex": {"approve", "zone", "--plan-hash", strings.Repeat("z", 64), "dnz_1"},
		"no zone":               {"approve", "zone", "--plan-hash", hashA},
	} {
		if code, _, _ := run(args...); code != cli.ExitUsage {
			t.Errorf("%s: %d", name, code)
		}
	}
	if len(a.zonePlans.calls) != 0 {
		t.Errorf("refused input reached the API: %v", a.zonePlans.calls)
	}
}

func TestDNSSyncZone(t *testing.T) {
	a, run, _ := dnsEnv(t, "")
	if code, out, _ := run("sync", "zone", "example.com"); code != cli.ExitOK || a.zonePlans.synced.GetDnsZoneId() != "dnz_1" || !strings.Contains(out, "full pass over zone example.com") {
		t.Fatalf("sync: %d %q %v", code, out, a.zonePlans.synced)
	}
	if code, _, _ := run("sync", "zone"); code != cli.ExitUsage {
		t.Errorf("sync without a zone: %d", code)
	}
}

// TestDNSRecordCommands (docs/16-cli.md, #674): list the owned records, and with --foreign the
// others; adopt provider records by ID; disown an owned one, keeping it or with --restore putting
// back its original, and show the warning the API gives; the API's refusals are shown with their
// reason.
func TestDNSRecordCommands(t *testing.T) {
	a, run, _ := dnsEnv(t, "")
	code, out, _ := run("list", "dns-record", "--zone", "example.com")
	if code != cli.ExitOK || a.zonePlans.listed.GetIncludeForeign() || !strings.Contains(out, "dnr_1") || strings.Contains(out, "mx.example.com") {
		t.Fatalf("list: %d %q %v", code, out, a.zonePlans.listed)
	}
	code, out, _ = run("list", "dns-record", "--zone", "dnz_1", "--foreign")
	if code != cli.ExitOK || !a.zonePlans.listed.GetIncludeForeign() || !strings.Contains(out, "mx.example.com") || !strings.Contains(out, "foreign") || !strings.Contains(out, "p2") {
		t.Fatalf("list --foreign: %d %q", code, out)
	}
	if code, out, _ := run("list", "dns-record", "--zone", "dnz_1", "-o", "json"); code != cli.ExitOK || !strings.Contains(out, `"providerRecordId": "p1"`) {
		t.Errorf("list -o json: %d %q", code, out)
	}
	a.zonePlans.listErr = connect.NewError(connect.CodePermissionDenied, errors.New("the records of a zone that rpmgr does not own are shown to Owners and Admins only"))
	if code, _, errOut := run("list", "dns-record", "--zone", "dnz_1", "--foreign"); code != cli.ExitError || !strings.Contains(errOut, "Owners and Admins only") {
		t.Errorf("an Operator asks for the foreign records: %d %q", code, errOut)
	}
	if code, _, _ := run("list", "dns-record"); code != cli.ExitUsage {
		t.Errorf("list without a zone: %d", code)
	}

	code, out, _ = run("adopt", "dns-record", "--zone", "example.com", "p2", "p3")
	if code != cli.ExitOK || strings.Join(a.zonePlans.adopted.GetProviderRecordIds(), ",") != "p2,p3" || a.zonePlans.adopted.GetDnsZoneId() != "dnz_1" || strings.Count(out, "Adopted") != 2 {
		t.Fatalf("adopt: %d %q %v", code, out, a.zonePlans.adopted)
	}
	a.zonePlans.adoptErr = withReasonErr(connect.CodeFailedPrecondition, "no source of the org publishes a record at the name of the record", "RECORD_NOT_WANTED")
	if code, _, errOut := run("adopt", "dns-record", "--zone", "dnz_1", "p9"); code != cli.ExitError || !strings.Contains(errOut, "RECORD_NOT_WANTED") {
		t.Errorf("a refused adoption: %d %q", code, errOut)
	}
	a.zonePlans.adopted = nil
	for name, args := range map[string][]string{
		"adopt no zone":    {"adopt", "dns-record", "p1"},
		"adopt no record":  {"adopt", "dns-record", "--zone", "dnz_1"},
		"disown no zone":   {"disown", "dns-record", "dnr_1"},
		"disown no record": {"disown", "dns-record", "--zone", "dnz_1"},
		"disown two":       {"disown", "dns-record", "--zone", "dnz_1", "dnr_1", "dnr_2"},
	} {
		if code, _, _ := run(args...); code != cli.ExitUsage {
			t.Errorf("%s: %d", name, code)
		}
	}
	if a.zonePlans.adopted != nil || a.zonePlans.released != nil {
		t.Fatal("refused input reached the API")
	}
	many := append([]string{"adopt", "dns-record", "--zone", "dnz_1"}, make([]string, 201)...)
	for i := 4; i < len(many); i++ {
		many[i] = "p"
	}
	if code, _, _ := run(many...); code != cli.ExitUsage || a.zonePlans.adopted != nil {
		t.Errorf("201 records: %d %v", code, a.zonePlans.adopted)
	}

	if code, out, _ := run("disown", "dns-record", "--zone", "dnz_1", "dnr_1"); code != cli.ExitOK || a.zonePlans.released.GetRestore() || a.zonePlans.released.GetRecordId() != "dnr_1" ||
		!strings.Contains(out, "without rpmgr's marker") {
		t.Fatalf("disown: %d %q %v", code, out, a.zonePlans.released)
	}
	a.zonePlans.warning = "the original is older than 30 days: its address may belong to someone else now"
	code, out, errOut := run("disown", "dns-record", "--zone", "dnz_1", "--restore", "dnr_1")
	if code != cli.ExitOK || !a.zonePlans.released.GetRestore() || !strings.Contains(out, "back to what it was") || !strings.Contains(errOut, "Warning: the original is older") {
		t.Fatalf("disown --restore: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := run("disown", "dns-record", "--zone", "dnz_1", "dnr_missing"); code != cli.ExitError || !strings.Contains(errOut, "RECORD_NOT_FOUND") {
		t.Errorf("disown of a record that is not owned: %d %q", code, errOut)
	}
}

// TestDNSRemoveZoneWithRecords (docs/16-cli.md, #674): the removal plan is shown before anything is
// deleted, the hash must be the one read, the step-up is asked for once the plan matches, and a plan
// that changed ends with exit code 4 and the new plan.
func TestDNSRemoveZoneWithRecords(t *testing.T) {
	a, run, _ := dnsEnv(t, "")
	if code, out, _ := run("plan", "zone", "--delete-records", "example.com"); code != cli.ExitOK || !strings.Contains(out, "Plan hash: "+hashA) || len(a.zonePlans.removal) != 1 || !a.zonePlans.removal[0] {
		t.Fatalf("plan --delete-records: %d %q %v", code, out, a.zonePlans.removal)
	}
	a.zonePlans.calls = nil
	code, out, errOut := run("remove", "zone", "--delete-records", "--plan-hash", hashA, "example.com")
	if code != cli.ExitOK || errOut != "" || !strings.Contains(out, "deleted the records rpmgr owned") {
		t.Fatalf("remove --delete-records: %d %q %q", code, out, errOut)
	}
	if strings.Join(a.zonePlans.calls, ",") != "plan,remove" || !a.removed.GetDeleteRecords() || a.removed.GetPlanHash() != hashA || a.removed.GetEtag() != "5" || len(a.stepUps) != 1 {
		t.Fatalf("calls %v, request %v, %d step-ups", a.zonePlans.calls, a.removed, len(a.stepUps))
	}
	if i, j := strings.Index(out, "Plan hash:"), strings.Index(out, "Removed zone"); i < 0 || i > j {
		t.Errorf("the plan is not shown before the removal:\n%s", out)
	}

	// A plan that is not the one read: exit code 4, the new plan, no step-up, nothing removed.
	a.zonePlans.calls, a.removed, a.stepUps = nil, nil, nil
	a.zonePlans.hashes = []string{hashB}
	code, out, errOut = run("remove", "zone", "--delete-records", "--plan-hash", hashA, "dnz_1")
	if code != ExitPlanChanged || !strings.Contains(out, "Plan hash: "+hashB) || !strings.Contains(errOut, "changed since you read it") || a.removed != nil || len(a.stepUps) != 0 {
		t.Fatalf("a stale hash: %d %q %q %v", code, out, errOut, a.removed)
	}
	// It changed while the command removed.
	a.zonePlans.hashes = []string{hashA}
	a.zonePlans.removeErr = withReasonErr(connect.CodeFailedPrecondition, "the removal plan changed", "PLAN_CHANGED")
	if code, _, errOut := run("remove", "zone", "--delete-records", "--plan-hash", hashA, "dnz_1"); code != ExitPlanChanged || !strings.Contains(errOut, "while the zone was being removed") {
		t.Errorf("a plan that changed meanwhile: %d %q", code, errOut)
	}
	a.zonePlans.removeErr = withReasonErr(connect.CodeUnavailable, "the provider cannot be reached", "")
	if code, _, errOut := run("remove", "zone", "--delete-records", "--plan-hash", hashA, "dnz_1"); code != cli.ExitError || !strings.Contains(errOut, "cannot be reached") {
		t.Errorf("a failing provider: %d %q", code, errOut)
	}
	a.zonePlans.removeErr, a.zonePlans.calls = nil, nil
	for name, args := range map[string][]string{
		"no hash":            {"remove", "zone", "--delete-records", "dnz_1"},
		"a hash without it":  {"remove", "zone", "--plan-hash", hashA, "dnz_1"},
		"a short hash":       {"remove", "zone", "--delete-records", "--plan-hash", "abc", "dnz_1"},
		"a hash in capitals": {"remove", "zone", "--delete-records", "--plan-hash", strings.ToUpper(hashA), "dnz_1"},
		"no zone":            {"remove", "zone", "--delete-records", "--plan-hash", hashA},
	} {
		if code, _, _ := run(args...); code != cli.ExitUsage {
			t.Errorf("%s: %d", name, code)
		}
	}
	if len(a.zonePlans.calls) != 0 {
		t.Errorf("refused input reached the API: %v", a.zonePlans.calls)
	}
}
