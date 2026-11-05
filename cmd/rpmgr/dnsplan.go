// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// ExitPlanChanged is the exit code of `rpmgr approve zone` when the plan is not the one the caller
// read (docs/16-cli.md, "Exit codes"): a script tells a stale hash from a failure.
const ExitPlanChanged = 4

// planChanged is the error of an approval of a plan that is not the current one. The new plan has
// been printed, so that it can be read again.
type planChanged struct{ msg string }

func (e *planChanged) Error() string { return e.msg }
func (e *planChanged) ExitCode() int { return ExitPlanChanged }

// planCommands are `plan zone`, `approve zone`, `sync zone` and the commands on a zone's records:
// `adopt dns-record`, `disown dns-record` (docs/16-cli.md, D169). `list dns-record` is the generic
// list's.
func planCommands() map[string][]*cli.Command {
	return map[string][]*cli.Command{
		"plan":    {planZone()},
		"approve": {approveZone()},
		"sync":    {syncZone()},
		"enable":  {enableZone()},
		"adopt":   {adoptRecords()},
		"disown":  {disownRecord()},
	}
}

func zoneClient(s *apiSession) rpmgrv1connect.DnsZoneServiceClient {
	return rpmgrv1connect.NewDnsZoneServiceClient(s.hc, s.creds.Controller)
}

// delegationWarning is the sentence of a zone whose domain is delegated to other nameservers than
// the ones its provider assigned, whose records are therefore not served ([docs/15-dns.md],
// "Delegation"); empty if the delegation is fine or not known.
func delegationWarning(z *rpmgrv1.DnsZone) string {
	if z.GetDelegationState() != rpmgrv1.ZoneDelegationState_ZONE_DELEGATION_STATE_MISMATCH {
		return ""
	}
	return fmt.Sprintf("Warning: %s is delegated to %s, not to the provider. Records published at the provider are not served: "+
		"set the nameservers at your registrar to %s.", z.GetName(), strings.Join(z.GetDelegationNameservers(), ", "),
		strings.Join(z.GetAssignedNameservers(), ", "))
}

// printPlan writes a plan the way a person reads it before approving it: what will be created,
// changed and deleted, what is left alone and why, and the hash to approve it by.
func printPlan(w io.Writer, z *rpmgrv1.DnsZone, p *rpmgrv1.ZonePlan) error {
	state := strings.ToLower(strings.TrimPrefix(z.GetSyncState().String(), "ZONE_SYNC_STATE_"))
	if z.GetHeldReason() != "" {
		state += ", " + strings.ReplaceAll(z.GetHeldReason(), "_", " ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Plan of zone %s (%s), now %s.\n", z.GetName(), z.GetId(), state)
	if w := delegationWarning(z); w != "" {
		b.WriteString(w + "\n")
	}
	rec := func(mark string, rs []*rpmgrv1.PlanRecord) {
		for _, r := range rs {
			proxied := ""
			if r.GetProxied() {
				proxied = "  proxied"
			}
			fmt.Fprintf(&b, "  %s %-6s %-40s %s  ttl %d%s\n", mark, r.GetType(), r.GetName(), r.GetContent(), r.GetTtl(), proxied)
		}
	}
	rec("+", p.GetCreates())
	rec("~", p.GetUpdates())
	rec("-", p.GetDeletes())
	if len(p.GetCreates())+len(p.GetUpdates())+len(p.GetDeletes()) == 0 {
		b.WriteString("  Nothing to write.\n")
	}
	if len(p.GetConflicts()) > 0 {
		b.WriteString("Left alone, in conflict:\n")
		for _, c := range p.GetConflicts() {
			fmt.Fprintf(&b, "  %s: %s\n", c.GetName(), strings.ReplaceAll(c.GetKind(), "_", " "))
			for _, r := range c.GetRecords() {
				fmt.Fprintf(&b, "      %s %s (%s)\n", r.GetType(), r.GetContent(), r.GetId())
			}
		}
	}
	if len(p.GetOrphans()) > 0 {
		b.WriteString("Records with this instance's marker and no ledger row (orphans, never deleted by a pass):\n")
		rec(" ", p.GetOrphans())
	}
	if len(p.GetShadows()) > 0 {
		fmt.Fprintf(&b, "Names that stop following a foreign wildcard: %s\n", strings.Join(p.GetShadows(), ", "))
	}
	if len(p.GetLost()) > 0 {
		fmt.Fprintf(&b, "Records rpmgr owns that are gone at the provider (created again if still wanted): %d\n", len(p.GetLost()))
	}
	fmt.Fprintf(&b, "Plan hash: %s\n", p.GetHash())
	_, err := io.WriteString(w, b.String())
	return err
}

func planZone() *cli.Command {
	var output string
	var deleteRecords bool
	k := kindOf("zone")
	return &cli.Command{
		Name: "zone", Summary: "show the plan of a managed zone: what a pass would create, change and delete, and the hash to approve it by", Args: "<id or name>",
		Flags: func(fs *flag.FlagSet) {
			outputFlag(fs, &output)
			fs.BoolVar(&deleteRecords, "delete-records", false, "show the plan of removing the zone with its records instead: it deletes every record rpmgr owns in it")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the zone's ID or name")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, k, args[0])
			if err != nil {
				return err
			}
			resp, err := zoneClient(s).PlanZoneSync(ctx, connect.NewRequest(&rpmgrv1.PlanZoneSyncRequest{DnsZoneId: id, DeleteRecords: deleteRecords}))
			if err != nil {
				return apiError(err)
			}
			switch output {
			case "json", "yaml":
				return printMessage(env.Stdout, output, resp.Msg.GetPlan())
			case "table":
				return printPlan(env.Stdout, resp.Msg.GetDnsZone(), resp.Msg.GetPlan())
			}
			return cli.Usagef("unknown output %q: table, yaml or json", output)
		},
	}
}

// printMessage writes a message as JSON or YAML, the resource alone.
func printMessage(w io.Writer, output string, m protoreflect.ProtoMessage) error {
	if output == "yaml" {
		return writeYAML(w, []protoreflect.Message{m.ProtoReflect()})
	}
	b, err := protojson.Marshal(m)
	if err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	b, err = json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

// isPlanChanged reports whether the API refused an approval because the plan has another hash.
func isPlanChanged(err error) bool {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return false
	}
	for _, d := range cerr.Details() {
		if v, derr := d.Value(); derr == nil {
			if x, ok := v.(*errdetails.ErrorInfo); ok && x.GetReason() == "PLAN_CHANGED" {
				return true
			}
		}
	}
	return false
}

func approveZone() *cli.Command {
	var hash string
	k := kindOf("zone")
	return &cli.Command{
		Name: "zone", Summary: "approve the plan of a held zone, by the hash you read, with a step-up; the next pass applies that plan and no other", Args: "--plan-hash <hash> <id or name>",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&hash, "plan-hash", "", "the hash of the plan you read with rpmgr plan zone (required)")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 || hash == "" {
				return cli.Usagef("give --plan-hash, the hash that rpmgr plan zone shows, and the zone's ID or name")
			}
			if len(hash) != 64 || strings.Trim(hash, "0123456789abcdef") != "" {
				return cli.Usagef("--plan-hash is the 64 lower-case hexadecimal characters that rpmgr plan zone shows")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, k, args[0])
			if err != nil {
				return err
			}
			// The plan is shown before the approval is asked for, and an approval of another plan
			// than the one read goes no further: no step-up is asked for a plan that has changed.
			cur, err := zoneClient(s).PlanZoneSync(ctx, connect.NewRequest(&rpmgrv1.PlanZoneSyncRequest{DnsZoneId: id}))
			if err != nil {
				return apiError(err)
			}
			if err := printPlan(env.Stdout, cur.Msg.GetDnsZone(), cur.Msg.GetPlan()); err != nil {
				return err
			}
			if cur.Msg.GetPlan().GetHash() != hash {
				return &planChanged{fmt.Sprintf("the plan changed since you read it (you approved %s): read the plan above and approve its hash", hash)}
			}
			var resp *connect.Response[rpmgrv1.ApproveZonePlanResponse]
			if err := s.withStepUp(ctx, func() error {
				var err error
				resp, err = zoneClient(s).ApproveZonePlan(ctx, connect.NewRequest(&rpmgrv1.ApproveZonePlanRequest{DnsZoneId: id, PlanHash: hash}))
				return err
			}); err != nil {
				if isPlanChanged(err) { // it changed between the two reads
					if again, perr := zoneClient(s).PlanZoneSync(ctx, connect.NewRequest(&rpmgrv1.PlanZoneSyncRequest{DnsZoneId: id})); perr == nil {
						_ = printPlan(env.Stdout, again.Msg.GetDnsZone(), again.Msg.GetPlan())
					}
					return &planChanged{"the plan changed while it was being approved: read the plan above and approve its hash"}
				}
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "Approved the plan of zone %s; it is active, and the next pass applies that plan.\n", resp.Msg.GetDnsZone().GetName())
			return err
		},
	}
}

// removeWithRecords is `remove zone --delete-records`: the plan of the removal is shown first, and
// the zone and its records go only if its hash is the one the caller read, after a step-up.
func removeWithRecords(ctx context.Context, env *cli.Env, s *apiSession, id, hash, etag string) error {
	cur, err := zoneClient(s).PlanZoneSync(ctx, connect.NewRequest(&rpmgrv1.PlanZoneSyncRequest{DnsZoneId: id, DeleteRecords: true}))
	if err != nil {
		return apiError(err)
	}
	if err := printPlan(env.Stdout, cur.Msg.GetDnsZone(), cur.Msg.GetPlan()); err != nil {
		return err
	}
	if cur.Msg.GetPlan().GetHash() != hash {
		return &planChanged{fmt.Sprintf("the plan changed since you read it (you gave %s): read the plan above and give its hash", hash)}
	}
	if err := s.withStepUp(ctx, func() error {
		_, err := zoneClient(s).RemoveZone(ctx, connect.NewRequest(&rpmgrv1.RemoveZoneRequest{DnsZoneId: id, Etag: etag, DeleteRecords: true, PlanHash: hash}))
		return err
	}); err != nil {
		if isPlanChanged(err) {
			return &planChanged{"the plan changed while the zone was being removed: run rpmgr plan zone --delete-records again"}
		}
		return apiError(err)
	}
	_, err = fmt.Fprintf(env.Stdout, "Asked for the removal of zone %s with its records. The zone is disabled; the DNS job deletes the records rpmgr owns, then removes the zone.\n"+
		"rpmgr get zone shows it as removal pending until then.\n", cur.Msg.GetDnsZone().GetName())
	return err
}

func enableZone() *cli.Command {
	k := kindOf("zone")
	return &cli.Command{
		Name: "zone", Summary: "move a disabled zone to held, with a step-up; it writes nothing until a plan is approved", Args: "<id or name>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the zone's ID or name")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, k, args[0])
			if err != nil {
				return err
			}
			var resp *connect.Response[rpmgrv1.EnableZoneResponse]
			if err := s.withStepUp(ctx, func() error {
				var err error
				resp, err = zoneClient(s).EnableZone(ctx, connect.NewRequest(&rpmgrv1.EnableZoneRequest{DnsZoneId: id}))
				return err
			}); err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "Zone %s is held: nothing is written until you approve a plan (rpmgr plan zone, rpmgr approve zone).\n", resp.Msg.GetDnsZone().GetName())
			return err
		},
	}
}

func syncZone() *cli.Command {
	k := kindOf("zone")
	return &cli.Command{
		Name: "zone", Summary: "ask for a full pass over a zone now", Args: "<id or name>",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the zone's ID or name")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, k, args[0])
			if err != nil {
				return err
			}
			resp, err := zoneClient(s).SyncZone(ctx, connect.NewRequest(&rpmgrv1.SyncZoneRequest{DnsZoneId: id}))
			if err != nil {
				return apiError(err)
			}
			_, err = fmt.Fprintf(env.Stdout, "Asked for a full pass over zone %s; the DNS job runs it at its next tick.\n", resp.Msg.GetDnsZone().GetName())
			return err
		},
	}
}

// zoneFlag is the --zone flag of the commands on a zone's records.
func zoneFlag(fs *flag.FlagSet, p *string) {
	fs.StringVar(p, "zone", "", "the managed zone, by name or ID (required)")
}

func adoptRecords() *cli.Command {
	var zone string
	zk := kindOf("zone")
	return &cli.Command{
		Name: "dns-record", Summary: "adopt foreign records at names the org publishes: rpmgr owns them from now on and rewrites them at its next pass",
		Args:  "--zone <zone> <provider record id>…",
		Flags: func(fs *flag.FlagSet) { zoneFlag(fs, &zone) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if zone == "" || len(args) == 0 {
				return cli.Usagef("give --zone and the provider's IDs of the records, as rpmgr list dns-record --zone <zone> --foreign shows them")
			}
			if len(args) > 200 {
				return cli.Usagef("at most 200 records at a time")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, zk, zone)
			if err != nil {
				return err
			}
			var resp *connect.Response[rpmgrv1.AdoptRecordsResponse]
			if err := s.withStepUp(ctx, func() error {
				var err error
				resp, err = zoneClient(s).AdoptRecords(ctx, connect.NewRequest(&rpmgrv1.AdoptRecordsRequest{DnsZoneId: id, ProviderRecordIds: args}))
				return err
			}); err != nil {
				return apiError(err)
			}
			for _, r := range resp.Msg.GetRecords() {
				if _, err := fmt.Fprintf(env.Stdout, "Adopted %s %s %s as %s; the next pass rewrites it to what the sources want.\n", r.GetType(), r.GetName(), r.GetContent(), r.GetId()); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func disownRecord() *cli.Command {
	var zone string
	var restore bool
	zk := kindOf("zone")
	return &cli.Command{
		Name: "dns-record", Summary: "release an owned record: it stays at the provider without rpmgr's marker, or with --restore as it was adopted",
		Args: "--zone <zone> <record id>",
		Flags: func(fs *flag.FlagSet) {
			zoneFlag(fs, &zone)
			fs.BoolVar(&restore, "restore", false, "put the record back to the content it had when it was adopted")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if zone == "" || len(args) != 1 {
				return cli.Usagef("give --zone and the ID (dnr_…) of one owned record")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			id, err := s.ref(ctx, zk, zone)
			if err != nil {
				return err
			}
			var resp *connect.Response[rpmgrv1.ReleaseRecordResponse]
			if err := s.withStepUp(ctx, func() error {
				var err error
				resp, err = zoneClient(s).ReleaseRecord(ctx, connect.NewRequest(&rpmgrv1.ReleaseRecordRequest{DnsZoneId: id, RecordId: args[0], Restore: restore}))
				return err
			}); err != nil {
				return apiError(err)
			}
			what := "stay at the provider without rpmgr's marker"
			if restore {
				what = "go back to what it was when it was adopted"
			}
			if _, err := fmt.Fprintf(env.Stdout, "Asked for the release of %s; the DNS job, at its next pass of the zone, lets the record %s; rpmgr then never changes it again.\n", args[0], what); err != nil {
				return err
			}
			if w := resp.Msg.GetWarning(); w != "" {
				_, err = fmt.Fprintf(env.Stderr, "Warning: %s.\n", w)
			}
			return err
		},
	}
}

// listRecords is `list dns-record`: the owned records of a zone and, with --foreign, the other
// records read live, for an Owner or Admin.
func listRecords(ctx context.Context, env *cli.Env, s *apiSession, k apicli.Kind, zone string, foreign bool, output string) error {
	zk := kindOf("zone")
	id, err := s.ref(ctx, zk, zone)
	if err != nil {
		return err
	}
	resp, err := zoneClient(s).ListZoneRecords(ctx, connect.NewRequest(&rpmgrv1.ListZoneRecordsRequest{DnsZoneId: id, IncludeForeign: foreign}))
	if err != nil {
		return apiError(err)
	}
	var found []protoreflect.Message
	var ids []string
	for _, r := range resp.Msg.GetRecords() {
		found = append(found, r.ProtoReflect())
		ids = append(ids, r.GetId())
	}
	if output == "table" {
		return writeRecords(env.Stdout, resp.Msg.GetRecords())
	}
	return s.print(ctx, env.Stdout, k, output, found, ids, true)
}

func writeRecords(w io.Writer, rs []*rpmgrv1.DnsRecord) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tPROVIDER ID\tNAME\tTYPE\tCONTENT\tTTL\tSTATE")
	for _, r := range rs {
		id := r.GetId()
		if id == "" {
			id = "-"
		}
		state := strings.ToLower(strings.TrimPrefix(r.GetState().String(), "DNS_RECORD_STATE_"))
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", id, r.GetProviderRecordId(), r.GetName(), r.GetType(), r.GetContent(), r.GetTtl(), state)
	}
	return tw.Flush()
}
