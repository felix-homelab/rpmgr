// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// maxReleaseFile bounds each signed file upload release reads; the API takes at most 1 MiB.
const maxReleaseFile = 1 << 20

// rolloutCommands are check release, upload release, create rollout, advance, pause, resume and
// cancel rollout, and upgrade connector and gateway (docs/16-cli.md); list release, get rollout,
// list rollout and list rollout-target are part of get and list. All are for an Instance Admin.
func rolloutCommands() map[string][]*cli.Command {
	var (
		release, output string
		canaries        cli.List
		agents          cli.List
		easy            bool
		controller      bool
	)
	create := &cli.Command{
		Name: "rollout", Summary: "roll a release out to the connectors and gateways: staged, its canary agents first, or easy, one agent after another",
		Args: "--release <version> (--canary <agent>… | --easy --agent <agent>… | --controller)",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&release, "release", "", "the release, by version or ID; no newer than the controller, but with --controller newer")
			fs.BoolVar(&controller, "controller", false, "update the controller or all-in-one itself over the air, after a backup, instead of agents; the release must be newer and mirrored")
			fs.Var(&canaries, "canary", "a staged rollout's canary agent: a connector or gateway of the org by name, or of any org by ID; repeat for more")
			fs.BoolVar(&easy, "easy", false, "an easy rollout: the --agent agents update one after another, and a failed one is skipped")
			fs.Var(&agents, "agent", "an easy rollout's agent, in the order they update: a connector or gateway of the org by name, or of any org by ID; repeat for more")
			outputFlag(fs, &output)
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if controller {
				if len(args) > 0 || release == "" || easy || len(canaries) > 0 || len(agents) > 0 {
					return cli.Usagef("--controller takes --release and nothing else")
				}
				return updateController(ctx, env, release)
			}
			switch {
			case len(args) > 0 || release == "":
				return cli.Usagef("give --release, and no argument")
			case easy && (len(agents) == 0 || len(canaries) > 0):
				return cli.Usagef("an easy rollout takes at least one --agent, and no --canary")
			case !easy && (len(canaries) == 0 || len(agents) > 0):
				return cli.Usagef("a staged rollout takes at least one --canary, and no --agent; give --easy for an easy rollout")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			req := &rpmgrv1.CreateRolloutRequest{}
			if req.ReleaseId, err = s.releaseID(ctx, release); err != nil {
				return err
			}
			for _, c := range canaries {
				id, err := s.agentID(ctx, c)
				if err != nil {
					return err
				}
				req.CanaryAgentIds = append(req.CanaryAgentIds, id)
			}
			if easy {
				req.Mode = rpmgrv1.RolloutMode_ROLLOUT_MODE_EASY
				for _, a := range agents {
					id, err := s.agentID(ctx, a)
					if err != nil {
						return err
					}
					req.AgentIds = append(req.AgentIds, id)
				}
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			rc := rpmgrv1connect.NewReleaseServiceClient(s.hc, s.creds.Controller)
			var ro *rpmgrv1.Rollout
			if err := s.withStepUp(ctx, func() error {
				resp, err := rc.CreateRollout(ctx, connect.NewRequest(req))
				if err == nil {
					ro = resp.Msg.GetRollout()
				}
				return err
			}); err != nil {
				return apiError(err)
			}
			what := "Started rollout %s of %s to its canary agents.\n"
			if easy {
				what = "Started easy rollout %s of %s; its agents update one after another.\n"
			}
			return s.writeRollout(ctx, env, output, what, ro)
		},
	}
	return map[string][]*cli.Command{"check": {checkRelease()}, "upload": {uploadRelease()}, "create": {create}, "advance": {advanceRollout()},
		"upgrade": {upgradeAgents("connector"), upgradeAgents("gateway")},
		"pause":   {changeRollout("pause", "pause a running rollout; agents offered the release keep it", false)},
		"resume":  {changeRollout("resume", "let a paused rollout run again", true)},
		"cancel":  {changeRollout("cancel", "end a running or paused rollout for good", true)}}
}

// checkPoll is how often check release asks whether the release check has ended.
var checkPoll = time.Second

// checkRelease is `rpmgr check release`: the controller's release check runs now, and the command
// waits for it to end.
func checkRelease() *cli.Command {
	return &cli.Command{
		Name: "release", Summary: "check for new releases now and wait for the check to end (Instance Admin)",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("expected no argument")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			rc := rpmgrv1connect.NewReleaseServiceClient(s.hc, s.creds.Controller)
			resp, err := rc.CheckReleases(ctx, connect.NewRequest(&rpmgrv1.CheckReleasesRequest{}))
			if err != nil {
				return apiError(err)
			}
			st := resp.Msg.GetReleaseCheck()
			for st.GetRunning() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(checkPoll):
				}
				list, err := rc.ListReleases(ctx, connect.NewRequest(&rpmgrv1.ListReleasesRequest{PageSize: 1}))
				if err != nil {
					return apiError(err)
				}
				st = list.Msg.GetReleaseCheck()
			}
			at := st.GetCheckTime().AsTime().UTC().Format(time.RFC3339)
			switch st.GetOutcome() {
			case rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_OK:
				_, err = fmt.Fprintf(env.Stdout, "Checked for releases at %s; rpmgr list release shows the releases the controller knows.\n", at)
				return err
			case rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_FAILED:
				return fmt.Errorf("the release check at %s failed, and the mirror keeps what it had: %s", at, st.GetError())
			default:
				return fmt.Errorf("the release check at %s listed no releases: it was turned off", at)
			}
		},
	}
}

// uploadRelease is `rpmgr upload release <dir>`: a release's signed files, as a GitHub release
// has them.
func uploadRelease() *cli.Command {
	var output string
	return &cli.Command{
		Name: "release", Summary: "upload a release's signed manifest and signing-key statement (Instance Admin)", Args: "<dir>",
		Flags: func(fs *flag.FlagSet) { outputFlag(fs, &output) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the directory of a release, with signing-key.json, manifest.json and their .minisig files")
			}
			var files [4][]byte
			for i, name := range []string{"signing-key.json", "signing-key.json.minisig", "manifest.json", "manifest.json.minisig"} {
				b, err := readSmall(filepath.Join(args[0], name))
				if err != nil {
					return err
				}
				files[i] = b
			}
			req := &rpmgrv1.UploadReleaseRequest{SigningKeyStatement: files[0], StatementSignature: files[1], Manifest: files[2], ManifestSignature: files[3]}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			rc := rpmgrv1connect.NewReleaseServiceClient(s.hc, s.creds.Controller)
			var rel *rpmgrv1.Release
			if err := s.withStepUp(ctx, func() error {
				resp, err := rc.UploadRelease(ctx, connect.NewRequest(req))
				if err == nil {
					rel = resp.Msg.GetRelease()
				}
				return err
			}); err != nil {
				return apiError(err)
			}
			held := "the mirror does not hold its artifacts yet"
			if rel.GetMirrored() {
				held = "the mirror holds its artifacts"
			}
			if _, err := fmt.Fprintf(notes(env, output).Stdout, "Uploaded release %s (manifest %d); %s.\n", rel.GetVersion(), rel.GetManifestSeq(), held); err != nil {
				return err
			}
			if output == "table" {
				return nil
			}
			return s.print(ctx, env.Stdout, kindOf("release"), output, []protoreflect.Message{rel.ProtoReflect()}, nil, false)
		},
	}
}

// upgradeAgents is `rpmgr upgrade connector|gateway <agent>…`: the agents join the easy rollout of
// the controller's own version, or start one (D129).
func upgradeAgents(kind string) *cli.Command {
	var output string
	return &cli.Command{
		Name: kind, Summary: "update " + kind + "s to the controller's version, one after another, in its easy rollout (Instance Admin)",
		Args:  "<" + kind + ">…",
		Flags: func(fs *flag.FlagSet) { outputFlag(fs, &output) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) == 0 {
				return cli.Usagef("expected at least one %s, by name (the org's) or ID (any org's)", kind)
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			k := kindOf(kind)
			req := &rpmgrv1.UpgradeAgentsRequest{}
			for _, ref := range args {
				id, err := k.Resolve(ctx, s.hc, s.creds.Controller, s.creds.Org, ref)
				if err != nil {
					return apiError(err)
				}
				if !slices.Contains(req.AgentIds, id) {
					req.AgentIds = append(req.AgentIds, id)
				}
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			rc := rpmgrv1connect.NewReleaseServiceClient(s.hc, s.creds.Controller)
			var resp *connect.Response[rpmgrv1.UpgradeAgentsResponse]
			if err := s.withStepUp(ctx, func() error {
				resp, err = rc.UpgradeAgents(ctx, connect.NewRequest(req))
				return err
			}); err != nil {
				return apiError(err)
			}
			ro := resp.Msg.GetRollout()
			w := notes(env, output).Stdout
			rows := make([]protoreflect.Message, 0, len(resp.Msg.GetRolloutTargets()))
			for _, t := range resp.Msg.GetRolloutTargets() {
				if _, err := fmt.Fprintf(w, "%s %s is number %d in the queue of easy rollout %s of %s.\n", kind,
					cmp.Or(t.GetAgentName(), t.GetAgentId()), t.GetPosition(), ro.GetId(), ro.GetVersion()); err != nil {
					return err
				}
				rows = append(rows, t.ProtoReflect())
			}
			return s.print(ctx, env.Stdout, kindOf("rollout-target"), output, rows, nil, true)
		},
	}
}

// updateController is `rpmgr create rollout --controller --release <version>`: the controller, or
// all-in-one, stages a release for the root updater of its host, which backs the database up and
// installs it (D158); `rpmgr get controller-update` tells how it stands.
func updateController(ctx context.Context, env *cli.Env, release string) error {
	s, err := newAPISession(env)
	if err != nil {
		return err
	}
	req := &rpmgrv1.UpdateControllerRequest{}
	if req.ReleaseId, err = s.releaseID(ctx, release); err != nil {
		return err
	}
	rc := rpmgrv1connect.NewReleaseServiceClient(s.hc, s.creds.Controller)
	var resp *connect.Response[rpmgrv1.UpdateControllerResponse]
	if err := s.withStepUp(ctx, func() error {
		resp, err = rc.UpdateController(ctx, connect.NewRequest(req))
		return err
	}); err != nil {
		return apiError(err)
	}
	_, err = fmt.Fprintf(env.Stdout, "Staged %s for the root updater, which backs the database up and installs it.\n"+
		"The controller restarts; follow it with `rpmgr get controller-update`.\n", resp.Msg.GetUpdate().GetVersion())
	return err
}

// getControllerUpdate is `rpmgr get controller-update`.
func getControllerUpdate(ctx context.Context, env *cli.Env) error {
	s, err := newAPISession(env)
	if err != nil {
		return err
	}
	resp, err := rpmgrv1connect.NewReleaseServiceClient(s.hc, s.creds.Controller).GetControllerUpdate(ctx, connect.NewRequest(&rpmgrv1.GetControllerUpdateRequest{}))
	if err != nil {
		return apiError(err)
	}
	return writeControllerUpdate(env.Stdout, resp.Msg.GetUpdate(), resp.Msg.GetBlocked(), resp.Msg.GetRunningVersion())
}

// writeControllerUpdate says how the controller's own update stands.
func writeControllerUpdate(w io.Writer, u *rpmgrv1.ControllerUpdate, blocked, running string) error {
	if _, err := fmt.Fprintf(w, "The controller runs %s.\n", running); err != nil {
		return err
	}
	if u == nil {
		_, err := fmt.Fprintln(w, "No update is under way or reported.")
		return err
	}
	state := strings.ToLower(strings.TrimPrefix(u.GetState().String(), "CONTROLLER_UPDATE_STATE_"))
	line := fmt.Sprintf("Update to %s: %s", u.GetVersion(), strings.ReplaceAll(state, "_", " "))
	if u.GetStep() != "" {
		line += " (" + strings.ReplaceAll(u.GetStep(), "_", " ") + ")"
	}
	if u.GetReason() != "" {
		line += ": " + u.GetReason()
	}
	if _, err := fmt.Fprintln(w, line+"."); err != nil {
		return err
	}
	if blocked != "" {
		_, err := fmt.Fprintf(w, "No update can be started now: %s.\n", blocked)
		return err
	}
	return nil
}

// advanceRollout is `rpmgr advance rollout`.
func advanceRollout() *cli.Command {
	var (
		percent int
		all     bool
		force   bool
		output  string
	)
	return &cli.Command{
		Name: "rollout", Summary: "move a running rollout to a higher percentage of the agents, or to all", Args: "(--percent <n> | --all) <rollout>",
		Flags: func(fs *flag.FlagSet) {
			fs.IntVar(&percent, "percent", 0, "the share of agents, 1 to 99, above the current one")
			fs.BoolVar(&all, "all", false, "every agent")
			fs.BoolVar(&force, "force", false, "advance without checking that the rollout is unchanged since this command read it")
			outputFlag(fs, &output)
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 || (percent == 0) == !all {
				return cli.Usagef("give --percent or --all, and the rollout's ID")
			}
			req := &rpmgrv1.AdvanceRolloutRequest{RolloutId: args[0], Next: &rpmgrv1.AdvanceRolloutRequest_All{All: true}}
			if !all {
				req.Next = &rpmgrv1.AdvanceRolloutRequest_Percentage{Percentage: int32(min(max(percent, -1), 100))} //nolint:gosec // G115: clamped
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			rc := rpmgrv1connect.NewReleaseServiceClient(s.hc, s.creds.Controller)
			if !force {
				if req.Etag, err = s.rolloutEtag(ctx, rc, args[0]); err != nil {
					return err
				}
			}
			var ro *rpmgrv1.Rollout
			if err := s.withStepUp(ctx, func() error {
				resp, err := rc.AdvanceRollout(ctx, connect.NewRequest(req))
				if err == nil {
					ro = resp.Msg.GetRollout()
				}
				return err
			}); err != nil {
				return apiError(err)
			}
			return s.writeRollout(ctx, env, output, "Advanced rollout %s of %s.\n", ro)
		},
	}
}

// changeRollout is pause, resume or cancel rollout; all but a pause take a step-up, which the API
// asks for.
func changeRollout(verb, summary string, stepUp bool) *cli.Command {
	var (
		force  bool
		output string
	)
	return &cli.Command{
		Name: "rollout", Summary: summary, Args: "<rollout>",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&force, "force", false, verb+" without checking that the rollout is unchanged since this command read it")
			outputFlag(fs, &output)
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the rollout's ID")
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			rc := rpmgrv1connect.NewReleaseServiceClient(s.hc, s.creds.Controller)
			etag := ""
			if !force {
				if etag, err = s.rolloutEtag(ctx, rc, args[0]); err != nil {
					return err
				}
			}
			var ro *rpmgrv1.Rollout
			call := func() error {
				var err error
				switch verb {
				case "pause":
					var resp *connect.Response[rpmgrv1.PauseRolloutResponse]
					if resp, err = rc.PauseRollout(ctx, connect.NewRequest(&rpmgrv1.PauseRolloutRequest{RolloutId: args[0], Etag: etag})); err == nil {
						ro = resp.Msg.GetRollout()
					}
				case "resume":
					var resp *connect.Response[rpmgrv1.ResumeRolloutResponse]
					if resp, err = rc.ResumeRollout(ctx, connect.NewRequest(&rpmgrv1.ResumeRolloutRequest{RolloutId: args[0], Etag: etag})); err == nil {
						ro = resp.Msg.GetRollout()
					}
				default:
					var resp *connect.Response[rpmgrv1.CancelRolloutResponse]
					if resp, err = rc.CancelRollout(ctx, connect.NewRequest(&rpmgrv1.CancelRolloutRequest{RolloutId: args[0], Etag: etag})); err == nil {
						ro = resp.Msg.GetRollout()
					}
				}
				return err
			}
			if stepUp {
				err = s.withStepUp(ctx, call)
			} else {
				err = call()
			}
			if err != nil {
				return apiError(err)
			}
			done := map[string]string{"pause": "Paused", "resume": "Resumed", "cancel": "Cancelled"}[verb]
			return s.writeRollout(ctx, env, output, done+" rollout %s of %s.\n", ro)
		},
	}
}

// writeRollout says what happened to a rollout, then shows it as table, YAML or JSON.
func (s *apiSession) writeRollout(ctx context.Context, env *cli.Env, output, what string, ro *rpmgrv1.Rollout) error {
	if _, err := fmt.Fprintf(notes(env, output).Stdout, what, ro.GetId(), ro.GetVersion()); err != nil {
		return err
	}
	return s.print(ctx, env.Stdout, kindOf("rollout"), output, []protoreflect.Message{ro.ProtoReflect()}, []string{ro.GetId()}, false)
}

// rolloutEtag reads a rollout's etag.
func (s *apiSession) rolloutEtag(ctx context.Context, rc rpmgrv1connect.ReleaseServiceClient, id string) (string, error) {
	resp, err := rc.GetRollout(ctx, connect.NewRequest(&rpmgrv1.GetRolloutRequest{RolloutId: id}))
	if err != nil {
		return "", apiError(err)
	}
	return resp.Msg.GetRollout().GetEtag(), nil
}

// releaseID is the ID of the release a version or an ID names.
func (s *apiSession) releaseID(ctx context.Context, ref string) (string, error) {
	if strings.HasPrefix(ref, kindOf("release").Prefix) {
		return ref, nil
	}
	rc := rpmgrv1connect.NewReleaseServiceClient(s.hc, s.creds.Controller)
	for page := ""; ; {
		resp, err := rc.ListReleases(ctx, connect.NewRequest(&rpmgrv1.ListReleasesRequest{PageSize: 500, PageToken: page}))
		if err != nil {
			return "", apiError(err)
		}
		for _, r := range resp.Msg.GetReleases() {
			if r.GetVersion() == strings.TrimPrefix(ref, "v") {
				return r.GetId(), nil
			}
		}
		if page = resp.Msg.GetNextPageToken(); page == "" {
			return "", fmt.Errorf("the controller knows no release %s; rpmgr list release shows those it knows", ref)
		}
	}
}

// agentID is the ID of the agent ref names: an ID of any org as it is, else the org's connector
// or gateway of that name.
func (s *apiSession) agentID(ctx context.Context, ref string) (string, error) {
	con, gw := kindOf("connector"), kindOf("gateway")
	if strings.HasPrefix(ref, con.Prefix) || strings.HasPrefix(ref, gw.Prefix) {
		return ref, nil
	}
	var errs []error
	for _, k := range []apicli.Kind{con, gw} {
		id, err := k.Resolve(ctx, s.hc, s.creds.Controller, s.creds.Org, ref)
		if err == nil {
			return id, nil
		}
		errs = append(errs, err)
	}
	var cerr *connect.Error
	if err := errors.Join(errs...); errors.As(err, &cerr) {
		return "", apiError(cerr)
	}
	return "", fmt.Errorf("the org has no connector or gateway named %q", ref)
}

// readSmall reads a file of at most maxReleaseFile bytes.
func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the user's file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxReleaseFile+1))
	if err == nil && len(b) > maxReleaseFile {
		err = fmt.Errorf("%s is larger than %d bytes", path, maxReleaseFile)
	}
	return b, err
}
