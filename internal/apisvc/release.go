// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/mod/semver"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	entrelease "github.com/felix-homelab/rpmgr/internal/store/ent/release"
)

// Reasons of ReleaseService (docs/07-api.md, "Errors"): an upload whose chain does not verify,
// and a release check asked for while it is off or the build checks for no releases.
const (
	ReasonReleaseDoesNotVerify = "RELEASE_DOES_NOT_VERIFY"
	ReasonReleaseCheckOff      = "RELEASE_CHECK_OFF"
)

// ReleaseChecker is the controller's release check (controller.ReleaseChecks).
type ReleaseChecker interface {
	// Status is the state of the release check.
	Status() *rpmgrv1.ReleaseCheck
	// CheckNow asks for a check at once and returns the state; a positive wait refuses it for
	// that long, and release.ErrDevelopment says the build checks for no releases.
	CheckNow() (*rpmgrv1.ReleaseCheck, time.Duration, error)
}

// Releases is ReleaseService (docs/04-security.md, "Over-the-air updates"; D121). Releases and
// rollouts are instance rows, which its methods read and change in the controller's system scope;
// the rollout job acts on what they record.
type Releases struct {
	rpmgrv1connect.UnimplementedReleaseServiceHandler
	DB  *store.DB
	Sys context.Context
	API *api.Server
	// Version is the controller's own version: no rollout installs a newer one.
	Version string
	// MinAgentVersion is the oldest agent version the controller accepts (controller.MinAgentVersion
	// of Version): no rollout installs an older one, whose agents it would refuse. Empty accepts
	// every version.
	MinAgentVersion string
	// Roots verify uploaded releases; nil is the roots compiled into the binary.
	Roots []release.PublicKey
	// MirrorNow, if set, asks the release mirror to check at once, without waiting for it: for a
	// rollout's target or an uploaded manifest the mirror does not hold yet (D125).
	MirrorNow func()
	// Checks is the release check; nil checks for no releases.
	Checks ReleaseChecker
	Now    func() time.Time
}

var (
	releaseSources = map[entrelease.Source]rpmgrv1.ReleaseSource{entrelease.SourceCheck: rpmgrv1.ReleaseSource_RELEASE_SOURCE_CHECK,
		entrelease.SourceUpload: rpmgrv1.ReleaseSource_RELEASE_SOURCE_UPLOAD, entrelease.SourceImport: rpmgrv1.ReleaseSource_RELEASE_SOURCE_IMPORT}
	releaseChannels = map[entrelease.Channel]rpmgrv1.UpdateChannel{entrelease.ChannelStable: rpmgrv1.UpdateChannel_UPDATE_CHANNEL_STABLE,
		entrelease.ChannelPrerelease: rpmgrv1.UpdateChannel_UPDATE_CHANNEL_PRERELEASE}
)

// ListReleases implements ReleaseService: the releases by version, the newest first, paged by
// version, which is unique.
func (r *Releases) ListReleases(ctx context.Context, req *connect.Request[rpmgrv1.ListReleasesRequest]) (
	*connect.Response[rpmgrv1.ListReleasesResponse], error) {
	size, err := api.PageSize(req.Msg.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := r.API.AfterPage(req.Msg.GetPageToken(), req.Msg)
	if err != nil {
		return nil, err
	}
	rows, err := r.DB.ReadClient().Release.Query().All(store.CarryTxHook(r.Sys, ctx))
	if err != nil {
		return nil, storeError(err)
	}
	slices.SortFunc(rows, func(a, b *ent.Release) int { return compareVersions(b.Version, a.Version) })
	if after != "" {
		i := slices.IndexFunc(rows, func(x *ent.Release) bool { return compareVersions(x.Version, after) < 0 })
		if i < 0 {
			i = len(rows)
		}
		rows = rows[i:]
	}
	out := &rpmgrv1.ListReleasesResponse{ControllerVersion: r.Version, ReleaseCheck: r.checkStatus()}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = r.API.PageToken(rows[size-1].Version, req.Msg)
	}
	for _, x := range rows {
		out.Releases = append(out.Releases, r.releaseOf(x))
	}
	return connect.NewResponse(out), nil
}

// CheckReleases implements ReleaseService: the release check runs now, unless it is off, ran a
// moment ago or the release source limits the rate; a check that runs is joined.
func (r *Releases) CheckReleases(ctx context.Context, _ *connect.Request[rpmgrv1.CheckReleasesRequest]) (
	*connect.Response[rpmgrv1.CheckReleasesResponse], error) {
	if r.Checks == nil {
		return nil, checkOff(release.ErrDevelopment)
	}
	set, _, err := settings.Instance(store.CarryTxHook(r.Sys, ctx), r.DB.ReadClient())
	if err != nil {
		return nil, storeError(err)
	}
	if !set.GetReleaseCheck() {
		return nil, checkOff(errors.New("apisvc: the release check is off; turn it on in the instance settings first"))
	}
	st, wait, err := r.Checks.CheckNow()
	if err != nil {
		return nil, checkOff(err)
	}
	if wait > 0 {
		return nil, retryAfter(connect.NewError(connect.CodeResourceExhausted,
			fmt.Errorf("apisvc: the release check ran a moment ago, or the release source limits the rate; check again in %s", wait.Round(time.Second))), wait)
	}
	return connect.NewResponse(&rpmgrv1.CheckReleasesResponse{ReleaseCheck: st}), nil
}

func checkOff(err error) error {
	return withReason(connect.NewError(connect.CodeFailedPrecondition, err), ReasonReleaseCheckOff)
}

func (r *Releases) checkStatus() *rpmgrv1.ReleaseCheck {
	if r.Checks == nil {
		return &rpmgrv1.ReleaseCheck{Outcome: rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_NONE}
	}
	return r.Checks.Status()
}

// UploadRelease implements ReleaseService: the signed files are verified like the release
// check's, against the release roots at the time now.
func (r *Releases) UploadRelease(ctx context.Context, req *connect.Request[rpmgrv1.UploadReleaseRequest]) (
	*connect.Response[rpmgrv1.UploadReleaseResponse], error) {
	m := req.Msg
	// The audit entry records what identifies the upload, not its up to 1.1 MiB of files.
	sum := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	diff := map[string]any{"manifest_sha256": sum(m.GetManifest()), "signing_key_statement_sha256": sum(m.GetSigningKeyStatement())}
	audited := func() {
		if b, err := json.Marshal(diff); err == nil {
			api.AuditDiff(ctx, string(b))
		}
	}
	audited()
	roots := r.Roots
	if roots == nil {
		roots = release.Roots()
	}
	man, err := release.Verify(roots, m.GetSigningKeyStatement(), m.GetStatementSignature(), m.GetManifest(), m.GetManifestSignature(), r.now())
	if err == nil && !release.Releasable(man.Version) {
		err = fmt.Errorf("release: %q is no release version", man.Version)
	}
	if err != nil {
		return nil, withReason(connect.NewError(connect.CodeInvalidArgument, err), ReasonReleaseDoesNotVerify)
	}
	diff["version"], diff["seq"], diff["channel"] = man.Version, man.Seq, man.Channel
	audited()
	row, err := store.RecordRelease(store.CarryTxHook(r.Sys, ctx), r.DB, &release.Signed{Manifest: man, Statement: m.GetSigningKeyStatement(),
		StatementSig: m.GetStatementSignature(), ManifestJSON: m.GetManifest(), ManifestSig: m.GetManifestSignature()}, entrelease.SourceUpload, nil)
	if err != nil {
		return nil, storeError(err)
	}
	if row.MirroredAt == nil {
		r.mirrorNow()
	}
	return connect.NewResponse(&rpmgrv1.UploadReleaseResponse{Release: r.releaseOf(row)}), nil
}

// releaseOf is a release as the API shows it.
func (r *Releases) releaseOf(x *ent.Release) *rpmgrv1.Release {
	out := &rpmgrv1.Release{Id: x.ID, Version: x.Version, Channel: releaseChannels[x.Channel], ManifestSeq: x.ManifestSeq,
		Source: releaseSources[x.Source], Mirrored: x.MirroredAt != nil, CreateTime: timestamppb.New(x.CreatedAt),
		ControllerVersion: x.Version == r.Version, NewerThanController: !release.Releasable(r.Version) || compareVersions(x.Version, r.Version) > 0}
	if x.MirroredAt != nil {
		out.MirrorTime = timestamppb.New(*x.MirroredAt)
	}
	return out
}

// compareVersions compares two release versions by semantic versioning.
func compareVersions(a, b string) int { return semver.Compare("v"+a, "v"+b) }

func (r *Releases) mirrorNow() {
	if r.MirrorNow != nil {
		r.MirrorNow()
	}
}

func (r *Releases) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
