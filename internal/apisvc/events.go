// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
)

// The event stream (docs/07-api.md, "Events and streaming").
const (
	eventsEvery = time.Second // how often a stream looks for new revisions
	eventsBatch = 100         // revisions read at once
)

var errResumeToken = connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: the resume token is not one WatchEvents gave"))

// resumeToken is where a stream resumes after the revision seq of epoch.
func resumeToken(epoch string, seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(epoch + "/" + strconv.FormatInt(seq, 10)))
}

func parseResumeToken(tok string) (string, int64, error) {
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return "", 0, errResumeToken
	}
	epoch, seq, ok := strings.Cut(string(b), "/")
	n, err := strconv.ParseInt(seq, 10, 64)
	if !ok || epoch == "" || err != nil || n < 0 {
		return "", 0, errResumeToken
	}
	return epoch, n, nil
}

// WatchEvents implements StatusService. Revisions are committed in the order of their seq
// (docs/03-connections.md, "Revisions and ordering"), so following the seq misses none. The
// revisions are instance rows, read in the controller's system scope, filtered to the org.
func (s *Status) WatchEvents(ctx context.Context, req *connect.Request[rpmgrv1.WatchEventsRequest],
	stream *connect.ServerStream[rpmgrv1.WatchEventsResponse]) error {
	org := req.Msg.GetOrgId()
	var cur store.Revision
	if err := store.ReadTx(s.Sys, s.DB, func(_ *ent.Tx, rev store.Revision) error { cur = rev; return nil }); err != nil {
		return storeError(err)
	}
	after := cur.Seq
	var epoch string
	var seq int64
	if tok := req.Msg.GetResumeToken(); tok != "" {
		var err error
		if epoch, seq, err = parseResumeToken(tok); err != nil {
			return err
		}
	}
	// The headers go out at once, so a client knows that the stream is open before the first event.
	if err := stream.Send(nil); err != nil {
		return err
	}
	if epoch != "" {
		if epoch == cur.DBEpoch {
			after = seq
		} else if err := stream.Send(&rpmgrv1.WatchEventsResponse{Reset_: true, Revision: revisionOf(cur),
			ResumeToken: resumeToken(cur.DBEpoch, cur.Seq)}); err != nil {
			return err
		}
	}
	every := s.Every
	if every == 0 {
		every = eventsEvery
	}
	for {
		rows, err := s.DB.ReadClient().ConfigRevision.Query().Where(configrevision.OrgID(org), configrevision.DbEpoch(cur.DBEpoch),
			configrevision.IDGT(after)).Order(ent.Asc(configrevision.FieldID)).Limit(eventsBatch).All(s.Sys)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return storeError(err)
		}
		for _, r := range rows {
			if err := stream.Send(&rpmgrv1.WatchEventsResponse{Revision: &rpmgrv1.Revision{DbEpoch: r.DbEpoch, Seq: r.ID},
				ChangedResources: r.ChangedResources, Actor: r.Actor, Time: timestamppb.New(r.CreatedAt),
				ResumeToken: resumeToken(r.DbEpoch, r.ID)}); err != nil {
				return err
			}
			after = r.ID
		}
		if len(rows) == eventsBatch {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(every):
		}
	}
}
