// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/apirequest"
)

// DedupWindow is how long a request_id makes retries of a Create call idempotent, and PruneEvery
// how often IDs past it are deleted (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	DedupWindow = 24 * time.Hour
	PruneEvery  = time.Hour
)

// Dedupe runs create, a Create method's work, once per caller, method and request_id within
// DedupWindow (docs/07-api.md, "Resource design"). The first request's transactions reserve the
// ID, so the change and the reservation commit together; its response is then stored under the
// KEK. A retry gets that response, without running create. A request_id used before with another
// request is INVALID_ARGUMENT; one whose first request has not answered is ABORTED. Without a
// request_id or a signed-in caller, create just runs.
func Dedupe[T proto.Message](ctx context.Context, s *Server, requestID string, req proto.Message,
	create func(context.Context) (T, error)) (T, error) {
	var zero T
	caller := CallerFrom(ctx)
	if requestID == "" || caller == nil || caller.UserID == "" {
		return create(ctx)
	}
	method := string(req.ProtoReflect().Descriptor().FullName())
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if err != nil {
		return zero, err
	}
	hash := sha256.Sum256(b)
	row, err := s.o.DB.Client().APIRequest.Query().Where(apirequest.CallerID(caller.UserID), apirequest.Method(method),
		apirequest.RequestID(requestID)).Only(s.o.Sys)
	switch {
	case ent.IsNotFound(err):
	case err != nil:
		return zero, err
	case !row.CreatedAt.After(s.o.Now().Add(-DedupWindow)):
		// Past the window, not pruned yet: the request_id is free again.
		if err := s.o.DB.Client().APIRequest.DeleteOneID(row.ID).Exec(s.o.Sys); err != nil {
			return zero, err
		}
	case string(row.RequestHash) != string(hash[:]):
		return zero, connect.NewError(connect.CodeInvalidArgument, errors.New("api: the request_id was used for another request"))
	case row.ResponseEnc == nil || len(*row.ResponseEnc) == 0:
		return zero, connect.NewError(connect.CodeAborted, errors.New("api: the first request with this request_id has not answered; retry"))
	default:
		return storedResponse(s, row, zero)
	}

	id := ""
	var reserved, conflict atomic.Bool
	ctx = store.WithTxHook(ctx, func(_ context.Context, tx *ent.Tx) error {
		if reserved.Load() {
			return nil
		}
		r, err := tx.APIRequest.Create().SetCallerID(caller.UserID).SetMethod(method).SetRequestID(requestID).
			SetRequestHash(hash[:]).SetCreatedAt(s.o.Now()).Save(s.o.Sys)
		if err != nil {
			conflict.Store(ent.IsConstraintError(err))
			return err
		}
		id = r.ID
		reserved.Store(true)
		return nil
	})
	resp, err := create(ctx)
	switch {
	case conflict.Load():
		return zero, connect.NewError(connect.CodeAborted, errors.New("api: another request with this request_id runs; retry"))
	case err != nil && reserved.Load():
		// A retry runs again rather than waiting for a response that never comes.
		if derr := s.o.DB.Client().APIRequest.DeleteOneID(id).Exec(s.o.Sys); derr != nil {
			s.o.Logger.Error("cannot release a request_id", "id", id, "error", derr)
		}
		return zero, err
	case err != nil || !reserved.Load():
		return resp, err // nothing was written, so a retry may run again
	}
	if err := s.store(id, resp); err != nil {
		s.o.Logger.Error("cannot store the response of a request_id; retries will get ABORTED", "id", id, "error", err)
	}
	return resp, nil
}

// store keeps a response under the KEK.
func (s *Server) store(id string, resp proto.Message) error {
	b, err := proto.Marshal(resp)
	if err != nil {
		return err
	}
	sealed, err := s.o.Sealer.Seal(responseContext(id), secret.FromBytes(b))
	if err != nil {
		return err
	}
	return s.o.DB.Client().APIRequest.UpdateOneID(id).SetResponseEnc(sealed).Exec(s.o.Sys)
}

// storedResponse returns the stored response as a T.
func storedResponse[T proto.Message](s *Server, row *ent.APIRequest, zero T) (T, error) {
	v, err := s.o.Sealer.Open(responseContext(row.ID), *row.ResponseEnc)
	if err != nil {
		return zero, err
	}
	out, ok := zero.ProtoReflect().New().Interface().(T)
	if !ok {
		return zero, errors.New("api: a stored response of another type")
	}
	return out, proto.Unmarshal([]byte(v.Reveal()), out)
}

func responseContext(id string) secret.Context {
	return secret.Context{Table: "api_requests", Column: "response_enc", RowID: id}
}

// PruneJob is the singleton job that deletes request_ids older than DedupWindow every interval.
func (s *Server) PruneJob(every time.Duration) lease.Job {
	return lease.Job{Name: "api-requests", Reason: "forget request_ids past the deduplication window", Every: every,
		Run: func(ctx context.Context, _ lease.Lease) error {
			_, err := s.o.DB.Client().APIRequest.Delete().Where(apirequest.CreatedAtLTE(s.o.Now().Add(-DedupWindow))).Exec(ctx)
			return err
		}}
}
