// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// Redacted replaces the value of a sensitive string field in audit diffs.
const Redacted = "[REDACTED]"

// record is the audit entry of one state-changing request (docs/04-security.md, "Audit log"). A
// write transaction of the handler appends it, so it commits with the change; a request that
// fails, is refused or writes nothing gets it in a transaction of its own.
type record struct {
	s        *Server
	req      *audit.Request
	appended atomic.Bool
}

// newRecord starts the record of a request, or returns nil for a method without side effects.
func (s *Server) newRecord(md protoreflect.MethodDescriptor, header http.Header, peer connect.Peer, msg proto.Message) *record {
	if opts, ok := md.Options().(*descriptorpb.MethodOptions); ok &&
		opts.GetIdempotencyLevel() == descriptorpb.MethodOptions_NO_SIDE_EFFECTS {
		return nil
	}
	ip := peer.Addr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	e := audit.Entry{ActorType: audit.ActorAnonymous, IP: ip, UserAgent: header.Get("User-Agent"),
		Action: string(md.FullName()), Diff: diffOf(msg)}
	if a, ok := authzOf(md); ok && a.GetResourceField() != "" {
		if fds, err := fieldPath(md.Input(), a.GetResourceField()); err == nil {
			e.TargetType = strings.TrimSuffix(strings.Split(a.GetResourceField(), ".")[0], "_id")
			e.TargetID = fieldValue(msg.ProtoReflect(), fds)
		}
	}
	if fd := md.Input().Fields().ByName("request_id"); fd != nil && fd.Kind() == protoreflect.StringKind && !fd.IsList() {
		e.RequestID = msg.ProtoReflect().Get(fd).String()
	}
	if e.RequestID == "" {
		e.RequestID = ids.New("req")
	}
	return &record{s: s, req: &audit.Request{Entry: e}}
}

// RequestIDHeader names the response header with a recorded request's ID, which its audit entries
// carry: the request's request_id if it has one, else one the API makes.
const RequestIDHeader = "Rpmgr-Request-Id"

// tell sets the request ID header on a response or an error.
func (r *record) tell(h http.Header, err error) {
	if r == nil {
		return
	}
	if cerr := new(connect.Error); errors.As(err, &cerr) {
		h = cerr.Meta()
	}
	if h != nil {
		h.Set(RequestIDHeader, r.req.Entry.RequestID)
	}
}

// by records who acted.
func (r *record) by(c *Caller) {
	if r == nil || c == nil || c.UserID == "" {
		return
	}
	e := &r.req.Entry
	e.ActorType, e.ActorID, e.CredentialID, e.AuthMethod = audit.ActorUser, c.UserID, c.CredentialID, c.AuthMethod
}

// in records the org the request acts in, whose chain gets the entry; none is the instance chain.
func (r *record) in(org string) {
	if r != nil {
		r.req.Entry.OrgID = org
	}
}

type recordKey struct{}

// SignedIn records in the audit entry of the request in ctx that userID signed in, with the
// session it got and the factors it used: a login's entry names who signed in, not the caller
// before.
func SignedIn(ctx context.Context, userID, sessionID, factors string) {
	if r, _ := ctx.Value(recordKey{}).(*record); r != nil {
		e := &r.req.Entry
		e.ActorType, e.ActorID, e.CredentialID, e.AuthMethod = audit.ActorUser, userID, sessionID, factors
		e.TargetType, e.TargetID = "user", userID
	}
}

// AuditReason sets the reason in the audit entry of the request in ctx.
func AuditReason(ctx context.Context, reason string) {
	if r, _ := ctx.Value(recordKey{}).(*record); r != nil {
		r.req.Entry.Reason = reason
	}
}

// hook returns ctx whose write transactions append the entry, as a success, before they commit,
// unless a service recorded the change in the transaction itself (audit.Append); handlers reach
// the entry through it (SignedIn, AuditReason).
func (r *record) hook(ctx context.Context) context.Context {
	if r == nil {
		return ctx
	}
	ctx = context.WithValue(ctx, recordKey{}, r)
	return store.WithTxValue(store.WithTxHook(ctx, func(ctx context.Context, tx *ent.Tx) error {
		ok, err := r.req.AppendOwn(ctx, tx, audit.Success)
		if ok {
			r.appended.Store(true)
		}
		return err
	}), r.req)
}

// finish records the outcome of a request no transaction recorded: a success that wrote nothing,
// a refusal, a failure. ctx carries the request's scope, if it got one.
func (r *record) finish(ctx context.Context, err error) {
	if r == nil || err == nil && (r.appended.Load() || r.req.Recorded()) {
		return
	}
	// A rate limit's refusal of an anonymous caller is not recorded: the limit bounds such
	// requests, and an entry for each would let a flood write the log at its own pace.
	if connect.CodeOf(err) == connect.CodeResourceExhausted && r.req.Entry.ActorType == audit.ActorAnonymous {
		return
	}
	e := r.req.Entry
	switch code := connect.CodeOf(err); {
	case err == nil:
		e.Result = audit.Success
	case code == connect.CodeUnauthenticated || code == connect.CodePermissionDenied || code == connect.CodeNotFound:
		e.Result, e.Reason = audit.Denied, code.String()
	default:
		e.Result, e.Reason = audit.Failure, code.String()
	}
	if _, aerr := audit.Record(ctx, r.s.o.DB, e); aerr != nil {
		r.s.o.Logger.Error("cannot record a request in the audit log", "action", e.Action, "error", aerr)
	}
}

// diffOf is the request as JSON with its sensitive fields redacted.
func diffOf(msg proto.Message) string {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(Redact(msg))
	if err != nil {
		return ""
	}
	return string(b)
}

// Redact returns a copy of m with every field marked (rpmgr.v1.sensitive) redacted, in nested
// messages, lists and maps too: a string becomes Redacted, so the record shows that one was given;
// any other value is cleared. Go's protobuf libraries print debug_redact fields as they are
// (VB-04), so every log and audit diff of a message goes through Redact.
func Redact(m proto.Message) proto.Message {
	c := proto.Clone(m)
	redact(c.ProtoReflect())
	return c
}

func redact(m protoreflect.Message) {
	var fields []protoreflect.FieldDescriptor
	m.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		fields = append(fields, fd)
		return true
	})
	for _, fd := range fields {
		switch {
		case sensitive(fd) && fd.Kind() == protoreflect.StringKind && fd.Cardinality() != protoreflect.Repeated:
			m.Set(fd, protoreflect.ValueOfString(Redacted))
		case sensitive(fd):
			m.Clear(fd)
		case fd.IsMap() && fd.MapValue().Kind() == protoreflect.MessageKind:
			m.Mutable(fd).Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
				redact(v.Message())
				return true
			})
		case fd.IsList() && fd.Kind() == protoreflect.MessageKind:
			l := m.Mutable(fd).List()
			for i := range l.Len() {
				redact(l.Get(i).Message())
			}
		case !fd.IsMap() && !fd.IsList() && fd.Kind() == protoreflect.MessageKind:
			redact(m.Mutable(fd).Message())
		}
	}
}

func sensitive(fd protoreflect.FieldDescriptor) bool {
	opts := fd.Options()
	if opts == nil || !proto.HasExtension(opts, rpmgrv1.E_Sensitive) {
		return false
	}
	v, _ := proto.GetExtension(opts, rpmgrv1.E_Sensitive).(bool)
	return v
}

// errNoDB is returned by New without the database, the system scope or the sealer.
var errNoDB = errors.New("api: the audit log and the request_ids need the database, the system scope and the sealer")
