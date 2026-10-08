// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/ids"
)

// ErrorDomain is the domain of the google.rpc.ErrorInfo details of API errors.
const ErrorDomain = "rpmgr.v1"

// The reasons of API errors (docs/07-api.md, "Errors").
const (
	ReasonStepUpRequired    = "STEP_UP_REQUIRED"
	ReasonPermissionMissing = "PERMISSION_MISSING"
)

func (s *Server) interceptor() connect.Interceptor { return interceptor{s} }

type interceptor struct{ s *Server }

func (i interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		msg, ok := req.Any().(proto.Message)
		md, isMethod := req.Spec().Schema.(protoreflect.MethodDescriptor)
		if !ok || !isMethod {
			return nil, connect.NewError(connect.CodeInternal, errors.New("api: a request without a protobuf method"))
		}
		rec := i.s.newRecord(md, req.Header(), req.Peer(), msg)
		ctx, err := i.s.admit(ctx, md, req.Header(), msg, rec)
		if err != nil {
			rec.finish(ctx, err)
			return nil, err
		}
		resp, err := next(rec.hook(ctx), req)
		rec.finish(ctx, err)
		return resp, err
	}
}

func (interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler admits a server stream on its one request message, which the handler then
// receives as usual.
func (i interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		md, ok := conn.Spec().Schema.(protoreflect.MethodDescriptor)
		if !ok || md.IsStreamingClient() {
			return connect.NewError(connect.CodeUnimplemented, errors.New("api: only server streams are served"))
		}
		msg := newMessage(md.Input())
		if err := conn.Receive(msg); err != nil {
			if errors.Is(err, io.EOF) {
				return connect.NewError(connect.CodeInvalidArgument, errors.New("api: no request message"))
			}
			return err
		}
		rec := i.s.newRecord(md, conn.RequestHeader(), conn.Peer(), msg)
		ctx, err := i.s.admit(ctx, md, conn.RequestHeader(), msg, rec)
		if err != nil {
			rec.finish(ctx, err)
			return err
		}
		err = next(rec.hook(ctx), &replay{StreamingHandlerConn: conn, first: msg})
		rec.finish(ctx, err)
		return err
	}
}

// newMessage returns an empty message of a type: the generated one, or a dynamic one.
func newMessage(md protoreflect.MessageDescriptor) proto.Message {
	if mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName()); err == nil {
		return mt.New().Interface()
	}
	return dynamicpb.NewMessage(md)
}

// replay hands a stream's first request message, already received, to the handler.
type replay struct {
	connect.StreamingHandlerConn
	first proto.Message
}

func (r *replay) Receive(m any) error {
	if r.first == nil {
		return r.StreamingHandlerConn.Receive(m)
	}
	b, err := proto.Marshal(r.first)
	r.first = nil
	if err != nil {
		return err
	}
	pm, ok := m.(proto.Message)
	if !ok {
		return errors.New("api: receiving into a value that is not a protobuf message")
	}
	return proto.Unmarshal(b, pm)
}

// admit authenticates, authorizes and validates one request, and returns the context the handler
// runs in: with the caller, and for org permissions with the scope of the resource's org. rec
// learns who acted and where. On an error the returned context is ctx.
func (s *Server) admit(ctx context.Context, md protoreflect.MethodDescriptor, header http.Header, msg proto.Message,
	rec *record) (context.Context, error) {
	// Mount checked the method already; this guards handlers mounted another way.
	if err := checkMethod(md); err != nil {
		s.o.Logger.Error("refused a method whose authorization cannot be enforced", "method", md.FullName(), "error", err)
		return ctx, connect.NewError(connect.CodePermissionDenied, errors.New("api: the method cannot be authorized"))
	}
	a, _ := authzOf(md)
	var caller *Caller
	if s.o.Authenticator != nil {
		c, err := s.o.Authenticator.Authenticate(ctx, header)
		switch {
		case err == nil:
			caller = c
		case a.GetPermission() != authz.PermPublic:
			s.o.Logger.Debug("refused credentials", "method", md.FullName(), "error", err)
			return ctx, connect.NewError(connect.CodeUnauthenticated, errors.New("api: the credentials are not valid"))
		}
		// A public method serves a caller with stale credentials as anonymous, so an expired
		// session can still log in again.
	}
	rec.by(caller)
	scoped, err := s.authorize(context.WithValue(ctx, callerKey{}, caller), md, a, caller, msg.ProtoReflect(), rec)
	if err != nil {
		return ctx, err
	}
	if err := s.validator.Validate(msg); err != nil {
		return scoped, invalid(err)
	}
	return scoped, nil
}

// authorize applies a method's permission to the caller: org permissions in the org of the
// request's resource, where a caller who is no member finds nothing, then step-up.
func (s *Server) authorize(ctx context.Context, md protoreflect.MethodDescriptor, a *rpmgrv1.Authz, caller *Caller,
	msg protoreflect.Message, rec *record) (context.Context, error) {
	p := a.GetPermission()
	if p == authz.PermPublic {
		return ctx, nil
	}
	if caller == nil || caller.UserID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("api: sign in first"))
	}
	switch p {
	case authz.PermAuthenticated:
		if !caller.scoped(p) {
			return nil, denied(p)
		}
	case authz.PermInstanceAdmin:
		if !caller.InstanceAdmin || !caller.scoped(p) {
			return nil, denied(p)
		}
	default:
		fds, err := fieldPath(md.Input(), a.GetResourceField())
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		org, err := s.orgOf(ctx, a.GetResourceField(), fieldValue(msg, fds))
		if err != nil {
			return nil, err
		}
		role, member := caller.Memberships[org]
		if !member {
			return nil, errNotFound()
		}
		rec.in(org)
		enroll := false
		if p == authz.PermConnectorsWrite && role == authz.RoleOperator {
			if enroll, err = s.o.OperatorsMayEnroll(ctx, org); err != nil {
				s.o.Logger.Error("cannot read an org's settings", "org", org, "error", err)
				return nil, connect.NewError(connect.CodeInternal, errors.New("api: cannot read the org's settings"))
			}
		}
		if !authz.Grants(role, p, enroll) || !caller.scoped(p) {
			return nil, denied(p)
		}
		if ctx, err = authz.ForOrg(ctx, caller.Principal, org); err != nil {
			return nil, errNotFound()
		}
	}
	if a.GetStepUp() && (caller.StepUpAt.IsZero() || s.o.Now().Sub(caller.StepUpAt) > StepUpWindow) {
		return nil, withInfo(connect.NewError(connect.CodeUnauthenticated, errors.New("api: step-up required")), ReasonStepUpRequired, nil)
	}
	return ctx, nil
}

// orgOf returns the org of the resource a request names.
func (s *Server) orgOf(ctx context.Context, field, id string) (string, error) {
	switch {
	case id == "":
		return "", connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("api: %s is required", field))
	case ids.Valid("org", id):
		return id, nil
	}
	org, err := s.o.Resolver(ctx, id)
	switch {
	case errors.Is(err, ErrNotFound):
		return "", errNotFound()
	case err != nil:
		s.o.Logger.Error("cannot resolve a resource's org", "id", id, "error", err)
		return "", connect.NewError(connect.CodeInternal, errors.New("api: cannot look the resource up"))
	}
	return org, nil
}

// scoped reports whether a token's scopes include p; a session has every permission of its roles.
func (c *Caller) scoped(p string) bool { return c.Scopes == nil || slices.Contains(c.Scopes, p) }

// errNotFound is the same for a resource that does not exist and one in another org, so callers
// learn nothing about other orgs (docs/07-api.md, "Errors").
func errNotFound() error { return connect.NewError(connect.CodeNotFound, errors.New("api: not found")) }

func denied(p string) error {
	return withInfo(connect.NewError(connect.CodePermissionDenied, fmt.Errorf("api: the permission %s is missing", p)),
		ReasonPermissionMissing, map[string]string{"permission": p})
}

func withInfo(err *connect.Error, reason string, metadata map[string]string) error {
	if d, derr := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: ErrorDomain, Metadata: metadata}); derr == nil {
		err.AddDetail(d)
	}
	return err
}

// invalid turns a protovalidate failure into INVALID_ARGUMENT with the field violations.
func invalid(err error) error {
	var verr *protovalidate.ValidationError
	if !errors.As(err, &verr) {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("api: validation: %w", err))
	}
	cerr := connect.NewError(connect.CodeInvalidArgument, errors.New("api: the request is not valid"))
	if d, derr := connect.NewErrorDetail(verr.ToProto()); derr == nil {
		cerr.AddDetail(d)
	}
	return cerr
}
