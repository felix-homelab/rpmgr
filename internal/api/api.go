// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// StepUpWindow is how long a step-up re-authentication lasts (docs/04-security.md, "Human
// authentication and sessions").
const StepUpWindow = 10 * time.Minute

// Caller is the authenticated principal of a request.
type Caller struct {
	authz.Principal           // the user and the roles of their memberships, by org ID
	CredentialID    string    // the session or token ID, never the secret
	AuthMethod      string    // "session" or "token"
	InstanceAdmin   bool      // holds the instance-level role
	StepUpAt        time.Time // the last step-up; zero for none
	Scopes          []string  // a token's permissions; nil for a session, which has its roles'
}

// Authenticator finds the caller of a request from its headers: nil without credentials, or an
// error for credentials that are not valid, which the request gets as UNAUTHENTICATED.
type Authenticator interface {
	Authenticate(ctx context.Context, header http.Header) (*Caller, error)
}

// Options configure a Server.
type Options struct {
	// DB keeps the audit log of state-changing requests and the request_ids of Create calls.
	DB *store.DB
	// Sys is the controller's system scope, for the request_ids, which belong to no org.
	Sys context.Context
	// Sealer keeps the responses of request_ids under the KEK.
	Sealer *secret.Sealer
	// Authenticator finds callers; nil leaves every caller anonymous.
	Authenticator Authenticator
	// Resolver finds the org of a resource ID; StoreResolver is the controller's.
	Resolver Resolver
	// OperatorsMayEnroll returns an org's setting that gives Operators connectors.write.
	OperatorsMayEnroll func(ctx context.Context, orgID string) (bool, error)
	// PageKey authenticates page tokens; the controller derives it from the KEK, so tokens stay
	// valid across restarts. Without it, a random key lasts as long as the Server.
	PageKey []byte
	Now     func() time.Time
	Logger  *slog.Logger
}

// Server holds the interceptor every method of the public API goes through.
type Server struct {
	o         Options
	validator protovalidate.Validator
	pageKey   []byte
}

// New returns a Server.
func New(o Options) (*Server, error) {
	if o.Resolver == nil || o.OperatorsMayEnroll == nil {
		return nil, errors.New("api: a resolver and the operator setting are required")
	}
	if o.DB == nil || o.Sys == nil || o.Sealer == nil {
		return nil, errNoDB
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	v, err := protovalidate.New()
	if err != nil {
		return nil, err
	}
	key := o.PageKey
	if len(key) == 0 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	return &Server{o: o, validator: v, pageKey: key}, nil
}

// Mount checks every method of a service and adds its handler to mux. handler is the generated
// constructor with the implementation bound, for example
//
//	func(o ...connect.HandlerOption) (string, http.Handler) {
//		return rpmgrv1connect.NewRouteServiceHandler(impl, o...)
//	}
func (s *Server) Mount(mux *http.ServeMux, sd protoreflect.ServiceDescriptor,
	handler func(...connect.HandlerOption) (string, http.Handler)) error {
	if err := Check(sd); err != nil {
		return err
	}
	path, h := handler(connect.WithInterceptors(s.interceptor()))
	if path != "/"+string(sd.FullName())+"/" {
		return fmt.Errorf("api: the handler of %s serves %s", sd.FullName(), path)
	}
	mux.Handle(path, h)
	return nil
}

// Check reports the first method of a service whose authorization cannot be enforced: no
// (rpmgr.v1.authz) option, an unknown permission, an org permission without a resource field, a
// resource field that is not a string field of the request, step-up on a public method, or a
// client stream.
func Check(sd protoreflect.ServiceDescriptor) error {
	methods := sd.Methods()
	for i := range methods.Len() {
		md := methods.Get(i)
		if err := checkMethod(md); err != nil {
			return fmt.Errorf("api: %s: %w", md.FullName(), err)
		}
	}
	return nil
}

func checkMethod(md protoreflect.MethodDescriptor) error {
	a, ok := authzOf(md)
	switch {
	case !ok:
		return errors.New("no (rpmgr.v1.authz) option")
	case !authz.KnownPermission(a.GetPermission()):
		return fmt.Errorf("unknown permission %q", a.GetPermission())
	case md.IsStreamingClient():
		return errors.New("client streams are not served")
	case a.GetStepUp() && a.GetPermission() == authz.PermPublic:
		return errors.New("step-up on a public method")
	case authz.OrgPermission(a.GetPermission()) && a.GetResourceField() == "":
		return errors.New("an org permission needs a resource field")
	}
	if f := a.GetResourceField(); f != "" {
		if _, err := fieldPath(md.Input(), f); err != nil {
			return err
		}
	}
	return nil
}

// authzOf returns a method's (rpmgr.v1.authz) option.
func authzOf(md protoreflect.MethodDescriptor) (*rpmgrv1.Authz, bool) {
	opts := md.Options()
	if opts == nil || !proto.HasExtension(opts, rpmgrv1.E_Authz) {
		return nil, false
	}
	a, ok := proto.GetExtension(opts, rpmgrv1.E_Authz).(*rpmgrv1.Authz)
	return a, ok && a != nil
}

// fieldPath resolves a dotted path of field names, singular messages up to a string field.
func fieldPath(m protoreflect.MessageDescriptor, path string) ([]protoreflect.FieldDescriptor, error) {
	var fds []protoreflect.FieldDescriptor
	names := strings.Split(path, ".")
	for i, name := range names {
		fd := m.Fields().ByName(protoreflect.Name(name))
		switch {
		case fd == nil:
			return nil, fmt.Errorf("resource field %q: %s has no field %q", path, m.FullName(), name)
		case fd.IsList() || fd.IsMap():
			return nil, fmt.Errorf("resource field %q: %q repeats", path, name)
		case i < len(names)-1 && fd.Kind() != protoreflect.MessageKind:
			return nil, fmt.Errorf("resource field %q: %q is not a message", path, name)
		case i == len(names)-1 && fd.Kind() != protoreflect.StringKind:
			return nil, fmt.Errorf("resource field %q is not a string", path)
		}
		fds = append(fds, fd)
		m = fd.Message()
	}
	return fds, nil
}

// fieldValue reads a resource field from a request; unset messages on the way read as "".
func fieldValue(msg protoreflect.Message, fds []protoreflect.FieldDescriptor) string {
	for _, fd := range fds[:len(fds)-1] {
		if !msg.Has(fd) {
			return ""
		}
		msg = msg.Get(fd).Message()
	}
	return msg.Get(fds[len(fds)-1]).String()
}

type callerKey struct{}

// CallerFrom returns the caller of a request, nil for an anonymous one.
func CallerFrom(ctx context.Context) *Caller {
	c, _ := ctx.Value(callerKey{}).(*Caller)
	return c
}
