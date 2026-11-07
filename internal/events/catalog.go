// SPDX-License-Identifier: Apache-2.0

package events

import (
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// The types of the events that report a state and not a change of configuration (docs/07-api.md,
// "Webhooks (Phase 2)"). Every other type is the type of an audit action (TypeOf).
const (
	RouteStatus      = "route.status"
	AgentConnect     = "agent.connect"
	AgentDisconnect  = "agent.disconnect"
	ApplyReject      = "apply.reject"
	AlertFire        = "alert.fire"
	AlertResolve     = "alert.resolve"
	WebhookDisable   = "webhook.disable"
	WebhookTest      = "webhook.test"
	DNSConflict      = "dns.conflict"
	DNSZoneHeld      = "dns.zone_held"
	DNSSyncFailing   = "dns.sync_failing"
	DNSDrifted       = "dns.drifted"
	DNSTokenExpiring = "dns.token_expiring" //nolint:gosec // G101: an event type, no credential

	// AuditExport is the action of an export of an audit chain, org or instance.
	AuditExport = "audit.export"
)

// Status says what a status event reports and whose it is.
type Status struct {
	Type    string
	Meaning string
	Scope   string // org, or "org or instance" where the subject can belong to either
}

// StatusEvents are the status events, in the order of the documentation.
var StatusEvents = []Status{
	{RouteStatus, "A route's status changed.", "org"},
	{AgentConnect, "An agent connected.", "org or instance"},
	{AgentDisconnect, "An agent went offline.", "org or instance"},
	{ApplyReject, "An agent rejected a configuration snapshot.", "org or instance"},
	{AlertFire, "An alert fired.", "org or instance"},
	{AlertResolve, "An alert resolved.", "org or instance"},
	{WebhookDisable, "A failing webhook endpoint was disabled.", "org or instance"},
	{WebhookTest, "A test event, sent to one endpoint on request and to no other.", "org or instance"},
	{DNSConflict, "A DNS name is in conflict with another record.", "org"},
	{DNSZoneHeld, "A DNS zone is held.", "org"},
	{DNSSyncFailing, "A DNS zone's provider keeps failing.", "org"},
	{DNSDrifted, "A DNS record drifted from what rpmgr manages.", "org"},
	{DNSTokenExpiring, "A DNS provider token is about to expire or no longer works.", "org"},
}

// recordedAs names the API methods whose handler records the change in its transaction under an
// action of its own, which replaces the method's entry and so gives the event its type. A method
// whose action is not a change (notChanges) is no event.
var recordedAs = map[string]string{
	"rpmgr.v1.TokenService.CreateAPIToken":            "token.create",
	"rpmgr.v1.TokenService.RevokeAPIToken":            "token.revoke",
	"rpmgr.v1.OrgService.ResumeAPIToken":              "token.resume",
	"rpmgr.v1.UserService.UpdateMe":                   "user.update",
	"rpmgr.v1.AuthService.CompletePasswordReset":      "user.password_reset",
	"rpmgr.v1.AuditService.ExportAudit":               AuditExport,
	"rpmgr.v1.AuditService.ExportInstanceAudit":       AuditExport,
	"rpmgr.v1.LogService.StreamLogs":                  "agent.logs_open",
	"rpmgr.v1.ConnectorService.DecommissionConnector": "connector.decommission",
}

// Type is one event type of the catalog.
type Type struct {
	Type     string
	Resource string // the part before the dot
	Verb     string // the part after the dot
	Method   string // the API method it comes from; empty for a status event
	Meaning  string // set for a status event only
	Scope    string // org, instance, or empty where the chain depends on the request
	Status   bool
}

// Catalog lists every event type: each audited method of the registered API services, named as
// FromAudit and TypeOf name its audit entry, and the status events. It is sorted by resource, then
// type.
func Catalog() []Type {
	byType := map[string]Type{}
	protoregistry.GlobalFiles.RangeFilesByPackage("rpmgr.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := 0; i < fd.Services().Len(); i++ {
			svc := fd.Services().Get(i)
			for j := 0; j < svc.Methods().Len(); j++ {
				md := svc.Methods().Get(j)
				opts, _ := md.Options().(*descriptorpb.MethodOptions)
				if opts.GetIdempotencyLevel() == descriptorpb.MethodOptions_NO_SIDE_EFFECTS {
					continue // a read: the API records no entry
				}
				method := string(md.FullName())
				action := method
				if a, ok := recordedAs[method]; ok {
					action = a
				}
				if !FromAudit(action, "success") {
					continue
				}
				typ := TypeOf(action)
				t := Type{Type: typ, Method: method, Scope: scopeOf(opts)}
				t.Resource, t.Verb, _ = strings.Cut(typ, ".")
				if prev, ok := byType[typ]; ok && prev.Scope != t.Scope {
					t.Scope = ""
				}
				byType[typ] = t
			}
		}
		return true
	})
	for _, s := range StatusEvents {
		t := Type{Type: s.Type, Meaning: s.Meaning, Scope: s.Scope, Status: true}
		t.Resource, t.Verb, _ = strings.Cut(s.Type, ".")
		byType[s.Type] = t
	}
	out := make([]Type, 0, len(byType))
	for _, t := range byType {
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b Type) int { return strings.Compare(a.Type, b.Type) })
	return out
}

// scopeOf says whose chain a method's entry goes to, where its permission tells: the Instance
// Admin's methods write the instance chain, an org permission's the org's. A method for any
// signed-in user, or for anyone, has no scope here.
func scopeOf(opts *descriptorpb.MethodOptions) string {
	if opts == nil || !proto.HasExtension(opts, rpmgrv1.E_Authz) {
		return ""
	}
	a, _ := proto.GetExtension(opts, rpmgrv1.E_Authz).(*rpmgrv1.Authz)
	switch p := a.GetPermission(); p {
	case "instance.admin":
		return "instance"
	case "public", "authenticated", "":
		return ""
	default:
		return "org"
	}
}
