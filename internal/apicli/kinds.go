// SPDX-License-Identifier: Apache-2.0

package apicli

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	_ "github.com/felix-homelab/rpmgr/gen/rpmgr/v1" // registers the public API's descriptors
)

// Kind is a kind of resource the verb-first commands handle: `rpmgr <verb> <kind>`
// (docs/16-cli.md, D51). Its methods follow the API's naming (docs/07-api.md, "Resource design").
type Kind struct {
	Name     string   // the command line's name, e.g. "gateway-group"
	Service  string   // the service's full name
	Resource string   // the message, and the stem of its methods: Get<Resource>, Delete<Resource>
	Plural   string   // the stem of List<Plural>
	IDField  string   // the request field that names one, e.g. "gateway_group_id"
	Prefix   string   // the prefix of its IDs, e.g. "gwg_"
	Manifest string   // its manifest kind; empty for none
	Columns  []string // the fields a table shows after its ID and name, as JSON names
	Delete   bool     // whether Delete<Resource> exists
	NoGet    bool     // whether Get<Resource> is missing: the kind is only listed
}

// Kinds are the kinds of the public API's resources, by name.
var Kinds = []Kind{
	{Name: "route", Prefix: "rt_", Service: "rpmgr.v1.RouteService", Resource: "Route", Plural: "Routes", IDField: "route_id", Manifest: "Route",
		Columns: []string{"gatewayGroupId", "enabled", "status.state"}, Delete: true},
	{Name: "connector", Prefix: "con_", Service: "rpmgr.v1.ConnectorService", Resource: "Connector", Plural: "Connectors", IDField: "connector_id",
		Manifest: "Connector", Columns: []string{"enabled", "session.connected", "session.version"}},
	{Name: "gateway", Prefix: "gw_", Service: "rpmgr.v1.GatewayService", Resource: "Gateway", Plural: "Gateways", IDField: "gateway_id",
		Manifest: "Gateway", Columns: []string{"gatewayGroupId", "enabled", "status.connected"}},
	{Name: "gateway-group", Prefix: "gwg_", Service: "rpmgr.v1.GatewayService", Resource: "GatewayGroup", Plural: "GatewayGroups",
		IDField: "gateway_group_id", Manifest: "GatewayGroup", Columns: []string{"region"}, Delete: true},
	{Name: "port-pool", Prefix: "pp_", Service: "rpmgr.v1.GatewayService", Resource: "PortPool", Plural: "PortPools", IDField: "port_pool_id",
		Manifest: "PortPool", Columns: []string{"gatewayGroupId", "protocol", "portFrom", "portTo", "allocatedPorts"}, Delete: true},
	{Name: "port-quota", Prefix: "pq_", Service: "rpmgr.v1.GatewayService", Resource: "PortQuota", Plural: "PortQuotas",
		IDField: "port_quota_id", Columns: []string{"gatewayGroupId", "protocol", "maxPorts", "allocatedPorts"}, Delete: true, NoGet: true},
	{Name: "domain", Prefix: "dom_", Service: "rpmgr.v1.DomainService", Resource: "Domain", Plural: "Domains", IDField: "domain_id", Manifest: "Domain",
		Columns: []string{"wildcard", "method", "status"}, Delete: true},
	{Name: "certificate", Prefix: "crt_", Service: "rpmgr.v1.CertificateService", Resource: "Certificate", Plural: "Certificates",
		IDField: "certificate_id", Columns: []string{"source", "status", "sans", "notAfter"}, Delete: true},
	{Name: "ca-bundle", Prefix: "cab_", Service: "rpmgr.v1.CertificateService", Resource: "CABundle", Plural: "CABundles", IDField: "ca_bundle_id",
		Manifest: "CABundle", Delete: true},
	{Name: "route-target", Prefix: "tg_", Service: "rpmgr.v1.RouteService", Resource: "RouteTarget", IDField: "route_target_id",
		Columns: []string{"connectorId", "upstreamProtocol", "enabled", "weight", "priority"}, Delete: true},
	{Name: "enrollment-token", Prefix: "enr_", Service: "rpmgr.v1.EnrollmentService", Resource: "EnrollmentToken",
		Plural: "EnrollmentTokens", IDField: "enrollment_token_id", Columns: []string{"role", "useCount", "maxUses", "expireTime", "revokeTime"},
		NoGet: true},
	{Name: "access-policy", Prefix: "ap_", Service: "rpmgr.v1.PolicyService", Resource: "AccessPolicy", Plural: "AccessPolicies",
		IDField: "access_policy_id", Manifest: "AccessPolicy", Columns: []string{"description"}, Delete: true},
}

// KindOf returns the kind with name.
func KindOf(name string) (Kind, error) {
	var names []string
	for _, k := range Kinds {
		if k.Name == name {
			return k, nil
		}
		names = append(names, k.Name)
	}
	return Kind{}, fmt.Errorf("unknown kind %q; the kinds are %s", name, strings.Join(names, ", "))
}

// Method returns the descriptor of a method of the kind's service.
func (k Kind) Method(name string) (protoreflect.MethodDescriptor, error) {
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(k.Service))
	if err != nil {
		return nil, err
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%s is not a service", k.Service)
	}
	md := sd.Methods().ByName(protoreflect.Name(name))
	if md == nil {
		return nil, fmt.Errorf("%s has no method %s", k.Service, name)
	}
	return md, nil
}

// Call calls a unary method of the API with a request whose fields fields sets, by their proto
// names, and returns the response. Header values go along with the request.
func Call(ctx context.Context, hc *http.Client, base string, md protoreflect.MethodDescriptor, fields map[string]any,
	header http.Header) (*dynamicpb.Message, error) {
	req := dynamicpb.NewMessage(md.Input())
	for name, v := range fields {
		fd := md.Input().Fields().ByName(protoreflect.Name(name))
		if fd == nil {
			return nil, fmt.Errorf("%s has no field %s", md.Input().FullName(), name)
		}
		req.Set(fd, protoreflect.ValueOf(v))
	}
	return call(ctx, hc, base, md, req, header)
}

// CallMessage calls a unary method of the API with a request built as a generated message.
func CallMessage(ctx context.Context, hc *http.Client, base string, md protoreflect.MethodDescriptor, msg proto.Message,
	header http.Header) (*dynamicpb.Message, error) {
	b, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	req := dynamicpb.NewMessage(md.Input())
	if err := proto.Unmarshal(b, req); err != nil {
		return nil, err
	}
	return call(ctx, hc, base, md, req, header)
}

func call(ctx context.Context, hc *http.Client, base string, md protoreflect.MethodDescriptor, req *dynamicpb.Message,
	header http.Header) (*dynamicpb.Message, error) {
	c := connect.NewClient[dynamicpb.Message, dynamicpb.Message](hc, base+"/"+string(md.Parent().FullName())+"/"+string(md.Name()),
		connect.WithSchema(md), connect.WithResponseInitializer(func(_ connect.Spec, msg any) error {
			if m, ok := msg.(*dynamicpb.Message); ok {
				*m = *dynamicpb.NewMessage(md.Output())
			}
			return nil
		}))
	r := connect.NewRequest(req)
	for k, vs := range header {
		for _, v := range vs {
			r.Header().Add(k, v)
		}
	}
	resp, err := c.CallUnary(ctx, r)
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// Field returns the field of a response that holds the kind's resource, or a list of them.
func (k Kind) Field(m protoreflect.Message) (protoreflect.FieldDescriptor, error) {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.Kind() == protoreflect.MessageKind && string(fd.Message().Name()) == k.Resource {
			return fd, nil
		}
	}
	return nil, fmt.Errorf("%s holds no %s", m.Descriptor().FullName(), k.Resource)
}

// Resolve returns the ID of the org's resource of the kind that ref names: ref itself if it has
// the kind's ID prefix, else the ID of the one whose name it is.
func (k Kind) Resolve(ctx context.Context, hc *http.Client, base, org, ref string) (string, error) {
	if strings.HasPrefix(ref, k.Prefix) {
		return ref, nil
	}
	md, err := k.Method("List" + k.Plural)
	if err != nil {
		return "", err
	}
	for page := ""; ; {
		resp, err := Call(ctx, hc, base, md, map[string]any{"org_id": org, "page_size": int32(500), "page_token": page}, nil)
		if err != nil {
			return "", err
		}
		fd, err := k.Field(resp)
		if err != nil {
			return "", err
		}
		l := resp.Get(fd).List()
		for i := range l.Len() {
			m := l.Get(i).Message()
			if name := m.Descriptor().Fields().ByName("name"); name != nil && m.Get(name).String() == ref {
				return m.Get(m.Descriptor().Fields().ByName("id")).String(), nil
			}
		}
		if page = resp.Get(resp.Descriptor().Fields().ByName("next_page_token")).String(); page == "" {
			return "", fmt.Errorf("no %s named %q", k.Name, ref)
		}
	}
}
