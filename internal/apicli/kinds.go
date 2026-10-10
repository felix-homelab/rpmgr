// SPDX-License-Identifier: Apache-2.0

package apicli

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"
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
	Manifest string   // its manifest kind; empty for none
	Columns  []string // the fields a table shows after its ID and name, as JSON names
	Delete   bool     // whether Delete<Resource> exists
}

// Kinds are the kinds of the public API's resources, by name.
var Kinds = []Kind{
	{Name: "route", Service: "rpmgr.v1.RouteService", Resource: "Route", Plural: "Routes", IDField: "route_id", Manifest: "Route",
		Columns: []string{"gatewayGroupId", "enabled", "status.state"}, Delete: true},
	{Name: "connector", Service: "rpmgr.v1.ConnectorService", Resource: "Connector", Plural: "Connectors", IDField: "connector_id",
		Manifest: "Connector", Columns: []string{"enabled", "session.connected", "session.version"}},
	{Name: "gateway", Service: "rpmgr.v1.GatewayService", Resource: "Gateway", Plural: "Gateways", IDField: "gateway_id",
		Manifest: "Gateway", Columns: []string{"gatewayGroupId", "enabled", "status.connected"}},
	{Name: "gateway-group", Service: "rpmgr.v1.GatewayService", Resource: "GatewayGroup", Plural: "GatewayGroups",
		IDField: "gateway_group_id", Manifest: "GatewayGroup", Columns: []string{"region"}, Delete: true},
	{Name: "port-pool", Service: "rpmgr.v1.GatewayService", Resource: "PortPool", Plural: "PortPools", IDField: "port_pool_id",
		Manifest: "PortPool", Columns: []string{"gatewayGroupId", "protocol", "portFrom", "portTo", "allocatedPorts"}, Delete: true},
	{Name: "domain", Service: "rpmgr.v1.DomainService", Resource: "Domain", Plural: "Domains", IDField: "domain_id", Manifest: "Domain",
		Columns: []string{"wildcard", "method", "status"}, Delete: true},
	{Name: "certificate", Service: "rpmgr.v1.CertificateService", Resource: "Certificate", Plural: "Certificates",
		IDField: "certificate_id", Columns: []string{"source", "status", "sans", "notAfter"}, Delete: true},
	{Name: "ca-bundle", Service: "rpmgr.v1.CertificateService", Resource: "CABundle", Plural: "CABundles", IDField: "ca_bundle_id",
		Manifest: "CABundle", Delete: true},
	{Name: "access-policy", Service: "rpmgr.v1.PolicyService", Resource: "AccessPolicy", Plural: "AccessPolicies",
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
