// SPDX-License-Identifier: Apache-2.0

// Package manifest writes the org's resources as YAML manifests and reads them back
// (docs/07-api.md, "Declarative manifests"): `kind`, `metadata` with the resource's name and
// labels, and a `spec` in the protobuf JSON mapping of the public resource, without the fields the
// server sets and with other resources named by their names rather than their IDs. Phase 1 writes
// them for the CLI and the UI; applying them comes with ManifestService in Phase 2.
package manifest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// Resolver turns the IDs of an org's resources into their names, and back.
type Resolver interface {
	// Name returns the name of the resource of kind with id.
	Name(ctx context.Context, kind, id string) (string, error)
	// ID returns the ID of the resource of kind with name.
	ID(ctx context.Context, kind, name string) (string, error)
}

// ErrKind is returned for a message or a kind that has no manifest.
var ErrKind = errors.New("manifest: not a kind of manifest")

// Doc is one manifest.
type Doc struct {
	Kind     string         `yaml:"kind"`
	Metadata Metadata       `yaml:"metadata"`
	Spec     map[string]any `yaml:"spec,omitempty"`
}

// Metadata names a resource.
type Metadata struct {
	Name   string            `yaml:"name"`
	Labels map[string]string `yaml:"labels,omitempty"`
}

// ref is a field that holds the ID of another resource, which a manifest names instead.
type ref struct {
	path []string // the JSON keys to the field; "*" for every item of a list
	key  string   // its key in the manifest
	kind string   // the kind it names
}

// kindOf is how a resource becomes a manifest.
type kindOf struct {
	name      string
	new       func() proto.Message
	nameField string     // the field that names it; empty: its ID does
	output    [][]string // the fields the server sets, as JSON paths
	refs      []ref
}

var kinds = []kindOf{
	{name: "Route", new: func() proto.Message { return &rpmgrv1.Route{} }, nameField: "name",
		output: [][]string{{"etag"}, {"status"}, {"createTime"}, {"updateTime"}, {"targets", "*", "id"}, {"targets", "*", "etag"}},
		refs: []ref{{[]string{"gatewayGroupId"}, "gatewayGroup", "GatewayGroup"}, {[]string{"policyIds"}, "policies", "AccessPolicy"},
			{[]string{"targets", "*", "connectorId"}, "connector", "Connector"}, {[]string{"targets", "*", "tls", "caBundleId"}, "caBundle", "CABundle"}}},
	{name: "AccessPolicy", new: func() proto.Message { return &rpmgrv1.AccessPolicy{} }, nameField: "name",
		output: [][]string{{"etag"}, {"routeIds"}}},
	{name: "GatewayGroup", new: func() proto.Message { return &rpmgrv1.GatewayGroup{} }, nameField: "name", output: [][]string{{"etag"}}},
	{name: "Gateway", new: func() proto.Message { return &rpmgrv1.Gateway{} }, nameField: "name",
		output: [][]string{{"etag"}, {"slot"}, {"status"}, {"decommissionTime"}, {"createTime"}},
		refs:   []ref{{[]string{"gatewayGroupId"}, "gatewayGroup", "GatewayGroup"}}},
	{name: "PortPool", new: func() proto.Message { return &rpmgrv1.PortPool{} }, output: [][]string{{"etag"}, {"allocatedPorts"}},
		refs: []ref{{[]string{"gatewayGroupId"}, "gatewayGroup", "GatewayGroup"}}},
	{name: "Domain", new: func() proto.Message { return &rpmgrv1.Domain{} }, nameField: "fqdn",
		output: [][]string{{"etag"}, {"status"}, {"challenge"}, {"verifyTime"}, {"lastCheckTime"}, {"createTime"}, {"lastError"}}},
	{name: "Connector", new: func() proto.Message { return &rpmgrv1.Connector{} }, nameField: "name",
		output: [][]string{{"etag"}, {"ephemeral"}, {"session"}, {"createTime"}, {"decommissionTime"}}},
	{name: "CABundle", new: func() proto.Message { return &rpmgrv1.CABundle{} }, nameField: "name",
		output: [][]string{{"etag"}, {"certificates"}, {"targetIds"}, {"createTime"}}},
}

func lookup(match func(kindOf) bool) (kindOf, error) {
	for _, k := range kinds {
		if match(k) {
			return k, nil
		}
	}
	return kindOf{}, ErrKind
}

// Of returns the manifest of a resource: one of Route, AccessPolicy, GatewayGroup, Gateway,
// PortPool, Domain, Connector and CABundle. Fields marked sensitive are never in it.
func Of(ctx context.Context, r Resolver, m proto.Message) (*Doc, error) {
	k, err := lookup(func(k kindOf) bool { return k.new().ProtoReflect().Descriptor() == m.ProtoReflect().Descriptor() })
	if err != nil {
		return nil, err
	}
	c := proto.Clone(m)
	dropSensitive(c.ProtoReflect())
	b, err := protojson.Marshal(c)
	if err != nil {
		return nil, err
	}
	var spec map[string]any
	if err := json.Unmarshal(b, &spec); err != nil {
		return nil, err
	}
	d := &Doc{Kind: k.name, Spec: spec}
	id, _ := spec["id"].(string)
	delete(spec, "id")
	d.Metadata.Name = id
	if k.nameField != "" {
		d.Metadata.Name, _ = spec[k.nameField].(string)
		delete(spec, k.nameField)
	}
	if labels, ok := spec["labels"].(map[string]any); ok {
		d.Metadata.Labels = map[string]string{}
		for l, v := range labels {
			d.Metadata.Labels[l], _ = v.(string)
		}
		delete(spec, "labels")
	}
	for _, p := range k.output {
		if err := edit(spec, p, func(parent map[string]any, key string) error { delete(parent, key); return nil }); err != nil {
			return nil, err
		}
	}
	for _, f := range k.refs {
		if err := edit(spec, f.path, func(parent map[string]any, key string) error {
			v, err := convert(parent[key], func(id string) (string, error) { return r.Name(ctx, f.kind, id) })
			if err != nil {
				return fmt.Errorf("manifest: %s %s: %w", k.name, d.Metadata.Name, err)
			}
			delete(parent, key)
			parent[f.key] = v
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// Parse returns the resource of a manifest, with the names it holds turned into IDs; the fields
// the server sets are not set. A key the resource does not have is an error.
func Parse(ctx context.Context, r Resolver, d *Doc) (proto.Message, error) {
	k, err := lookup(func(k kindOf) bool { return k.name == d.Kind })
	if err != nil {
		return nil, fmt.Errorf("%w: %q", err, d.Kind)
	}
	spec := map[string]any{}
	for key, v := range d.Spec {
		spec[key] = v
	}
	for _, f := range k.refs {
		path := append(append([]string{}, f.path[:len(f.path)-1]...), f.key)
		if err := edit(spec, path, func(parent map[string]any, key string) error {
			v, err := convert(parent[key], func(name string) (string, error) { return r.ID(ctx, f.kind, name) })
			if err != nil {
				return fmt.Errorf("manifest: %s %s: %w", k.name, d.Metadata.Name, err)
			}
			delete(parent, key)
			parent[f.path[len(f.path)-1]] = v
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if k.nameField != "" {
		spec[k.nameField] = d.Metadata.Name
	}
	if len(d.Metadata.Labels) > 0 {
		spec["labels"] = d.Metadata.Labels
	}
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	m := k.new()
	if err := protojson.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("manifest: %s %s: %w", k.name, d.Metadata.Name, err)
	}
	return m, nil
}

// Write writes manifests as one YAML stream, separated by "---"; no manifests are an empty stream.
func Write(w io.Writer, docs []*Doc) error {
	if len(docs) == 0 {
		return nil // the encoder refuses to close a stream it has not started
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	for _, d := range docs {
		if err := enc.Encode(d); err != nil {
			return err
		}
	}
	return enc.Close()
}

// Read reads a YAML stream of manifests; a key a manifest does not have is an error.
func Read(r io.Reader) ([]*Doc, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var out []*Doc
	for {
		d := &Doc{}
		err := dec.Decode(d)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("manifest: %w", err)
		}
		out = append(out, d)
	}
}

// edit calls f for the field at path in v, through every item of a list at "*"; a path that is not
// there is skipped.
func edit(v any, path []string, f func(parent map[string]any, key string) error) error {
	switch x := v.(type) {
	case map[string]any:
		if len(path) == 1 {
			if _, ok := x[path[0]]; !ok {
				return nil
			}
			return f(x, path[0])
		}
		return edit(x[path[0]], path[1:], f)
	case []any:
		if path[0] != "*" {
			return nil
		}
		for _, item := range x {
			if err := edit(item, path[1:], f); err != nil {
				return err
			}
		}
	}
	return nil
}

// convert maps a string, or each string of a list, with f.
func convert(v any, f func(string) (string, error)) (any, error) {
	switch x := v.(type) {
	case string:
		return f(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%v is not a name", item)
			}
			var err error
			if out[i], err = f(s); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("%v is not a name", v)
}

// dropSensitive clears every field marked sensitive, also in nested messages.
func dropSensitive(m protoreflect.Message) {
	var set []protoreflect.FieldDescriptor
	m.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool { set = append(set, fd); return true })
	for _, fd := range set {
		switch {
		case proto.GetExtension(fd.Options(), rpmgrv1.E_Sensitive) == true:
			m.Clear(fd)
		case fd.IsList() && fd.Kind() == protoreflect.MessageKind:
			l := m.Mutable(fd).List()
			for i := range l.Len() {
				dropSensitive(l.Get(i).Message())
			}
		case fd.IsMap() && fd.MapValue().Kind() == protoreflect.MessageKind:
			m.Mutable(fd).Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool { dropSensitive(mv.Message()); return true })
		case !fd.IsList() && !fd.IsMap() && fd.Kind() == protoreflect.MessageKind:
			dropSensitive(m.Mutable(fd).Message())
		}
	}
}
