// SPDX-License-Identifier: Apache-2.0

package manifest_test

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/manifest"
)

var (
	quoted  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	block   = regexp.MustCompile(`^(message|enum|oneof|service|extend)\s+(\w+)\s*\{`)
	field   = regexp.MustCompile(`^(?:repeated\s+|optional\s+)?(map<[^>]*>|[A-Za-z_][\w.]*)\s+([A-Za-z_]\w*)\s*=\s*\d+`)
	pkgLine = regexp.MustCompile(`^package\s+([\w.]+)\s*;`)
)

// fieldComments reads the .proto files of rpmgr.v1 and returns the leading comment of each field
// of a message, by its full name, such as "rpmgr.v1.Route.update_user_id".
func fieldComments(t *testing.T) map[protoreflect.FullName]string {
	t.Helper()
	files, err := filepath.Glob("../../proto/rpmgr/v1/*.proto")
	if err != nil || len(files) == 0 {
		t.Fatalf("the protos: %v %v", files, err)
	}
	out := map[protoreflect.FullName]string{}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		type frame struct{ kind, name string }
		var (
			pkg     string
			stack   []frame
			comment []string
		)
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if c, ok := strings.CutPrefix(line, "//"); ok {
				comment = append(comment, strings.TrimSpace(c))
				continue
			}
			code := quoted.ReplaceAllString(line, `""`)
			if i := strings.Index(code, "//"); i >= 0 {
				code = code[:i]
			}
			if m := pkgLine.FindStringSubmatch(code); m != nil {
				pkg = m[1]
			}
			if n := len(stack); n > 0 && (stack[n-1].kind == "message" || stack[n-1].kind == "oneof") {
				if m := field.FindStringSubmatch(code); m != nil && m[1] != "option" && m[1] != "reserved" {
					var names []string
					for _, fr := range stack {
						if fr.kind == "message" {
							names = append(names, fr.name)
						}
					}
					out[protoreflect.FullName(pkg+"."+strings.Join(names, ".")+"."+m[2])] = strings.Join(comment, " ")
				}
			}
			opens := strings.Count(code, "{")
			if m := block.FindStringSubmatch(code); m != nil {
				stack = append(stack, frame{m[1], m[2]})
				opens--
			}
			for range opens {
				stack = append(stack, frame{kind: "other"})
			}
			for range strings.Count(code, "}") {
				if len(stack) == 0 {
					t.Fatalf("%s: a } without a {: %s", file, line)
				}
				stack = stack[:len(stack)-1]
			}
			comment = nil
		}
		if err := s.Err(); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		if len(stack) != 0 {
			t.Fatalf("%s: %d blocks are not closed", file, len(stack))
		}
	}
	for name := range out {
		if d, err := protoregistry.GlobalFiles.FindDescriptorByName(name); err != nil {
			t.Errorf("the protos have %s, which is no field: %v", name, err)
		} else if _, ok := d.(protoreflect.FieldDescriptor); !ok {
			t.Errorf("the protos have %s, which is no field", name)
		}
	}
	return out
}

// anyName is a Resolver that names every resource after its ID.
type anyName struct{}

func (anyName) Name(_ context.Context, _, id string) (string, error) { return "name-of-" + id, nil }
func (anyName) ID(_ context.Context, _, name string) (string, error) {
	return strings.TrimPrefix(name, "name-of-"), nil
}

// fill sets every field of m and of the messages in it, choosing member variant of each oneof.
func fill(m protoreflect.Message, variant, depth int) {
	if strings.HasPrefix(string(m.Descriptor().FullName()), "google.protobuf.") || depth > 8 {
		return // set, but left at its zero value, which the JSON mapping writes
	}
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() && od.Fields().Get(variant%od.Fields().Len()) != fd {
			continue
		}
		switch {
		case fd.IsList():
			l := m.Mutable(fd).List()
			if fd.Message() != nil {
				v := l.NewElement()
				fill(v.Message(), variant, depth+1)
				l.Append(v)
			} else {
				l.Append(scalar(fd))
			}
		case fd.IsMap():
			mp := m.Mutable(fd).Map()
			v := mp.NewValue()
			if fd.MapValue().Message() != nil {
				fill(v.Message(), variant, depth+1)
			} else {
				v = scalar(fd.MapValue())
			}
			mp.Set(scalar(fd.MapKey()).MapKey(), v)
		case fd.Message() != nil:
			fill(m.Mutable(fd).Message(), variant, depth+1)
		default:
			m.Set(fd, scalar(fd))
		}
	}
}

// scalar is a value of fd's kind that is not its zero value.
func scalar(fd protoreflect.FieldDescriptor) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		values := fd.Enum().Values()
		return protoreflect.ValueOfEnum(values.Get(values.Len() - 1).Number())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(1)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(1)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(1)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(1)
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(1)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(1)
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte("x"))
	default:
		return protoreflect.ValueOfString("x")
	}
}

// oneofSize is the most members any oneof in md, or in the messages it holds, has.
func oneofSize(md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) int {
	if seen[md.FullName()] {
		return 0
	}
	seen[md.FullName()] = true
	most := 1
	for i := range md.Oneofs().Len() {
		most = max(most, md.Oneofs().Get(i).Fields().Len())
	}
	for i := range md.Fields().Len() {
		if sub := md.Fields().Get(i).Message(); sub != nil {
			most = max(most, oneofSize(sub, seen))
		}
	}
	return most
}

// TestOutputOnly (docs/07-api.md, "Declarative manifests"): a manifest's spec holds no field the
// protos mark "output only", at any depth, but for a route's targets, which its manifest carries;
// it holds every other field the resource sets, or names it in metadata or by a name. The protos
// are read, so a new output-only field fails this test until the manifest leaves it out.
func TestOutputOnly(t *testing.T) {
	outputOnly := map[protoreflect.FullName]bool{}
	for name, comment := range fieldComments(t) {
		if strings.Contains(strings.ToLower(comment), "output only") {
			outputOnly[name] = true
		}
	}
	for _, name := range []protoreflect.FullName{"rpmgr.v1.Route.update_user_id", "rpmgr.v1.RouteTarget.etag", "rpmgr.v1.Connector.built_in"} {
		if !outputOnly[name] {
			t.Fatalf("the protos do not mark %s output only: the comments were not read", name)
		}
	}
	kept := map[protoreflect.FullName]bool{"rpmgr.v1.Route.targets": true}
	// Where a field the spec does not hold under its own JSON name goes instead.
	moved := map[string]string{"name": "metadata", "fqdn": "metadata", "labels": "metadata", "gatewayGroupId": "gatewayGroup",
		"policyIds": "policies", "connectorId": "connector", "caBundleId": "caBundle"}

	var check func(path string, m protoreflect.Message, spec map[string]any)
	check = func(path string, m protoreflect.Message, spec map[string]any) {
		m.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
			key := fd.JSONName()
			v, ok := spec[key]
			switch {
			case outputOnly[fd.FullName()] && !kept[fd.FullName()]:
				if ok {
					t.Errorf("%s: the spec holds %s, which is output only", path, key)
				}
				return true
			case proto.GetExtension(fd.Options(), rpmgrv1.E_Sensitive) == true:
				return true
			case !ok:
				if _, named := spec[moved[key]]; !named && moved[key] != "metadata" {
					t.Errorf("%s: the spec lacks %s", path, key)
				}
				return true
			}
			if fd.Message() == nil || fd.IsMap() || strings.HasPrefix(string(fd.Message().FullName()), "google.protobuf.") {
				return true
			}
			if !fd.IsList() {
				sub, _ := v.(map[string]any)
				check(path+"."+key, m.Get(fd).Message(), sub)
				return true
			}
			items, _ := v.([]any)
			l := m.Get(fd).List()
			if len(items) != l.Len() {
				t.Errorf("%s: the spec holds %d of %d %s", path, len(items), l.Len(), key)
				return true
			}
			for i, item := range items {
				sub, _ := item.(map[string]any)
				check(path+"."+key, l.Get(i).Message(), sub)
			}
			return true
		})
	}

	for _, kind := range []proto.Message{&rpmgrv1.Route{}, &rpmgrv1.AccessPolicy{}, &rpmgrv1.GatewayGroup{}, &rpmgrv1.Gateway{},
		&rpmgrv1.PortPool{}, &rpmgrv1.Domain{}, &rpmgrv1.Connector{}, &rpmgrv1.CABundle{}} {
		md := kind.ProtoReflect().Descriptor()
		marked := 0
		for i := range md.Fields().Len() {
			if fd := md.Fields().Get(i); outputOnly[fd.FullName()] {
				marked++
			}
		}
		if marked == 0 {
			t.Errorf("%s has no output-only field: its comments were not read", md.Name())
		}
		for variant := range oneofSize(md, map[protoreflect.FullName]bool{}) {
			m := kind.ProtoReflect().New()
			fill(m, variant, 0)
			d, err := manifest.Of(context.Background(), anyName{}, m.Interface())
			if err != nil {
				t.Fatalf("%s: %v", md.Name(), err)
			}
			if d.Metadata.Name == "" {
				t.Errorf("%s: no name", md.Name())
			}
			check(string(md.Name()), m, d.Spec)
		}
	}
}
