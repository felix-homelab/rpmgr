// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// field is a flag that sets a field of a resource, by its proto name: a string, a repeated string
// (the flag repeats), a number, a bool, an enum by the end of its value's name ("tcp" for
// PORT_PROTOCOL_TCP), or with ref the ID of a resource of that kind given by name or ID.
type field struct {
	flag, name, usage, ref string
	update                 bool // whether update may change it; create always sets it
	file                   bool // the flag names a file whose content is the field's value
}

// resourceCommands are `create <kind>` and `update <kind>` of a kind whose resource the fields
// describe, through its Create<Resource> and Update<Resource> methods. after, if given, prints
// more about a resource written.
func resourceCommands(kind string, fields []field, after ...func(env *cli.Env, res protoreflect.Message) error) (create, update *cli.Command) {
	k, err := apicli.KindOf(kind)
	if err != nil {
		panic(err)
	}
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName("rpmgr.v1." + k.Resource))
	if err != nil {
		panic(err)
	}
	values := map[string]*string{}
	lists := map[string]*listFlag{}
	var force bool
	var wait time.Duration
	var output string
	var cfs, ufs *flag.FlagSet
	register := func(fs *flag.FlagSet, forUpdate bool) {
		for _, f := range fields {
			if forUpdate && !f.update {
				continue
			}
			fd := mt.Descriptor().Fields().ByName(protoreflect.Name(f.name))
			switch {
			case fd.IsList():
				lists[f.flag] = &listFlag{}
				fs.Var(lists[f.flag], f.flag, f.usage+"; repeat for more")
			case fd.Kind() == protoreflect.BoolKind:
				values[f.flag] = new(string)
				fs.Var(boolFlag{values[f.flag]}, f.flag, f.usage)
			default:
				values[f.flag] = new(string)
				fs.StringVar(values[f.flag], f.flag, "", f.usage)
			}
		}
		fs.DurationVar(&wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
		outputFlag(fs, &output)
	}
	// build sets the fields the flags given name on m, and returns their paths.
	build := func(ctx context.Context, s *apiSession, m protoreflect.Message, set map[string]bool, forUpdate bool) ([]string, error) {
		var paths []string
		for _, f := range fields {
			if !set[f.flag] || forUpdate && !f.update {
				continue
			}
			fd := m.Descriptor().Fields().ByName(protoreflect.Name(f.name))
			if fd.IsList() {
				l := m.Mutable(fd).List()
				l.Truncate(0)
				for _, v := range *lists[f.flag] {
					l.Append(protoreflect.ValueOfString(v))
				}
			} else {
				raw := *values[f.flag]
				if f.file {
					b, err := os.ReadFile(raw) //nolint:gosec // G304: the user's file
					if err != nil {
						return nil, err
					}
					raw = string(b)
				}
				v, err := s.value(ctx, fd, f, raw)
				if err != nil {
					return nil, err
				}
				m.Set(fd, v)
			}
			paths = append(paths, f.name)
		}
		return paths, nil
	}
	resourceField := strings.TrimSuffix(k.IDField, "_id")
	create = &cli.Command{
		Name: kind, Summary: "create a " + strings.ReplaceAll(kind, "-", " "),
		Flags: func(fs *flag.FlagSet) { cfs = fs; register(fs, false) },
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			res := mt.New()
			if _, err := build(ctx, s, res, setFlags(cfs), false); err != nil {
				return err
			}
			md, err := k.Method("Create" + k.Resource)
			if err != nil {
				return err
			}
			req := md.Input()
			rm := msgOf(req)
			rm.Set(req.Fields().ByName("org_id"), protoreflect.ValueOfString(s.creds.Org))
			rm.Set(req.Fields().ByName(protoreflect.Name(resourceField)), protoreflect.ValueOfMessage(res))
			return s.send(ctx, env, k, md, rm.Interface(), wait, output, "Created", after...)
		},
	}
	update = &cli.Command{
		Name: kind, Summary: "change the fields of a " + strings.ReplaceAll(kind, "-", " ") + " that the flags name", Args: "<id>",
		Flags: func(fs *flag.FlagSet) {
			ufs = fs
			register(fs, true)
			fs.BoolVar(&force, "force", false, "update without checking that it is unchanged since this command read it")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("expected the %s's ID", kind)
			}
			set := setFlags(ufs)
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			cur, err := s.get(ctx, k, args[0])
			if err != nil {
				return err
			}
			res := mt.New()
			b, err := proto.Marshal(cur.Interface())
			if err == nil {
				err = proto.Unmarshal(b, res.Interface())
			}
			if err != nil {
				return err
			}
			paths, err := build(ctx, s, res, set, true)
			if err != nil {
				return err
			}
			if len(paths) == 0 {
				return cli.Usagef("name a field to change")
			}
			md, err := k.Method("Update" + k.Resource)
			if err != nil {
				return err
			}
			rm := msgOf(md.Input())
			rm.Set(md.Input().Fields().ByName(protoreflect.Name(resourceField)), protoreflect.ValueOfMessage(res))
			rm.Set(md.Input().Fields().ByName("update_mask"), protoreflect.ValueOfMessage((&fieldmaskpb.FieldMask{Paths: paths}).ProtoReflect()))
			if !force {
				rm.Set(md.Input().Fields().ByName("etag"), res.Get(res.Descriptor().Fields().ByName("etag")))
			}
			return s.send(ctx, env, k, md, rm.Interface(), wait, output, "Updated", after...)
		},
	}
	return create, update
}

// boolFlag is a bool field's flag: given alone it is true, and --flag=false sets false.
type boolFlag struct{ v *string }

func (b boolFlag) String() string {
	if b.v == nil {
		return ""
	}
	return *b.v
}
func (b boolFlag) Set(v string) error { *b.v = v; return nil }
func (b boolFlag) IsBoolFlag() bool   { return true }

// msgOf is a new generated message of a descriptor.
func msgOf(md protoreflect.MessageDescriptor) protoreflect.Message {
	mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName())
	if err != nil {
		panic(err)
	}
	return mt.New()
}

// value converts a flag's value to the field's type.
func (s *apiSession) value(ctx context.Context, fd protoreflect.FieldDescriptor, f field, v string) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		if f.ref != "" {
			var id string
			err := s.resolve(ctx, f.ref, v, &id)
			return protoreflect.ValueOfString(id), err
		}
		return protoreflect.ValueOfString(v), nil
	case protoreflect.BoolKind:
		if v != "true" && v != "false" {
			return protoreflect.Value{}, cli.Usagef("--%s %q: true or false", f.flag, v)
		}
		return protoreflect.ValueOfBool(v == "true"), nil
	case protoreflect.Uint32Kind, protoreflect.Int32Kind:
		var n int64
		if _, err := fmt.Sscan(v, &n); err != nil || n < 0 || n > 1<<31-1 {
			return protoreflect.Value{}, cli.Usagef("--%s %q is not a number", f.flag, v)
		}
		if fd.Kind() == protoreflect.Uint32Kind {
			return protoreflect.ValueOfUint32(uint32(n)), nil //nolint:gosec // G115: checked above
		}
		return protoreflect.ValueOfInt32(int32(n)), nil //nolint:gosec // G115: checked above
	case protoreflect.EnumKind:
		values := fd.Enum().Values()
		var names []string
		for i := range values.Len() {
			name := string(values.Get(i).Name())
			short := strings.ToLower(name[strings.LastIndex(name, "_")+1:])
			if strings.HasSuffix(name, "_UNSPECIFIED") {
				continue
			}
			if short == strings.ToLower(v) {
				return protoreflect.ValueOfEnum(values.Get(i).Number()), nil
			}
			names = append(names, short)
		}
		return protoreflect.Value{}, cli.Usagef("--%s %q: one of %s", f.flag, v, strings.Join(names, ", "))
	}
	return protoreflect.Value{}, fmt.Errorf("--%s: a field of kind %s", f.flag, fd.Kind())
}

// send checks a write with the API's rules and sends it, taking a step-up if the API wants one,
// then prints the resource written and how far the agents are.
func (s *apiSession) send(ctx context.Context, env *cli.Env, k apicli.Kind, md protoreflect.MethodDescriptor, req proto.Message,
	wait time.Duration, output, verb string, after ...func(env *cli.Env, res protoreflect.Message) error) error {
	if err := protovalidate.Validate(req); err != nil {
		return cli.Usagef("%v", err)
	}
	var resp protoreflect.Message
	if err := s.withStepUp(ctx, func() error {
		r, err := apicli.CallMessage(ctx, s.hc, s.creds.Controller, md, req, waitHeader(wait))
		resp = r
		return err
	}); err != nil {
		return apiError(err)
	}
	fd, err := k.Field(resp)
	if err != nil {
		return err
	}
	res := resp.Get(fd).Message()
	id := res.Get(res.Descriptor().Fields().ByName("id")).String()
	if _, err := fmt.Fprintf(env.Stdout, "%s %s %s%s.\n", verb, strings.ReplaceAll(k.Name, "-", " "), id, applied(resp)); err != nil {
		return err
	}
	if err := s.print(ctx, env.Stdout, k, output, []protoreflect.Message{res}, []string{id}, false); err != nil {
		return err
	}
	for _, f := range after {
		if err := f(env, res); err != nil {
			return err
		}
	}
	return nil
}
