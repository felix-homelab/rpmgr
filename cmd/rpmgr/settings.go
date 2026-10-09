// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/apicli"
	"github.com/felix-homelab/rpmgr/internal/cli"
)

// settingsCommands are update settings and set smtp-password; get settings is part of get.
func settingsCommands() map[string][]*cli.Command {
	var (
		instance, force bool
		sets            listFlag
		wait            time.Duration
		output          string
	)
	update := &cli.Command{
		Name: "settings", Summary: "change the org's settings, or with --instance the instance's",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&instance, "instance", false, "the instance's settings, for an Instance Admin")
			fs.Var(&sets, "set", "<setting>=<value>, a setting as get settings names it; an empty value restores the default; repeat for more")
			fs.BoolVar(&force, "force", false, "update without checking that the settings are unchanged since this command read them")
			fs.DurationVar(&wait, "wait", 0, "wait up to this long, at most 30s, for the agents to apply the change")
			outputFlag(fs, &output)
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 {
				return cli.Usagef("unexpected argument %q", args[0])
			}
			if len(sets) == 0 {
				return cli.Usagef("give --set <setting>=<value>; the settings are %s", strings.Join(settingNames(settingsType(instance)), ", "))
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			sc := rpmgrv1connect.NewSettingsServiceClient(s.hc, s.creds.Controller)
			cur, etag, _, err := s.settingsOf(ctx, sc, instance)
			if err != nil {
				return err
			}
			next := proto.Clone(cur).ProtoReflect()
			var paths []string
			for _, kv := range sets {
				name, v, ok := strings.Cut(kv, "=")
				if !ok {
					return cli.Usagef("--set %q is not <setting>=<value>", kv)
				}
				if err := s.setSetting(ctx, next, name, v); err != nil {
					return err
				}
				if top, _, _ := strings.Cut(name, "."); !slices.Contains(paths, top) {
					paths = append(paths, top)
				}
			}
			if force {
				etag = ""
			}
			mask := &fieldmaskpb.FieldMask{Paths: paths}
			var req proto.Message
			switch set := next.Interface().(type) {
			case *rpmgrv1.InstanceSettings:
				req = &rpmgrv1.UpdateInstanceSettingsRequest{Settings: set, UpdateMask: mask, Etag: etag}
			case *rpmgrv1.OrgSettings:
				req = &rpmgrv1.UpdateOrgSettingsRequest{OrgId: s.creds.Org, Settings: set, UpdateMask: mask, Etag: etag}
			}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			var resp, res protoreflect.Message
			if err := s.withStepUp(ctx, func() error {
				var err error
				switch r := req.(type) {
				case *rpmgrv1.UpdateInstanceSettingsRequest:
					var out *connect.Response[rpmgrv1.UpdateInstanceSettingsResponse]
					c := connect.NewRequest(r)
					setWait(c.Header(), wait)
					if out, err = sc.UpdateInstanceSettings(ctx, c); err == nil {
						resp, res = out.Msg.ProtoReflect(), out.Msg.GetSettings().ProtoReflect()
					}
				case *rpmgrv1.UpdateOrgSettingsRequest:
					var out *connect.Response[rpmgrv1.UpdateOrgSettingsResponse]
					c := connect.NewRequest(r)
					setWait(c.Header(), wait)
					if out, err = sc.UpdateOrgSettings(ctx, c); err == nil {
						resp, res = out.Msg.ProtoReflect(), out.Msg.GetSettings().ProtoReflect()
					}
				}
				return err
			}); err != nil {
				return apiError(err)
			}
			whose := "the org's"
			if instance {
				whose = "the instance's"
			}
			if _, err := fmt.Fprintf(env.Stdout, "Updated %s settings%s.\n", whose, applied(resp)); err != nil {
				return err
			}
			return s.writeSettings(ctx, env.Stdout, res, output, nil)
		},
	}
	var file string
	var remove bool
	smtpPassword := &cli.Command{
		Name: "smtp-password", Summary: "set or remove the mail relay's password (Instance Admin)",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "password-file", "", "a file whose first line is the password; without it, the password is asked for")
			fs.BoolVar(&remove, "remove", false, "remove the password")
		},
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) > 0 || remove && file != "" {
				return cli.Usagef("give --password-file, --remove or neither, and no argument")
			}
			var pw string
			switch {
			case file != "":
				warnOpenFile(env, "password", file)
				b, err := os.ReadFile(file) //nolint:gosec // G304: the user's file
				if err != nil {
					return err
				}
				line, _, _ := strings.Cut(string(b), "\n")
				pw = strings.TrimSuffix(line, "\r")
			case !remove:
				var err error
				if pw, err = passwordPrompt("the mail relay", false); err != nil {
					return err
				}
			}
			if pw == "" && !remove {
				return cli.Usagef("the password is empty; --remove removes it")
			}
			req := &rpmgrv1.SetSmtpPasswordRequest{Password: pw}
			if err := protovalidate.Validate(req); err != nil {
				return cli.Usagef("%v", err)
			}
			s, err := newAPISession(env)
			if err != nil {
				return err
			}
			if _, err := rpmgrv1connect.NewSettingsServiceClient(s.hc, s.creds.Controller).SetSmtpPassword(ctx, connect.NewRequest(req)); err != nil {
				return apiError(err)
			}
			msg := "Set the mail relay's password."
			if remove {
				msg = "Removed the mail relay's password."
			}
			_, err = fmt.Fprintln(env.Stdout, msg)
			return err
		},
	}
	return map[string][]*cli.Command{"update": {update}, "set": {smtpPassword}}
}

func settingsType(instance bool) protoreflect.MessageDescriptor {
	if instance {
		return (&rpmgrv1.InstanceSettings{}).ProtoReflect().Descriptor()
	}
	return (&rpmgrv1.OrgSettings{}).ProtoReflect().Descriptor()
}

// getSettings is `rpmgr get settings`.
func getSettings(ctx context.Context, env *cli.Env, instance bool, output string) error {
	s, err := newAPISession(env)
	if err != nil {
		return err
	}
	cur, _, pwSet, err := s.settingsOf(ctx, rpmgrv1connect.NewSettingsServiceClient(s.hc, s.creds.Controller), instance)
	if err != nil {
		return err
	}
	var extra [][2]string
	if instance {
		extra = append(extra, [2]string{"smtp password", map[bool]string{true: "set", false: "not set"}[pwSet]})
	}
	return s.writeSettings(ctx, env.Stdout, cur.ProtoReflect(), output, extra)
}

// settingsOf reads the org's settings, or the instance's, with their etag and whether the mail
// relay's password is set.
func (s *apiSession) settingsOf(ctx context.Context, sc rpmgrv1connect.SettingsServiceClient, instance bool) (proto.Message, string, bool, error) {
	if instance {
		r, err := sc.GetInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.GetInstanceSettingsRequest{}))
		if err != nil {
			return nil, "", false, apiError(err)
		}
		if r.Msg.GetSettings() == nil {
			return &rpmgrv1.InstanceSettings{}, r.Msg.GetEtag(), r.Msg.GetSmtpPasswordSet(), nil
		}
		return r.Msg.GetSettings(), r.Msg.GetEtag(), r.Msg.GetSmtpPasswordSet(), nil
	}
	r, err := sc.GetOrgSettings(ctx, connect.NewRequest(&rpmgrv1.GetOrgSettingsRequest{OrgId: s.creds.Org}))
	if err != nil {
		return nil, "", false, apiError(err)
	}
	if r.Msg.GetSettings() == nil {
		return &rpmgrv1.OrgSettings{}, r.Msg.GetEtag(), false, nil
	}
	return r.Msg.GetSettings(), r.Msg.GetEtag(), false, nil
}

// writeSettings writes settings as a table of the names that --set takes, or as YAML or JSON.
func (s *apiSession) writeSettings(ctx context.Context, w io.Writer, m protoreflect.Message, output string, extra [][2]string) error {
	if output != "table" {
		return s.print(ctx, w, apicli.Kind{}, output, []protoreflect.Message{m}, nil, false)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SETTING\tVALUE")
	var rows func(m protoreflect.Message, prefix string)
	rows = func(m protoreflect.Message, prefix string) {
		fields := m.Descriptor().Fields()
		for i := range fields.Len() {
			fd := fields.Get(i)
			if settingGroup(fd) {
				if m.Has(fd) {
					rows(m.Get(fd).Message(), prefix+string(fd.Name())+".")
					continue
				}
				_, _ = fmt.Fprintf(tw, "%s%s\t-\n", prefix, fd.Name())
				continue
			}
			_, _ = fmt.Fprintf(tw, "%s%s\t%s\n", prefix, fd.Name(), settingText(m, fd))
		}
	}
	rows(m, "")
	for _, e := range extra {
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", e[0], e[1])
	}
	return tw.Flush()
}

// settingGroup reports whether a field holds settings of its own, such as smtp.
func settingGroup(fd protoreflect.FieldDescriptor) bool {
	return fd.Kind() == protoreflect.MessageKind && !fd.IsList() && fd.Message().FullName() != "google.protobuf.Duration"
}

// settingNames are the names --set takes for a settings message.
func settingNames(md protoreflect.MessageDescriptor) []string {
	var out []string
	fields := md.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if settingGroup(fd) {
			for _, sub := range settingNames(fd.Message()) {
				out = append(out, string(fd.Name())+"."+sub)
			}
			continue
		}
		out = append(out, string(fd.Name()))
	}
	return out
}

// settingText is a setting's value as --set takes it, or "-" if it is not set.
func settingText(m protoreflect.Message, fd protoreflect.FieldDescriptor) string {
	if !m.Has(fd) {
		return "-"
	}
	v := m.Get(fd)
	switch {
	case fd.IsList():
		var parts []string
		for i := range v.List().Len() {
			parts = append(parts, v.List().Get(i).String())
		}
		return strings.Join(parts, ",")
	case fd.Kind() == protoreflect.MessageKind:
		d := v.Message().Interface().(*durationpb.Duration).AsDuration()
		if d%(24*time.Hour) == 0 && d > 0 {
			return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
		}
		return d.String()
	case fd.Kind() == protoreflect.EnumKind:
		return enumText(fd.Enum(), fd.Enum().Values().ByNumber(v.Enum()))
	case fd.Kind() == protoreflect.BoolKind:
		return strconv.FormatBool(v.Bool())
	}
	return v.String()
}

// enumText is an enum value's name without its enum's prefix, in lower case with dashes:
// "low-memory" for PASSWORD_HASH_PROFILE_LOW_MEMORY.
func enumText(ed protoreflect.EnumDescriptor, vd protoreflect.EnumValueDescriptor) string {
	if vd == nil {
		return "-"
	}
	prefix := strings.TrimSuffix(string(ed.Values().ByNumber(0).Name()), "UNSPECIFIED")
	return strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(string(vd.Name()), prefix)), "_", "-")
}

// setSetting sets the setting that name names on m from text; an empty text clears it, so that
// the default applies.
func (s *apiSession) setSetting(ctx context.Context, m protoreflect.Message, name, text string) error {
	head, rest, nested := strings.Cut(name, ".")
	fd := m.Descriptor().Fields().ByName(protoreflect.Name(head))
	unknown := cli.Usagef("--set: no setting %q; the settings are %s", name, strings.Join(settingNames(m.Descriptor()), ", "))
	switch {
	case fd == nil || nested && !settingGroup(fd):
		return unknown
	case nested:
		return s.setSetting(ctx, m.Mutable(fd).Message(), rest, text)
	case text == "":
		m.Clear(fd)
		return nil
	case settingGroup(fd):
		return cli.Usagef("--set %s: set its parts, such as %s.%s, or clear it with %s=", name, name, fd.Message().Fields().Get(0).Name(), name)
	case fd.IsList():
		l := m.Mutable(fd).List()
		l.Truncate(0)
		for _, v := range strings.Split(text, ",") {
			l.Append(protoreflect.ValueOfString(v))
		}
		return nil
	case fd.Kind() == protoreflect.MessageKind:
		d, err := parseDays(text)
		if err != nil {
			return cli.Usagef("--set %s=%s: a duration such as 30d or 12h", name, text)
		}
		m.Set(fd, protoreflect.ValueOfMessage(durationpb.New(d).ProtoReflect()))
		return nil
	case fd.Kind() == protoreflect.EnumKind:
		values := fd.Enum().Values()
		var names []string
		for i := 1; i < values.Len(); i++ {
			t := enumText(fd.Enum(), values.Get(i))
			if t == text {
				m.Set(fd, protoreflect.ValueOfEnum(values.Get(i).Number()))
				return nil
			}
			names = append(names, t)
		}
		return cli.Usagef("--set %s=%s: one of %s", name, text, strings.Join(names, ", "))
	case fd.Kind() == protoreflect.BoolKind:
		b, err := strconv.ParseBool(text)
		if err != nil {
			return cli.Usagef("--set %s=%s: true or false", name, text)
		}
		m.Set(fd, protoreflect.ValueOfBool(b))
		return nil
	case name == "default_gateway_group_id":
		var id string
		if err := s.resolve(ctx, "gateway-group", text, &id); err != nil {
			return err
		}
		text = id
	}
	m.Set(fd, protoreflect.ValueOfString(text))
	return nil
}

// parseDays parses a Go duration, or a whole number of days such as 30d.
func parseDays(text string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(text, "d"); ok {
		days, err := strconv.ParseUint(n, 10, 16)
		return time.Duration(days) * 24 * time.Hour, err //nolint:gosec // G115: at most 65535 days
	}
	return time.ParseDuration(text)
}
