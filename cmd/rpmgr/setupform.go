// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/huh/v2"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/setup"
)

// setupStdin is what the plain prompts read, and setupTerminal whether the forms can take the
// full screen: a terminal at least 40 columns wide, which a serial console without a size is not.
// Tests replace both.
var (
	setupStdin    io.Reader = os.Stdin
	setupTerminal           = func() bool {
		w, _, err := term.GetSize(int(os.Stdout.Fd()))                      //nolint:gosec // G115: file descriptors fit in an int
		return term.IsTerminal(int(os.Stdin.Fd())) && err == nil && w >= 40 //nolint:gosec // G115: as above
	}
)

// setupForm asks for the values of `rpmgr setup`, pre-filled with its flags (D73): full screen on
// a terminal, else as plain prompts on stdin and stdout (huh's accessible mode). It asks role by
// role, one form after another, so that the plain prompts ask only what the role needs.
type setupForm struct {
	ctx   context.Context
	out   io.Writer
	in    io.Reader
	plain bool
	facts setup.Facts
}

func newSetupForm(ctx context.Context, out io.Writer, facts setup.Facts) *setupForm {
	f := &setupForm{ctx: ctx, out: out, plain: !setupTerminal(), facts: facts}
	if f.plain {
		f.in = &lineReader{r: bufio.NewReader(setupStdin)}
	}
	return f
}

// ask runs one form of fields.
func (f *setupForm) ask(fields ...huh.Field) error {
	form := huh.NewForm(huh.NewGroup(fields...)).WithAccessible(f.plain)
	if f.plain {
		form = form.WithInput(f.in).WithOutput(plainWriter{f.out})
	}
	err := form.RunWithContext(f.ctx)
	if errors.Is(err, huh.ErrUserAborted) {
		return errors.New("setup: cancelled; nothing was changed")
	}
	return err
}

// values asks for the role and everything it needs.
func (f *setupForm) values(v *setup.Values) error {
	role := string(v.Role)
	if role == "" {
		role = string(setup.AllInOne)
	}
	roles := make([]huh.Option[string], 0, len(setup.Roles))
	for _, r := range setup.Roles {
		roles = append(roles, huh.NewOption(string(r.Role)+": "+r.About, string(r.Role)))
	}
	if err := f.ask(huh.NewNote().Title("rpmgr setup").Description("Sets this host up for one role. Nothing changes before you confirm the plan."),
		huh.NewSelect[string]().Title("Role of this host").Options(roles...).Value(&role)); err != nil {
		return err
	}
	v.Role = setup.Role(role)
	var err error
	if v.Role.Initialises() {
		err = f.controller(v)
	} else {
		err = f.agent(v)
	}
	if err != nil {
		return err
	}
	if err := f.listeners(v); err != nil {
		return err
	}
	unit := !v.NoUnit
	if err := f.ask(huh.NewConfirm().Title("Install the unit rpmgr-" + role + ", start it and wait until it is ready?").Value(&unit)); err != nil {
		return err
	}
	v.NoUnit = !unit
	return nil
}

// controller asks a controller's or all-in-one's public URL, KEK, certificate and ACME CA, and an
// all-in-one's connector targets.
func (f *setupForm) controller(v *setup.Values) error {
	if err := f.ask(huh.NewInput().Title("Public URL: https://<host>[:<port>] of the web UI, the API and the agents").
		Placeholder("https://rpmgr.example.com").Validate(keep(v.PublicURL, setup.CheckPublicURL)).Value(&v.PublicURL)); err != nil {
		return err
	}
	host, public := setup.PublicHost(v.PublicURL)
	if v.KEKSource == "" {
		v.KEKSource = controller.KEKSourceFor(f.facts.Systemd)
	}
	if v.TLS == "" {
		v.TLS = setup.TLSSelfSigned
		if public {
			v.TLS = setup.TLSACME
		}
	}
	kekNote := "The key-encryption key (KEK) encrypts the secrets in the database. A systemd credential is " +
		"encrypted by systemd-creds for this host and given to the service only; a file lies plain on disk, " +
		"readable by rpmgr only. Either way, back the KEK up apart from the database."
	kek := huh.Field(huh.NewSelect[string]().Title("Where the KEK is kept").Options(
		huh.NewOption("systemd credential (systemd 250 or newer)", config.KEKSystemdCredential),
		huh.NewOption("file", config.KEKFile)).Value(&v.KEKSource))
	if f.facts.Systemd < 250 {
		v.KEKSource, kek = config.KEKFile, huh.NewNote().Title("The KEK is a file: this host has no systemd 250 or newer for a credential.")
	}
	certs := []huh.Option[string]{
		huh.NewOption("acme: from the ACME CA at the first start, Let's Encrypt production unless you choose staging", setup.TLSACME),
		huh.NewOption("files: your certificate chain and key", setup.TLSFiles),
		huh.NewOption("self-signed: no browser trusts it until you switch", setup.TLSSelfSigned),
	}
	if !public {
		certs = certs[1:]
	}
	if err := f.ask(huh.NewNote().Title("KEK").Description(kekNote), kek,
		huh.NewSelect[string]().Title("Certificate of "+host).Options(certs...).Value(&v.TLS)); err != nil {
		return err
	}
	var more []huh.Field
	if v.KEKSource == config.KEKFile {
		more = append(more, huh.NewInput().Title("KEK file").Placeholder("/etc/rpmgr/kek").Value(&v.KEKPath))
	}
	if v.TLS == setup.TLSFiles {
		more = append(more, huh.NewInput().Title("Certificate chain file").Validate(keep(v.CertFile, required)).Value(&v.CertFile),
			huh.NewInput().Title("Key file").Validate(keep(v.KeyFile, required)).Value(&v.KeyFile))
	}
	directory := v.ACMEDirectory
	if directory == "" {
		directory = "production"
	}
	directories := []huh.Option[string]{huh.NewOption("production: certificates browsers trust", "production"),
		huh.NewOption("staging: to try a setup first; no browser trusts its certificates", "staging")}
	if directory != "production" && directory != "staging" {
		directories = append(directories, huh.NewOption(directory, directory))
	}
	more = append(more, huh.NewSelect[string]().Title("ACME CA of the instance, for the public URL and the routes").
		Options(directories...).Value(&directory),
		huh.NewInput().Title("ACME account e-mail address (optional)").Validate(setup.CheckEmail).Value(&v.ACMEEmail))
	targets, denied := strings.Join(v.AllowTargets, " "), strings.Join(v.DenyTargets, " ")
	if v.Role == setup.AllInOne {
		more = append(more, huh.NewNote().Title("Its connector").Description("The all-in-one's own connector reaches services on this "+
			"host, such as containers, but only the targets its local policy allows; rpmgr's own ports never."))
		more = append(more, targetFields(&targets, &denied)...)
	}
	if err := f.ask(more...); err != nil {
		return err
	}
	if directory != "production" || v.ACMEDirectory != "" {
		v.ACMEDirectory = directory
	}
	v.AllowTargets, v.DenyTargets = strings.Fields(targets), strings.Fields(denied)
	return nil
}

// targetFields ask a connector's allowed and denied targets, separated by spaces.
func targetFields(targets, denied *string) []huh.Field {
	return []huh.Field{
		huh.NewInput().Title("Allowed targets, separated by spaces (optional)").
			Description("10.0.0.5:5432, 10.0.0.0/16 (all ports), 127.0.0.1:200-500, [fd00::1]:443 or /run/app.sock").
			Validate(func(s string) error { return checkEach(s, setup.CheckTarget) }).Value(targets),
		huh.NewInput().Title("Denied targets, which win over allowed ones (optional)").Placeholder("127.0.0.1:345").
			Validate(func(s string) error { return checkEach(s, setup.CheckTarget) }).Value(denied),
	}
}

// agent asks a gateway's or connector's controller, CA pin, and a connector's targets and proxy.
// The token comes afterwards, as for `rpmgr enroll`.
func (f *setupForm) agent(v *setup.Values) error {
	fields := []huh.Field{
		huh.NewInput().Title("Controller URL").Placeholder("https://rpmgr.example.com").
			Validate(keep(v.ControllerURL, setup.CheckControllerURL)).Value(&v.ControllerURL),
		huh.NewInput().Title("CA pin, as the controller's init printed it").Placeholder("sha256:…").
			Validate(keep(v.Pin, setup.CheckPin)).Value(&v.Pin),
	}
	targets, denied := strings.Join(v.AllowTargets, " "), strings.Join(v.DenyTargets, " ")
	if v.Role == setup.Connector {
		fields = append(append(fields, targetFields(&targets, &denied)...),
			huh.NewInput().Title("Proxy for the connection to the controller (optional)").Placeholder("http://proxy.lan:3128").
				Validate(setup.CheckProxy).Value(&v.Proxy))
	}
	if err := f.ask(fields...); err != nil {
		return err
	}
	v.AllowTargets, v.DenyTargets = strings.Fields(targets), strings.Fields(denied)
	return nil
}

// listeners asks the role's listen addresses; empty keeps the default.
func (f *setupForm) listeners(v *setup.Values) error {
	addr := func(title, placeholder string, value *string, off bool) huh.Field {
		return huh.NewInput().Title(title).Placeholder(placeholder).
			Validate(func(s string) error { return setup.CheckAddr(s, off) }).Value(value)
	}
	var fields []huh.Field
	switch v.Role {
	case setup.Controller:
		fields = append(fields, addr("listen.https", ":443", &v.ListenHTTPS, false))
	case setup.AllInOne, setup.Gateway:
		fields = append(fields, addr("listen.tcp", ":443", &v.ListenTCP, false), addr("listen.udp", ":443", &v.ListenUDP, false))
	}
	if v.Role != setup.Connector {
		fields = append(fields, addr("listen.http, or off", ":80", &v.ListenHTTP, true))
	}
	fields = append(fields, addr("listen.admin", "the role's 127.0.0.1 port", &v.ListenAdmin, false))
	return f.ask(append([]huh.Field{huh.NewNote().Title("Listen addresses").Description("Empty keeps the default.")}, fields...)...)
}

// token asks for the gateway or enrollment token without echo.
func (f *setupForm) token() (string, error) {
	if f.plain {
		return promptToken()
	}
	var tok string
	err := f.ask(huh.NewInput().Title("Token: the gateway or enrollment token").EchoMode(huh.EchoModePassword).
		Validate(setup.CheckToken).Value(&tok))
	return tok, err
}

// confirm shows the plan and asks whether to run it.
func (f *setupForm) confirm(plan *setup.Plan) error {
	var b strings.Builder
	for _, kv := range plan.Summary() {
		fmt.Fprintf(&b, "%-16s %s\n", kv[0]+":", kv[1])
	}
	b.WriteString("\nSteps:\n")
	for i, s := range plan.Steps() {
		fmt.Fprintf(&b, "%d. %s\n", i+1, s)
	}
	run := false
	if err := f.ask(huh.NewNote().Title("The plan").Description(b.String()),
		huh.NewConfirm().Title("Run it?").Affirmative("Run").Negative("Cancel").Value(&run)); err != nil {
		return err
	}
	if !run {
		return errors.New("setup: not confirmed; nothing was changed")
	}
	return nil
}

// keep accepts an empty answer for a pre-filled value: a plain prompt keeps the value then.
func keep(value string, check func(string) error) func(string) error {
	return func(s string) error {
		if s == "" && value != "" {
			return nil
		}
		return check(s)
	}
}

func required(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("needed")
	}
	return nil
}

func checkEach(s string, check func(string) error) error {
	for _, t := range strings.Fields(s) {
		if err := check(t); err != nil {
			return err
		}
	}
	return nil
}

// plainWriter strips the styles from plain prompts, which go to a pipe or a screen reader.
type plainWriter struct{ w io.Writer }

func (p plainWriter) Write(b []byte) (int, error) {
	if _, err := io.WriteString(p.w, ansi.Strip(string(b))); err != nil {
		return 0, err
	}
	return len(b), nil
}

// lineReader returns at most one line per read. Each plain prompt reads with a new scanner, which
// would otherwise take the answers to the next prompts from a pipe with it.
type lineReader struct {
	r    *bufio.Reader
	rest []byte
}

func (l *lineReader) Read(p []byte) (int, error) {
	if len(l.rest) == 0 {
		line, err := l.r.ReadBytes('\n')
		if len(line) == 0 {
			return 0, err
		}
		l.rest = line
	}
	n := copy(p, l.rest)
	l.rest = l.rest[n:]
	return n, nil
}
