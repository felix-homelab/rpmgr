// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/firewall"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// Firewall is the one backend setup knows (docs/04-security.md, "Host firewall for port pools").
const Firewall = "ufw"

// The bounds file the helper reads, and the directory the gateway writes the desired file in
// (docs/10-operations.md, "Host firewall helper").
func (p Paths) firewallBounds() string { return filepath.Join(p.Etc, "firewall.json") }
func (p Paths) firewallDir() string    { return filepath.Join(p.Lib, "firewall") }

// listenersOf are the ports a gateway listens on for the public, from its boot file: the
// helper always opens them (docs/10-operations.md, "Host firewall helper").
func listenersOf(g config.Gateway) []firewall.Listener {
	var out []firewall.Listener
	add := func(proto, addr string) {
		_, port, err := net.SplitHostPort(addr)
		if n, perr := strconv.Atoi(port); err == nil && perr == nil && n > 0 {
			l := firewall.Listener{Protocol: proto, Port: n}
			for _, o := range out {
				if o == l {
					return
				}
			}
			out = append(out, l)
		}
	}
	add("tcp", g.Listen.TCP)
	if g.Listen.HTTP != nil {
		add("tcp", *g.Listen.HTTP)
	}
	add("udp", g.Listen.UDP)
	add("udp", g.Listen.TunnelUDP)
	return out
}

// boundsOf are the helper's bounds for a gateway's boot file.
func boundsOf(g config.Gateway) firewall.Bounds {
	b := firewall.Bounds{Version: 1, Backend: g.Firewall.Backend, Listeners: listenersOf(g)}
	if from, to, ok := g.Firewall.Range(); ok {
		b.MaxRange = &firewall.PortRange{From: from, To: to}
	}
	return b
}

// installFirewall writes the root-owned bounds file, makes the directory the gateway writes the
// desired file in, and unless noUnit installs and enables the helper's units. It changes nothing a
// second run does not write again the same. A host without ufw is no error: the helper reports it
// as failed until ufw is installed and active, and the result says so.
func installFirewall(ctx context.Context, h Host, b firewall.Bounds, noUnit bool, r *Result) error {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := mkdirMode(h.Paths.Etc, 0o755); err != nil {
		return err
	}
	r.created(h.Paths.firewallBounds())
	if err := writeMode(h.Paths.firewallBounds(), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	dir := h.Paths.firewallDir()
	if !exists(dir) {
		r.Written = append(r.Written, dir)
	}
	if err := mkdirMode(dir, 0o750); err != nil {
		return err
	}
	if err := h.GiveTo(dir); err != nil {
		return err
	}
	if !h.HasUfw() {
		r.FirewallNote = "ufw is not installed on this host: the firewall shows as failed until ufw is installed and active"
	}
	if noUnit {
		return nil
	}
	for _, u := range []string{"rpmgr-firewall.path", "rpmgr-firewall.service"} {
		r.created(filepath.Join(h.Paths.Units, u))
	}
	if _, err := update.WriteFirewallUnits(h.Paths.Units, h.Paths.Bin); err != nil {
		return err
	}
	if err := h.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := h.Run(ctx, "systemctl", "enable", "rpmgr-firewall.service"); err != nil { // its run at boot
		return err
	}
	return h.Run(ctx, "systemctl", "enable", "--now", "rpmgr-firewall.path")
}

// firewallSteps hand the host's ufw to rpmgr when the values ask for it.
func (p *Plan) firewallSteps() {
	if p.v.Firewall != Firewall {
		return
	}
	h := p.h
	title := "hand ufw to rpmgr: write the bounds " + h.Paths.firewallBounds() + " (root's), create " + h.Paths.firewallDir() +
		", owned by " + ServiceUser
	if !p.v.NoUnit {
		title += ", install its units rpmgr-firewall.path and rpmgr-firewall.service: systemctl enable rpmgr-firewall.service, enable --now rpmgr-firewall.path"
	}
	p.add(title, func(ctx context.Context, r *Result) error {
		return installFirewall(ctx, h, p.bounds, p.v.NoUnit, r)
	})
}

// checkFirewall checks the firewall values.
func (v Values) checkFirewall() error {
	var errs []error
	switch {
	case v.Firewall == "" && v.FirewallRange != "":
		errs = append(errs, errors.New("--firewall-max-range needs --firewall ufw"))
	case v.Firewall != "" && v.Firewall != Firewall:
		errs = append(errs, fmt.Errorf("firewall %q: want ufw, the only firewall rpmgr manages", v.Firewall))
	case v.Firewall != "" && v.Role != Gateway && v.Role != AllInOne:
		errs = append(errs, errors.New("the firewall is a gateway's or an all-in-one's: a controller and a connector open no public port of the pools"))
	}
	if err := (config.Firewall{Backend: v.Firewall, MaxRange: v.FirewallRange}).Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ufwInstalled reports whether the ufw command is on the host's PATH.
func ufwInstalled() bool {
	_, err := exec.LookPath("ufw")
	return err == nil
}

// firewallSummary says what handing ufw to rpmgr opens, for the confirmation.
func (p *Plan) firewallSummary() string {
	s := "rpmgr manages ufw: the listeners and "
	if from, to, ok := (config.Firewall{MaxRange: p.v.FirewallRange}).Range(); ok {
		return s + fmt.Sprintf("the port pools within %d-%d", from, to)
	}
	return s + "no port pool (no --firewall-max-range)"
}
