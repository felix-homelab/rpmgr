// SPDX-License-Identifier: Apache-2.0

// Package policy reads and enforces the connector-local policy (docs/04-security.md,
// "Connector-local policy"; ADR-0009): a root-owned file on the connector host that limits what the
// connector may dial, whatever any snapshot says. It is the one control that survives a compromised
// controller.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"go.yaml.in/yaml/v3"
)

// DefaultPath is where the connector reads its policy.
const DefaultPath = "/etc/rpmgr/policy.yaml"

// The values of auto_update and update_channel.
const (
	AutoUpdateAuto    = "auto"
	AutoUpdateNotify  = "notify"
	AutoUpdateOff     = "off"
	ChannelStable     = "stable"
	ChannelPrerelease = "prerelease"
)

// Policy is a parsed policy file. The zero value allows nothing.
type Policy struct {
	targets       []target
	AutoUpdate    string
	UpdateChannel string
	// Invalid is set for the policy that stands in for a file that does not parse: it denies
	// everything, and every target reports not_ready(policy_invalid).
	Invalid error
}

type target struct {
	prefix netip.Prefix // zero for a unix socket
	ports  []portRange
	unix   string
}

type portRange struct{ lo, hi uint16 }

// Defaults is the policy without a file: no target allowed, auto_update auto, update_channel
// stable (D5, D6).
func Defaults() *Policy {
	return &Policy{AutoUpdate: AutoUpdateAuto, UpdateChannel: ChannelStable}
}

// file is the YAML form of version 1.
type file struct {
	Version      int `yaml:"version"`
	AllowTargets []struct {
		CIDR  string `yaml:"cidr"`
		Ports []any  `yaml:"ports"`
		Unix  string `yaml:"unix"`
	} `yaml:"allow_targets"`
	AllowListen      []string `yaml:"allow_listen"`
	AllowRemoteShell bool     `yaml:"allow_remote_shell"`
	AllowFunctions   bool     `yaml:"allow_functions"`
	AllowVNetRoutes  []string `yaml:"allow_vnet_routes"`
	AllowP2P         bool     `yaml:"allow_p2p"`
	AllowEgressProxy bool     `yaml:"allow_egress_proxy"`
	AutoUpdate       string   `yaml:"auto_update"`
	UpdateChannel    string   `yaml:"update_channel"`
}

// Parse reads a policy file. Unknown keys, a version other than 1, a bad CIDR, port or socket path
// and an unknown auto_update or update_channel are errors.
func Parse(data []byte) (*Policy, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("policy: version %d, want 1", f.Version)
	}
	p := Defaults()
	if f.AutoUpdate != "" {
		p.AutoUpdate = f.AutoUpdate
	}
	if f.UpdateChannel != "" {
		p.UpdateChannel = f.UpdateChannel
	}
	if !slices.Contains([]string{AutoUpdateAuto, AutoUpdateNotify, AutoUpdateOff}, p.AutoUpdate) {
		return nil, fmt.Errorf("policy: auto_update %q, want auto, notify or off", p.AutoUpdate)
	}
	if !slices.Contains([]string{ChannelStable, ChannelPrerelease}, p.UpdateChannel) {
		return nil, fmt.Errorf("policy: update_channel %q, want stable or prerelease", p.UpdateChannel)
	}
	for i, t := range f.AllowTargets {
		switch {
		case t.Unix != "" && (t.CIDR != "" || len(t.Ports) > 0):
			return nil, fmt.Errorf("policy: allow_targets[%d]: a unix socket has no cidr or ports", i)
		case t.Unix != "":
			if !filepath.IsAbs(t.Unix) || filepath.Clean(t.Unix) != t.Unix {
				return nil, fmt.Errorf("policy: allow_targets[%d]: unix %q is not a clean absolute path", i, t.Unix)
			}
			p.targets = append(p.targets, target{unix: t.Unix})
		default:
			prefix, err := netip.ParsePrefix(t.CIDR)
			if err != nil {
				return nil, fmt.Errorf("policy: allow_targets[%d]: cidr %q: %w", i, t.CIDR, err)
			}
			if prefix != prefix.Masked() {
				return nil, fmt.Errorf("policy: allow_targets[%d]: cidr %q has host bits set", i, t.CIDR)
			}
			if len(t.Ports) == 0 {
				return nil, fmt.Errorf("policy: allow_targets[%d]: no ports", i)
			}
			tg := target{prefix: unmapPrefix(prefix)}
			for _, raw := range t.Ports {
				r, err := parsePorts(raw)
				if err != nil {
					return nil, fmt.Errorf("policy: allow_targets[%d]: %w", i, err)
				}
				tg.ports = append(tg.ports, r)
			}
			p.targets = append(p.targets, tg)
		}
	}
	return p, nil
}

// parsePorts reads a port, 8080, or a range, "8000-8099".
func parsePorts(raw any) (portRange, error) {
	port := func(s string) (uint16, error) {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("port %q is not in 1-65535", s)
		}
		return uint16(n), nil //nolint:gosec // G115: checked above
	}
	switch v := raw.(type) {
	case int:
		n, err := port(strconv.Itoa(v))
		return portRange{n, n}, err
	case string:
		lo, hi, isRange := strings.Cut(v, "-")
		a, err := port(lo)
		if err != nil || !isRange {
			return portRange{a, a}, err
		}
		b, err := port(hi)
		if err != nil {
			return portRange{}, err
		}
		if a > b {
			return portRange{}, fmt.Errorf("port range %q is reversed", v)
		}
		return portRange{a, b}, nil
	}
	return portRange{}, fmt.Errorf("port %v is neither a number nor a range", raw)
}

// unmapPrefix turns an IPv4-mapped IPv6 prefix into its IPv4 form.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

// protected are the link-local and cloud metadata ranges, which a target allows only if it lies
// inside one of them: a broad CIDR such as 0.0.0.0/0 never allows them.
var protected = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("100.100.100.200/32"),
}

// Allows reports whether the connector may connect to ip:port.
func (p *Policy) Allows(ip netip.Addr, port uint16) bool {
	if p == nil || p.Invalid != nil {
		return false
	}
	ip = ip.Unmap()
	var guard *netip.Prefix
	for i, r := range protected {
		if r.Contains(ip) {
			guard = &protected[i]
		}
	}
	for _, t := range p.targets {
		if !t.prefix.IsValid() || !t.prefix.Contains(ip) {
			continue
		}
		if guard != nil && (t.prefix.Bits() < guard.Bits() || !guard.Contains(t.prefix.Addr())) {
			continue // the target is broader than the protected range: not explicit
		}
		for _, r := range t.ports {
			if port >= r.lo && port <= r.hi {
				return true
			}
		}
	}
	return false
}

// AllowsUnix reports whether the connector may connect to the unix socket at path.
func (p *Policy) AllowsUnix(path string) bool {
	if p == nil || p.Invalid != nil {
		return false
	}
	return slices.ContainsFunc(p.targets, func(t target) bool { return t.unix != "" && t.unix == path })
}

// BlockedError is a dial the policy refuses; it names the target, so that the route reports
// not_ready(blocked_by_local_policy: <target>) and the UI can show the command that allows it.
type BlockedError struct{ Target string }

func (e *BlockedError) Error() string {
	return "policy: the connector-local policy does not allow " + e.Target
}

// Control returns a net.Dialer.Control that checks every connection at dial time on the resolved
// address, so a name that resolves elsewhere since, as in DNS rebinding, is still refused. current
// returns the policy in force.
func Control(current func() *Policy) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		if network == "unix" {
			if current().AllowsUnix(address) {
				return nil
			}
			return &BlockedError{Target: address}
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return &BlockedError{Target: address}
		}
		if !current().Allows(ap.Addr(), ap.Port()) {
			return &BlockedError{Target: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()}
		}
		return nil
	}
}

// Load reads the policy at path. A missing file is Defaults. A file that does not parse, or that
// its group or other users may write, yields a policy that denies everything, with Invalid set,
// and the error.
func Load(path string) (*Policy, error) {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Defaults(), nil
	}
	if err == nil && st.Mode().Perm()&0o022 != 0 {
		err = fmt.Errorf("policy: %s has mode %04o; only its owner may write it", path, st.Mode().Perm())
	}
	var p *Policy
	if err == nil {
		var b []byte
		if b, err = os.ReadFile(path); err == nil { //nolint:gosec // G304: the configured policy file
			p, err = Parse(b)
		}
	}
	if err != nil {
		return &Policy{AutoUpdate: AutoUpdateAuto, UpdateChannel: ChannelStable, Invalid: err}, err
	}
	return p, nil
}

// ErrNotIP is returned by Check for a target that is not an IP address and port.
var ErrNotIP = errors.New("policy: not an IP address and port")

// Check reports whether host:port, an IP address and port, is allowed, as `rpmgr policy` and the
// UI's hint check it without dialling.
func (p *Policy) Check(hostport string) error {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return ErrNotIP
	}
	ap, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil {
		return ErrNotIP
	}
	if !p.Allows(ap.Addr(), ap.Port()) {
		return &BlockedError{Target: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()}
	}
	return nil
}
