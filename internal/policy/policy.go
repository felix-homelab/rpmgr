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
	denied        []target // deny_targets, which refuse whatever targets allows (D84)
	AutoUpdate    string
	UpdateChannel string
	// Invalid is set for the policy that stands in for a file that does not parse: it denies
	// everything, and every target reports not_ready(policy_invalid).
	Invalid error
}

// target is an entry of allow_targets or deny_targets: a unix socket, or an address or subnet
// with its ports, all of them unless the entry names some.
type target struct {
	prefix netip.Prefix // zero for a unix socket
	ports  []portRange
	unix   string
}

type portRange struct{ lo, hi uint16 }

// allPorts is the ports of an entry that names none.
var allPorts = []portRange{{1, 65535}}

// matches reports whether ip:port is inside t.
func (t target) matches(ip netip.Addr, port uint16) bool {
	return t.prefix.IsValid() && t.prefix.Contains(ip) && slices.ContainsFunc(t.ports, func(r portRange) bool {
		return port >= r.lo && port <= r.hi
	})
}

// text is t with only its port range r as a target string, which parseTarget reads back and the
// editing commands take: its subnet normalised, an address alone, IPv6 in brackets, and no port
// for all ports.
func (t target) text(r portRange) string {
	if t.unix != "" {
		return t.unix
	}
	host := t.prefix.String()
	if t.prefix.IsSingleIP() {
		host = t.prefix.Addr().String()
	}
	if t.prefix.Addr().Is6() {
		host = "[" + host + "]"
	}
	if r == allPorts[0] {
		return host
	}
	return host + ":" + r.String()
}

func (r portRange) String() string {
	if r.lo == r.hi {
		return strconv.Itoa(int(r.lo))
	}
	return fmt.Sprintf("%d-%d", r.lo, r.hi)
}

// parseTarget reads a target in the syntax of the policy file's string entries, `rpmgr policy`,
// `rpmgr setup` and the install command: an absolute socket path, or an address or subnet with an
// optional port or port range, such as 127.0.0.1, 10.0.0.1/16 (stored as 10.0.0.0/16),
// 127.0.0.1:200-500, 10.0.0.0/16:443 or [fd00::/64]:8000-8099, IPv6 always in brackets. Without a
// port it means all ports.
func parseTarget(s string) (target, error) {
	bad := func(format string, args ...any) (target, error) {
		return target{}, fmt.Errorf("policy: target %q: "+format, append([]any{s}, args...)...)
	}
	if strings.HasPrefix(s, "/") {
		if filepath.Clean(s) != s {
			return bad("not a clean absolute socket path")
		}
		return target{unix: s}, nil
	}
	host, ports := s, ""
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.Index(s, "]")
		if end < 0 {
			return bad("no closing bracket")
		}
		host, ports = s[1:end], s[end+1:]
		if ports != "" && !strings.HasPrefix(ports, ":") {
			return bad("want [<ipv6>]:<port> after the bracket")
		}
		ports = strings.TrimPrefix(ports, ":")
		if ports == "" && s[end+1:] != "" {
			return bad("no port after the colon")
		}
	case strings.Count(s, ":") > 1:
		// fd00::1:80 could be an address or an address and a port: brackets say which.
		return bad("write an IPv6 address or subnet in brackets, such as [fd00::1] or [fd00::/64]:443")
	case strings.Contains(s, ":"):
		host, ports, _ = strings.Cut(s, ":")
		if ports == "" {
			return bad("no port after the colon")
		}
	}
	prefix, err := parseHost(host)
	if err != nil {
		return bad("%v", err)
	}
	t := target{prefix: prefix, ports: allPorts}
	if ports != "" {
		r, err := parsePorts(ports)
		if err != nil {
			return bad("%v", err)
		}
		t.ports = []portRange{r}
	}
	return t, nil
}

// parseHost reads an address or a subnet, without a zone; a subnet's host bits are cleared and an
// IPv4-mapped IPv6 one becomes IPv4.
func parseHost(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		ip, err := netip.ParseAddr(s)
		if err != nil || ip.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q is not an IP address or subnet", s)
		}
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or subnet", s)
	}
	return unmapPrefix(prefix.Masked()), nil
}

// Defaults is the policy without a file: no target allowed, auto_update auto, update_channel
// stable (D5, D6).
func Defaults() *Policy {
	return &Policy{AutoUpdate: AutoUpdateAuto, UpdateChannel: ChannelStable}
}

// file is the YAML form of version 1.
type file struct {
	Version          int         `yaml:"version"`
	AllowTargets     []yaml.Node `yaml:"allow_targets"`
	DenyTargets      []yaml.Node `yaml:"deny_targets"`
	AllowListen      []string    `yaml:"allow_listen"`
	AllowRemoteShell bool        `yaml:"allow_remote_shell"`
	AllowFunctions   bool        `yaml:"allow_functions"`
	AllowVNetRoutes  []string    `yaml:"allow_vnet_routes"`
	AllowP2P         bool        `yaml:"allow_p2p"`
	AllowEgressProxy bool        `yaml:"allow_egress_proxy"`
	AutoUpdate       string      `yaml:"auto_update"`
	UpdateChannel    string      `yaml:"update_channel"`
}

// Parse reads a policy file. Unknown keys, a version other than 1, a bad target, port or socket
// path and an unknown auto_update or update_channel are errors.
func Parse(data []byte) (*Policy, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := noAliases(&doc); err != nil {
		return nil, err
	}
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
	for _, list := range []struct {
		key   string
		nodes []yaml.Node
		into  *[]target
	}{{"allow_targets", f.AllowTargets, &p.targets}, {"deny_targets", f.DenyTargets, &p.denied}} {
		for i := range list.nodes {
			t, err := parseEntry(&list.nodes[i])
			if err != nil {
				return nil, fmt.Errorf("policy: %s[%d]: %w", list.key, i, err)
			}
			*list.into = append(*list.into, t)
		}
	}
	return p, nil
}

// noAliases refuses anchors, aliases and merge keys anywhere in the file: an edit changes a node in
// place, which would change every alias of it as well, and a merge key could hide a list an edit
// replaces.
func noAliases(n *yaml.Node) error {
	if n.Anchor != "" || n.Kind == yaml.AliasNode || n.ShortTag() == "!!merge" {
		return fmt.Errorf("policy: line %d: anchors, aliases and merge keys are not allowed in the policy file; edit it by hand "+
			"without them", n.Line)
	}
	for _, c := range n.Content {
		if err := noAliases(c); err != nil {
			return err
		}
	}
	return nil
}

// parseEntry reads an entry of allow_targets or deny_targets: a target as a string, or a mapping
// of cidr, an address or subnet, and ports, all of them if none, or of unix, a socket path.
func parseEntry(n *yaml.Node) (target, error) {
	if n.Kind == yaml.ScalarNode {
		return parseTarget(n.Value)
	}
	if n.Kind != yaml.MappingNode {
		return target{}, errors.New("an entry is a target string or a mapping of cidr and ports, or unix")
	}
	var cidr, unix string
	var ports []any
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1]
		if seen[k] {
			return target{}, fmt.Errorf("key %q given twice", k)
		}
		seen[k] = true
		var err error
		switch k {
		case "cidr":
			err = v.Decode(&cidr)
		case "unix":
			err = v.Decode(&unix)
		case "ports":
			err = v.Decode(&ports)
		default:
			err = fmt.Errorf("unknown key %q", k)
		}
		if err != nil {
			return target{}, err
		}
	}
	switch {
	case unix != "" && (cidr != "" || len(ports) > 0):
		return target{}, errors.New("a unix socket has no cidr or ports")
	case unix != "":
		if !filepath.IsAbs(unix) {
			return target{}, fmt.Errorf("unix %q is not a clean absolute path", unix)
		}
		return parseTarget(unix)
	}
	prefix, err := parseHost(cidr)
	if err != nil {
		return target{}, fmt.Errorf("cidr: %w", err)
	}
	t := target{prefix: prefix, ports: allPorts}
	if seen["ports"] {
		if len(ports) == 0 {
			return target{}, errors.New("ports is empty; leave the key out for all ports")
		}
		t.ports = nil
	}
	for _, raw := range ports {
		r, err := parsePorts(raw)
		if err != nil {
			return target{}, err
		}
		t.ports = append(t.ports, r)
	}
	return t, nil
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

// Allows reports whether the connector may connect to ip:port: no entry of deny_targets matches it,
// and one of allow_targets does.
func (p *Policy) Allows(ip netip.Addr, port uint16) bool {
	if p == nil || p.Invalid != nil {
		return false
	}
	ip = ip.Unmap()
	if p.DeniedBy(ip, port) != "" {
		return false
	}
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
		if t.matches(ip, port) {
			return true
		}
	}
	return false
}

// DeniedBy returns the entry of deny_targets that matches ip:port, with the port or range that
// matched, as a target string `rpmgr policy remove-deny-target` takes, or "".
func (p *Policy) DeniedBy(ip netip.Addr, port uint16) string {
	if p == nil {
		return ""
	}
	ip = ip.Unmap()
	for _, t := range p.denied {
		for _, r := range t.ports {
			if t.prefix.IsValid() && t.prefix.Contains(ip) && port >= r.lo && port <= r.hi {
				return t.text(r)
			}
		}
	}
	return ""
}

// AllowsUnix reports whether the connector may connect to the unix socket at path: deny_targets
// does not name it, and allow_targets does.
func (p *Policy) AllowsUnix(path string) bool {
	if p == nil || p.Invalid != nil || p.DeniedByUnix(path) != "" {
		return false
	}
	return slices.ContainsFunc(p.targets, func(t target) bool { return t.unix != "" && t.unix == path })
}

// DeniedByUnix returns path if deny_targets names the socket, else "".
func (p *Policy) DeniedByUnix(path string) string {
	if p != nil && slices.ContainsFunc(p.denied, func(t target) bool { return t.unix != "" && t.unix == path }) {
		return path
	}
	return ""
}

// BlockedError is a dial the policy refuses; it names the target, and the entry of deny_targets
// that refused it if one did, so that the route reports not_ready(blocked_by_local_policy:
// <Detail>) and the UI can show the command that would let it through.
type BlockedError struct {
	Target string
	Denied string // the deny_targets entry, "" if no allow_targets entry allows the target
}

func (e *BlockedError) Error() string {
	if e.Denied != "" {
		return "policy: the connector-local policy denies " + e.Target + " (deny_targets entry " + e.Denied + ")"
	}
	return "policy: the connector-local policy does not allow " + e.Target
}

// Detail is the readiness detail of the refused target: the target, followed by " denied by " and
// the entry of deny_targets if one refused it.
func (e *BlockedError) Detail() string {
	if e.Denied != "" {
		return e.Target + " denied by " + e.Denied
	}
	return e.Target
}

// Control returns a net.Dialer.Control that checks every connection at dial time on the resolved
// address, so a name that resolves elsewhere since, as in DNS rebinding, is still refused. current
// returns the policy in force.
func Control(current func() *Policy) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		p := current()
		if network == "unix" {
			if p.AllowsUnix(address) {
				return nil
			}
			return &BlockedError{Target: address, Denied: p.DeniedByUnix(address)}
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return &BlockedError{Target: address}
		}
		return p.blocked(ap)
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
	return p.blocked(ap)
}

// blocked returns the BlockedError for ap, or nil if the policy allows it.
func (p *Policy) blocked(ap netip.AddrPort) error {
	if p.Allows(ap.Addr(), ap.Port()) {
		return nil
	}
	return &BlockedError{Target: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(), Denied: p.DeniedBy(ap.Addr(), ap.Port())}
}

// Describe returns the policy in the form `rpmgr policy show` prints: its subnets normalised, and
// "all ports" for an entry that names none.
func (p *Policy) Describe() string {
	var b strings.Builder
	for _, list := range []struct {
		name    string
		targets []target
	}{{"allowed targets", p.targets}, {"denied targets, which win over allowed ones", p.denied}} {
		if len(list.targets) == 0 {
			fmt.Fprintf(&b, "%s: none\n", list.name)
			continue
		}
		fmt.Fprintf(&b, "%s:\n", list.name)
		for _, t := range list.targets {
			switch {
			case t.unix != "":
				fmt.Fprintf(&b, "  unix %s\n", t.unix)
			case slices.Equal(t.ports, allPorts):
				fmt.Fprintf(&b, "  %s all ports\n", t.prefix)
			default:
				ports := make([]string, 0, len(t.ports))
				for _, r := range t.ports {
					ports = append(ports, r.String())
				}
				fmt.Fprintf(&b, "  %s ports %s\n", t.prefix, strings.Join(ports, ", "))
			}
		}
	}
	fmt.Fprintf(&b, "auto_update: %s\nupdate_channel: %s\n", p.AutoUpdate, p.UpdateChannel)
	return b.String()
}
