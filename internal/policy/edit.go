// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// newFile is what AllowTarget writes when there is no policy file: the update keys always
// explicit, as the installer writes them.
const newFile = `# Connector-local policy (docs/04-security.md, "Connector-local policy"). Edit with
# "rpmgr policy allow-target" and "rpmgr policy remove-target", or by hand as root.
version: 1
allow_targets: []
auto_update: auto
update_channel: stable
`

// target is an edited target: a unix socket, or an address and a port.
type editTarget struct {
	unix string
	cidr string
	port uint16
}

// parseEditTarget reads ip:port, [ipv6]:port or an absolute socket path.
func parseEditTarget(s string) (editTarget, error) {
	if strings.HasPrefix(s, "/") {
		if filepath.Clean(s) != s {
			return editTarget{}, fmt.Errorf("policy: %q is not a clean absolute path", s)
		}
		return editTarget{unix: s}, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return editTarget{}, fmt.Errorf("policy: target %q: want <ip>:<port>, [<ipv6>]:<port> or a socket path", s)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return editTarget{}, fmt.Errorf("policy: target %q: %q is not an IP address without a zone", s, host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return editTarget{}, fmt.Errorf("policy: target %q: port %q is not in 1-65535", s, port)
	}
	ip = ip.Unmap()
	return editTarget{cidr: netip.PrefixFrom(ip, ip.BitLen()).String(), port: uint16(n)}, nil //nolint:gosec // G115: checked
}

// AllowTarget allows target, ip:port or a socket path, in the policy file at path, keeping the
// rest of the file and its comments, and reports whether the file changed. Without a file it
// writes a new one.
func AllowTarget(path, target string) (bool, error) {
	t, err := parseEditTarget(target)
	if err != nil {
		return false, err
	}
	return edit(path, func(targets *yaml.Node) (bool, error) {
		for _, e := range targets.Content {
			switch {
			case t.unix != "" && value(e, "unix") == t.unix:
				return false, nil
			case t.unix == "" && value(e, "cidr") == t.cidr:
				ports := field(e, "ports")
				for _, p := range ports.Content {
					if r, err := parsePorts(scalar(p)); err == nil && t.port >= r.lo && t.port <= r.hi {
						return false, nil
					}
				}
				ports.Content = append(ports.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(int(t.port))})
				return true, nil
			}
		}
		entry := &yaml.Node{Kind: yaml.MappingNode, Style: yaml.FlowStyle}
		if t.unix != "" {
			entry.Content = []*yaml.Node{str("unix"), str(t.unix)}
		} else {
			entry.Content = []*yaml.Node{str("cidr"), str(t.cidr), str("ports"), {Kind: yaml.SequenceNode, Style: yaml.FlowStyle,
				Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(int(t.port))}}}}
		}
		targets.Content = append(targets.Content, entry)
		targets.Style = 0 // block style once it has entries
		return true, nil
	})
}

// ErrInRange is returned by RemoveTarget for a port that only a port range allows.
var ErrInRange = errors.New("policy: the port is part of a port range; edit the file to split it")

// RemoveTarget stops allowing target, ip:port or a socket path, and reports whether the file
// changed. It removes the exact port, and an entry left without ports.
func RemoveTarget(path, target string) (bool, error) {
	t, err := parseEditTarget(target)
	if err != nil {
		return false, err
	}
	return edit(path, func(targets *yaml.Node) (bool, error) {
		changed := false
		kept := targets.Content[:0]
		for _, e := range targets.Content {
			switch {
			case t.unix != "" && value(e, "unix") == t.unix:
				changed = true
				continue
			case t.unix == "" && value(e, "cidr") == t.cidr:
				ports := field(e, "ports")
				var rest []*yaml.Node
				for _, p := range ports.Content {
					r, err := parsePorts(scalar(p))
					switch {
					case err == nil && r.lo == t.port && r.hi == t.port:
						changed = true
						continue
					case err == nil && t.port >= r.lo && t.port <= r.hi:
						return false, ErrInRange
					}
					rest = append(rest, p)
				}
				ports.Content = rest
				if len(rest) == 0 {
					continue
				}
			}
			kept = append(kept, e)
		}
		targets.Content = kept
		return changed, nil
	})
}

// edit applies change to the allow_targets of the file at path under its lock, validates the
// result and writes it atomically with mode 0644.
func edit(path string, change func(targets *yaml.Node) (bool, error)) (bool, error) {
	unlock, err := lockPolicy(path + ".lock")
	if err != nil {
		return false, err
	}
	defer unlock()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the configured policy file
	if errors.Is(err, fs.ErrNotExist) {
		data = []byte(newFile)
	} else if err != nil {
		return false, err
	}
	if _, err := Parse(data); err != nil {
		return false, fmt.Errorf("%w (fix the file first)", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return false, err
	}
	root := doc.Content[0]
	targets := field(root, "allow_targets")
	if targets == nil {
		targets = &yaml.Node{Kind: yaml.SequenceNode}
		root.Content = append(root.Content, str("allow_targets"), targets)
	}
	if targets.Kind != yaml.SequenceNode {
		return false, errors.New("policy: allow_targets is not a list")
	}
	changed, err := change(targets)
	if err != nil || !changed {
		return false, err
	}
	if len(targets.Content) == 0 {
		targets.Style = yaml.FlowStyle
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return false, err
	}
	if _, err := Parse(buf.Bytes()); err != nil {
		return false, fmt.Errorf("policy: the edit would make the file invalid: %w", err)
	}
	return true, writeFile(path, buf.Bytes())
}

// writeFile replaces path atomically with data, mode 0644.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op after the rename
	for _, step := range []func() error{
		func() error { return f.Chmod(0o644) },
		func() error { _, err := f.Write(data); return err },
		f.Sync,
	} {
		if err := step(); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path)) //nolint:gosec // G304: the policy file's directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func str(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

// field returns the value of key in the mapping m, or nil.
func field(m *yaml.Node, key string) *yaml.Node {
	if m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// value returns the scalar value of key in m, normalised for CIDRs.
func value(m *yaml.Node, key string) string {
	v := field(m, key)
	if v == nil {
		return ""
	}
	if key == "cidr" {
		if p, err := netip.ParsePrefix(v.Value); err == nil {
			return unmapPrefix(p).String()
		}
	}
	return v.Value
}

// scalar turns a port node into what parsePorts reads.
func scalar(n *yaml.Node) any {
	if n.Tag == "!!int" {
		if v, err := strconv.Atoi(n.Value); err == nil {
			return v
		}
	}
	return n.Value
}
