// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// newFile is what AllowTarget and DenyTarget write when there is no policy file: the update keys
// always explicit, as the installer writes them.
const newFile = `# Connector-local policy (docs/04-security.md, "Connector-local policy"). Edit with
# "rpmgr policy allow-target", "deny-target" and their "remove-" forms, or by hand as root.
version: 1
allow_targets: []
deny_targets: []
auto_update: auto
update_channel: stable
`

// CheckTarget checks a target in the syntax AllowTarget and DenyTarget read: an address or subnet
// with an optional port or port range, or a clean absolute socket path.
func CheckTarget(target string) error {
	_, err := parseTarget(target)
	return err
}

// AllowTarget allows target in the policy file at path, keeping the rest of the file and its
// comments, and reports whether the file changed. Without a file it writes a new one.
func AllowTarget(path, target string) (bool, error) { return addTarget(path, "allow_targets", target) }

// DenyTarget denies target in deny_targets, which wins over allow_targets (D84).
func DenyTarget(path, target string) (bool, error) { return addTarget(path, "deny_targets", target) }

// RemoveTarget stops allowing target and reports whether the file changed.
func RemoveTarget(path, target string) (bool, error) {
	return removeTarget(path, "allow_targets", target)
}

// RemoveDenyTarget stops denying target and reports whether the file changed.
func RemoveDenyTarget(path, target string) (bool, error) {
	return removeTarget(path, "deny_targets", target)
}

// addTarget adds target to the list key, unless an entry covers it already. Ports go to the
// mapping entry of the same subnet, if there is one; a target of all ports makes it one.
func addTarget(path, key, s string) (bool, error) {
	t, err := parseTarget(s)
	if err != nil {
		return false, err
	}
	return edit(path, key, func(targets *yaml.Node) (bool, error) {
		for _, e := range targets.Content {
			if et, err := parseEntry(e); err == nil && covers(et, t, key == "allow_targets") {
				return false, nil
			}
		}
		for _, e := range targets.Content {
			if t.unix != "" || e.Kind != yaml.MappingNode || field(e, "unix") != nil {
				continue
			}
			if p, err := parseHost(value(e, "cidr")); err != nil || p != t.prefix {
				continue
			}
			if ports := field(e, "ports"); ports != nil && !slices.Equal(t.ports, allPorts) {
				ports.Content = append(ports.Content, portNode(t.ports[0]))
				return true, nil
			}
			e.Content = withoutKey(e.Content, "ports") // all ports
			return true, nil
		}
		entry := &yaml.Node{Kind: yaml.MappingNode, Style: yaml.FlowStyle}
		if t.unix != "" {
			entry.Content = []*yaml.Node{str("unix"), str(t.unix)}
		} else {
			entry.Content = []*yaml.Node{str("cidr"), str(t.prefix.String())}
			if !slices.Equal(t.ports, allPorts) {
				entry.Content = append(entry.Content, str("ports"), &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle,
					Content: []*yaml.Node{portNode(t.ports[0])}})
			}
		}
		targets.Content = append(targets.Content, entry)
		targets.Style = 0 // block style once it has entries
		return true, nil
	})
}

// covers reports whether entry e takes in all of t: the same socket, or a subnet that holds t's
// and port ranges that each hold one of t's. For allow_targets, a broad subnet does not cover a
// target in a protected range, as Allows does not let it through.
func covers(e, t target, allow bool) bool {
	if e.unix != "" || t.unix != "" {
		return e.unix == t.unix
	}
	if e.prefix.Bits() > t.prefix.Bits() || !e.prefix.Contains(t.prefix.Addr()) {
		return false
	}
	if allow {
		for _, r := range protected {
			if r.Overlaps(t.prefix) && (e.prefix.Bits() < r.Bits() || !r.Contains(e.prefix.Addr())) {
				return false
			}
		}
	}
	return !slices.ContainsFunc(t.ports, func(tr portRange) bool {
		return !slices.ContainsFunc(e.ports, func(er portRange) bool { return tr.lo >= er.lo && tr.hi <= er.hi })
	})
}

func portNode(r portRange) *yaml.Node {
	if r.lo == r.hi {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(int(r.lo))}
	}
	return str(r.String())
}

// withoutKey returns the content of a mapping without key and its value.
func withoutKey(content []*yaml.Node, key string) []*yaml.Node {
	out := make([]*yaml.Node, 0, len(content))
	for i := 0; i+1 < len(content); i += 2 {
		if content[i].Value != key {
			out = append(out, content[i], content[i+1])
		}
	}
	return out
}

// ErrInRange is returned when removing a target that only a broader entry or a port range takes
// in, which an edit cannot split.
var ErrInRange = errors.New("policy: the target is part of a broader entry or port range; " +
	"deny it with `rpmgr policy deny-target`, or edit the file to split the entry")

// removeTarget removes target from the list key and reports whether the file changed: an entry of
// exactly that socket, subnet and ports, or that port or range of an entry of the subnet, and an
// entry left without ports. A target of all ports removes every entry of its subnet.
func removeTarget(path, key, s string) (bool, error) {
	t, err := parseTarget(s)
	if err != nil {
		return false, err
	}
	all := slices.Equal(t.ports, allPorts)
	return edit(path, key, func(targets *yaml.Node) (bool, error) {
		changed, covered := false, false
		kept := targets.Content[:0]
		for _, e := range targets.Content {
			et, err := parseEntry(e)
			switch {
			case err != nil:
			case t.unix != "" || et.unix != "":
				if et.unix == t.unix {
					changed = true
					continue
				}
			case et.prefix == t.prefix && (all || slices.Equal(et.ports, t.ports)):
				changed = true
				continue
			case et.prefix == t.prefix && e.Kind == yaml.MappingNode && field(e, "ports") != nil:
				ports := field(e, "ports")
				rest := slices.DeleteFunc(slices.Clone(ports.Content), func(n *yaml.Node) bool {
					r, err := parsePorts(scalar(n))
					return err == nil && r == t.ports[0]
				})
				if len(rest) < len(ports.Content) {
					changed = true
					if ports.Content = rest; len(rest) == 0 {
						continue
					}
				} else {
					covered = covered || covers(et, t, false)
				}
			default:
				covered = covered || covers(et, t, false)
			}
			kept = append(kept, e)
		}
		targets.Content = kept
		if !changed && covered {
			return false, ErrInRange
		}
		return changed, nil
	})
}

// edit applies change to the list key, allow_targets or deny_targets, of the file at path under
// its lock, validates the result and writes it atomically with mode 0644.
func edit(path, key string, change func(targets *yaml.Node) (bool, error)) (bool, error) {
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
	targets := field(root, key)
	if targets == nil {
		targets = &yaml.Node{Kind: yaml.SequenceNode}
		root.Content = append(root.Content, str(key), targets)
	}
	if targets.Kind != yaml.SequenceNode {
		return false, fmt.Errorf("policy: %s is not a list", key)
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
