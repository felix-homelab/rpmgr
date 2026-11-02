// SPDX-License-Identifier: Apache-2.0

//go:build unix

package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeUfw is a ufw whose output has the format of `ufw status numbered` (sample below) and that
// records every call. ufw adds an IPv4 and an IPv6 rule for one allow, as the real one does with
// IPV6=yes.
type fakeUfw struct {
	rules     []fakeRule
	inactive  bool
	missing   bool
	failOn    string // a command whose first word matches fails: "allow" or "delete"
	calls     [][]string
	deletedBy []int
}

type fakeRule struct{ to, from, comment string }

func (f *fakeUfw) add(to, comment string) {
	f.rules = append(f.rules, fakeRule{to, "Anywhere", comment})
}

func (f *fakeUfw) Run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if f.missing {
		return nil, ErrNotInstalled
	}
	switch {
	case slices.Equal(args, []string{"status"}):
		if f.inactive {
			return []byte("Status: inactive\n"), nil
		}
		return []byte("Status: active\n"), nil
	case slices.Equal(args, []string{"status", "numbered"}):
		var b strings.Builder
		b.WriteString("Status: active\n\n     To                         Action      From\n     --                         ------      ----\n")
		for i, r := range f.rules {
			fmt.Fprintf(&b, "[%2d] %-26s ALLOW IN    %-26s", i+1, r.to, r.from)
			if r.comment != "" {
				b.WriteString(" # " + r.comment)
			}
			b.WriteString("\n")
		}
		return []byte(b.String()), nil
	case args[0] == "allow" && len(args) == 4 && args[2] == "comment":
		if f.failOn == "allow" {
			return nil, errors.New("ERROR: problem running ufw-init")
		}
		for _, r := range f.rules {
			if r.to == args[1] && r.from == "Anywhere" {
				return []byte("Skipping adding existing rule\n"), nil
			}
		}
		f.add(args[1], args[3])
		f.rules = append(f.rules, fakeRule{args[1] + " (v6)", "Anywhere (v6)", args[3]})
		return []byte("Rule added\n"), nil
	case len(args) == 3 && args[0] == "--force" && args[1] == "delete":
		if f.failOn == "delete" {
			return nil, errors.New("ERROR: could not delete")
		}
		n, _ := strconv.Atoi(args[2])
		if n < 1 || n > len(f.rules) {
			return nil, errors.New("ERROR: Could not find rule")
		}
		f.deletedBy = append(f.deletedBy, n)
		f.rules = slices.Delete(f.rules, n-1, n)
		return []byte("Rule deleted\n"), nil
	}
	return nil, fmt.Errorf("fake ufw: unexpected %v", args)
}

// allowed returns the specs of the allow calls.
func (f *fakeUfw) allowed() []string {
	var out []string
	for _, c := range f.calls {
		if c[0] == "allow" {
			out = append(out, c[1])
		}
	}
	return out
}

func (f *fakeUfw) marked() []string {
	var out []string
	for _, r := range f.rules {
		if r.comment == Marker && r.from == "Anywhere" {
			out = append(out, r.to)
		}
	}
	return out
}

func (f *fakeUfw) mutations() int {
	n := 0
	for _, c := range f.calls {
		if c[0] == "allow" || c[0] == "--force" {
			n++
		}
	}
	return n
}

const boundsOn = `{"version":1,"backend":"ufw","listeners":[{"protocol":"tcp","port":80},{"protocol":"tcp","port":443},{"protocol":"udp","port":443}],"max_range":{"from":20000,"to":29999}}`

type env struct {
	t   *testing.T
	dir string
	a   *Applier
	u   *fakeUfw
}

// testUID is the uid of the test process, as the helper's root.
func testUID() uint32 {
	return uint32(os.Getuid()) //nolint:gosec // G115: a uid is never negative
}

func newEnv(t *testing.T, bounds string) *env {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc") // the umask of the test host decides the mode of a TempDir
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the fixture directory must be traversable, like root's /etc
		t.Fatal(err)
	}
	// The directories above the test's own are not root's; they pass as if they were.
	old := lstat
	lstat = func(p string) (os.FileInfo, error) {
		fi, err := old(p)
		if err == nil && p != dir && strings.HasPrefix(dir, strings.TrimSuffix(p, "/")+"/") {
			return fakeDir{fi, testUID(), 0o755}, nil
		}
		return fi, err
	}
	t.Cleanup(func() { lstat = old })
	e := &env{t: t, dir: dir, u: &fakeUfw{}}
	e.a = &Applier{Desired: filepath.Join(dir, "desired.json"), Bounds: filepath.Join(dir, "firewall.json"),
		StatusFile: filepath.Join(dir, "run", "status.json"), Ufw: e.u, RootUID: testUID(),
		Now: func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC) }}
	if bounds != "" {
		e.write("firewall.json", bounds, 0o644)
	}
	return e
}

// fakeDir is a directory with another owner and mode than the real one.
type fakeDir struct {
	os.FileInfo
	uid  uint32
	perm os.FileMode
}

func (d fakeDir) Mode() os.FileMode { return os.ModeDir | d.perm }
func (d fakeDir) Sys() any {
	st := *d.FileInfo.Sys().(*syscall.Stat_t)
	st.Uid = d.uid
	return &st
}

// ancestor makes dir, above the test's directory, look owned by uid with the mode perm.
func (e *env) ancestor(dir string, uid uint32, perm os.FileMode) {
	prev := lstat
	lstat = func(p string) (os.FileInfo, error) {
		fi, err := prev(p)
		if err == nil && p == dir {
			return fakeDir{fi, uid, perm}, nil
		}
		return fi, err
	}
	e.t.Cleanup(func() { lstat = prev })
}

func (e *env) write(name, content string, mode os.FileMode) {
	e.t.Helper()
	p := filepath.Join(e.dir, name)
	_ = os.Remove(p)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) desired(ranges ...string) {
	e.write("desired.json", `{"version":1,"ranges":[`+strings.Join(ranges, ",")+`]}`, 0o644)
}

func (e *env) apply() Status {
	e.t.Helper()
	st, _ := e.a.Apply(context.Background())
	return st
}

func rng(proto string, from, to int) string {
	return fmt.Sprintf(`{"protocol":%q,"from":%d,"to":%d}`, proto, from, to)
}

// TestParseRules reads a sample of `ufw status numbered` in the format of ufw 0.36 [V]: IPv4 and
// IPv6 rules, rules of the operator's, one with another comment, one that only contains the marker.
func TestParseRules(t *testing.T) {
	const sample = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    Anywhere                   # rpmgr
[ 3] 20000:20999/tcp            ALLOW IN    Anywhere                   # rpmgr
[ 4] 5353/udp                   DENY IN     192.168.1.0/24             # lan, not rpmgr
[ 5] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 6] 20000:20999/tcp (v6)       ALLOW IN    Anywhere (v6)              # rpmgr
[ 7] 443/tcp                    ALLOW IN    Anywhere                   # rpmgr-old
[ 8] 8080/tcp                   ALLOW IN    Anywhere                   # rpmgr # mine
[10] 443/udp                    ALLOW IN    Anywhere                   # rpmgr
`
	rules := parseRules([]byte(sample))
	if len(rules) != 9 {
		t.Fatalf("parsed %d rules, want 9: %+v", len(rules), rules)
	}
	for _, tc := range []struct {
		i     int
		to    string
		v6    bool
		owned bool
	}{{0, "22/tcp", false, false}, {1, "80/tcp", false, true}, {2, "20000:20999/tcp", false, true}, {3, "5353/udp", false, false},
		{4, "22/tcp", true, false}, {5, "20000:20999/tcp", true, true}, {6, "443/tcp", false, false}, {7, "8080/tcp", false, false}, {8, "443/udp", false, true}} {
		if r := rules[tc.i]; r.To != tc.to || r.V6 != tc.v6 || r.owned() != tc.owned {
			t.Errorf("rule %d = %+v, want to %q v6 %v owned %v", tc.i, r, tc.to, tc.v6, tc.owned)
		}
	}
	if rules[8].Number != 10 || rules[3].Action != "DENY IN" || rules[3].From != "192.168.1.0/24" {
		t.Errorf("number, action or from misread: %+v %+v", rules[8], rules[3])
	}
	if got := parseRules([]byte("Status: inactive\n")); len(got) != 0 {
		t.Errorf("an inactive ufw has rules: %+v", got)
	}
}

func TestApplyHappyPathAndStatusFile(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.desired(rng("tcp", 20000, 20999), rng("udp", 25000, 25000))
	st := e.apply()
	want := []string{"80/tcp", "443/tcp", "20000:20999/tcp", "443/udp", "25000/udp"}
	if st.State != Applied || !slices.Equal(st.Rules, want) {
		t.Fatalf("status = %+v, want applied with %v", st, want)
	}
	if got := e.u.marked(); !slices.Equal(got, want) {
		t.Errorf("ufw holds %v", got)
	}
	read, err := ReadStatus(e.a.StatusFile)
	if err != nil || read.State != Applied || read.At.IsZero() {
		t.Errorf("status file = %+v, %v", read, err)
	}
	if fi, err := os.Stat(e.a.StatusFile); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("status file mode: %v %v", fi, err)
	}
}

// TestFirewall_OnlyBoundedPortsOpened: whatever the desired file says, no allow is run for a port
// outside the listeners and the maximum range, and a file that is not valid changes nothing.
func TestFirewall_OnlyBoundedPortsOpened(t *testing.T) {
	inside := func(spec string) bool {
		port, proto, _ := strings.Cut(spec, "/")
		from, to, _ := strings.Cut(port, ":")
		if to == "" {
			to = from
		}
		f, _ := strconv.Atoi(from)
		l, _ := strconv.Atoi(to)
		return (f == l && f == 80 && proto == "tcp") || (f == l && f == 443) || (f >= 20000 && l <= 29999)
	}
	for _, tc := range []struct {
		name, file  string
		refusedFile bool   // the whole file is refused, no rule is added
		refused     string // the ports reported as outside
	}{
		{"ssh", `{"version":1,"ranges":[` + rng("tcp", 22, 22) + `]}`, false, "22/tcp"},
		{"straddles the top", `{"version":1,"ranges":[` + rng("tcp", 29000, 30500) + `]}`, false, "30000:30500/tcp"},
		{"straddles the bottom", `{"version":1,"ranges":[` + rng("udp", 100, 20010) + `]}`, false, "100:442/udp, 444:19999/udp"},
		{"everything", `{"version":1,"ranges":[` + rng("tcp", 1, 65535) + `]}`, false, "1:79/tcp, 81:442/tcp, 444:19999/tcp, 30000:65535/tcp"},
		{"port 0", `{"version":1,"ranges":[` + rng("tcp", 0, 10) + `]}`, true, ""},
		{"overflowing port", `{"version":1,"ranges":[{"protocol":"tcp","from":20000,"to":99999999999}]}`, true, ""},
		{"negative port", `{"version":1,"ranges":[{"protocol":"tcp","from":-1,"to":20000}]}`, true, ""},
		{"port 65536", `{"version":1,"ranges":[` + rng("tcp", 65000, 65536) + `]}`, true, ""},
		{"reversed", `{"version":1,"ranges":[` + rng("tcp", 21000, 20000) + `]}`, true, ""},
		{"icmp", `{"version":1,"ranges":[` + rng("icmp", 20000, 20010) + `]}`, true, ""},
		{"empty protocol", `{"version":1,"ranges":[` + rng("", 20000, 20010) + `]}`, true, ""},
		{"a rule text as protocol", `{"version":1,"ranges":[{"protocol":"tcp from 1.2.3.4","from":20000,"to":20001}]}`, true, ""},
		{"unknown field", `{"version":1,"ranges":[],"extra":true}`, true, ""},
		{"a field of a range", `{"version":1,"ranges":[{"protocol":"tcp","from":20000,"to":20001,"comment":"x"}]}`, true, ""},
		{"second value", `{"version":1,"ranges":[]} {"version":1,"ranges":[]}`, true, ""},
		{"wrong version", `{"version":2,"ranges":[]}`, true, ""},
		{"malformed", `{"version":1,"ranges":[`, true, ""},
		{"not json", "allow 22/tcp\n", true, ""},
		{"empty file", "", true, ""},
		{"ports as strings", `{"version":1,"ranges":[{"protocol":"tcp","from":"22","to":"22"}]}`, true, ""},
		{"too many ranges", `{"version":1,"ranges":[` + strings.TrimSuffix(strings.Repeat(rng("tcp", 20000, 20000)+",", MaxRanges+1), ",") + `]}`, true, ""},
		{"oversized", `{"version":1,"ranges":[],"pad":"` + strings.Repeat("x", MaxDesired) + `"}`, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, boundsOn)
			e.u.add("22/tcp", "")
			e.write("desired.json", tc.file, 0o644)
			st := e.apply()
			if st.State != Failed {
				t.Errorf("state = %q, want failed: %+v", st.State, st)
			}
			for _, a := range e.u.allowed() {
				if !inside(a) {
					t.Errorf("allow %s runs outside the bounds", a)
				}
			}
			if tc.refusedFile && e.u.mutations() != 0 {
				t.Errorf("a refused file changed rules: %v", e.u.calls)
			}
			if !tc.refusedFile {
				if got := strings.Join(st.Refused, ", "); got != tc.refused {
					t.Errorf("refused = %q, want %q", got, tc.refused)
				}
				if !slices.Contains(st.Rules, "80/tcp") {
					t.Errorf("the inside part was not applied: %v", st.Rules)
				}
			}
			if slices.Contains(e.u.marked(), "22/tcp") {
				t.Error("22/tcp was opened by rpmgr")
			}
		})
	}
}

func TestClampKeepsTheInsidePartOfARange(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.desired(rng("tcp", 29990, 30010))
	st := e.apply()
	if st.State != Failed || !slices.Contains(st.Rules, "29990:29999/tcp") || !slices.Equal(st.Refused, []string{"30000:30010/tcp"}) {
		t.Errorf("status = %+v", st)
	}
	if !strings.Contains(st.Reason, "never opened") {
		t.Errorf("reason = %q", st.Reason)
	}
}

func TestOverlappingAndAdjacentRangesMerge(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.desired(rng("tcp", 20000, 20099), rng("tcp", 20100, 20199), rng("tcp", 20150, 20300), rng("tcp", 20500, 20500), rng("tcp", 20500, 20500),
		rng("udp", 20000, 20010), rng("tcp", 80, 80), rng("tcp", 443, 443))
	st := e.apply()
	want := []string{"80/tcp", "443/tcp", "20000:20300/tcp", "20500/tcp", "443/udp", "20000:20010/udp"}
	if st.State != Applied || !slices.Equal(st.Rules, want) {
		t.Errorf("status = %+v, want %v", st, want)
	}
	// A port range of a pool that includes a listener's port still opens the listener once.
	e = newEnv(t, `{"version":1,"backend":"ufw","listeners":[{"protocol":"tcp","port":20000}],"max_range":{"from":20001,"to":20100}}`)
	e.desired(rng("tcp", 20000, 20100))
	if st := e.apply(); st.State != Applied || !slices.Equal(st.Rules, []string{"20000:20100/tcp"}) {
		t.Errorf("a listener next to the pool: %+v", st)
	}
}

func TestNoMaximumRangeOpensOnlyTheListeners(t *testing.T) {
	e := newEnv(t, `{"version":1,"backend":"ufw","listeners":[{"protocol":"tcp","port":443}]}`)
	e.desired(rng("tcp", 20000, 20010))
	st := e.apply()
	if st.State != Failed || !slices.Equal(st.Rules, []string{"443/tcp"}) || !slices.Equal(st.Refused, []string{"20000:20010/tcp"}) {
		t.Errorf("status = %+v", st)
	}
}

func TestMissingDesiredFileOpensTheListeners(t *testing.T) {
	e := newEnv(t, boundsOn)
	if st := e.apply(); st.State != Applied || !slices.Equal(st.Rules, []string{"80/tcp", "443/tcp", "443/udp"}) {
		t.Errorf("status = %+v", st)
	}
}

// TestFirewall_BoundsFileMustBeRootOwned: a bounds file another user owns, that group or others
// may write, in such a directory, or that is a link or no file, runs no ufw command.
func TestFirewall_BoundsFileMustBeRootOwned(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(e *env)
		want   string
	}{
		{"another owner", func(e *env) { e.a.RootUID++ }, "not owned by root"},
		{"group writable", func(e *env) { e.write("firewall.json", boundsOn, 0o664) }, "written by its group or others"},
		{"world writable", func(e *env) { e.write("firewall.json", boundsOn, 0o666) }, "written by its group or others"},
		{"world writable directory", func(e *env) { _ = os.Chmod(e.dir, 0o777) }, //nolint:gosec // G302: the case under test is a world-writable directory
			"written by its group or others"},
		{"an ancestor of another owner", func(e *env) { e.ancestor(filepath.Dir(e.dir), testUID()+1, 0o755) }, "not owned by root"},
		{"a world-writable ancestor", func(e *env) { e.ancestor(filepath.Dir(e.dir), testUID(), 0o777) }, "written by its group or others"},
		{"a sticky world-writable ancestor", func(e *env) { e.ancestor(filepath.Dir(e.dir), testUID(), 0o777|os.ModeSticky) }, "written by its group or others"},
		{"a group-writable ancestor near the top", func(e *env) { e.ancestor(filepath.Dir(filepath.Dir(e.dir)), testUID(), 0o775) }, "written by its group or others"},
		{"a link", func(e *env) {
			e.write("real.json", boundsOn, 0o644)
			_ = os.Remove(e.a.Bounds)
			if err := os.Symlink(filepath.Join(e.dir, "real.json"), e.a.Bounds); err != nil {
				t.Fatal(err)
			}
		}, "firewall.json"},
		{"a directory", func(e *env) { _ = os.Remove(e.a.Bounds); _ = os.Mkdir(e.a.Bounds, 0o755) }, "no regular file"},
		{"too large", func(e *env) { e.write("firewall.json", boundsOn+strings.Repeat(" ", MaxBounds), 0o644) }, "more than"},
		{"malformed", func(e *env) { e.write("firewall.json", "{", 0o644) }, "refused"},
		{"unknown backend", func(e *env) { e.write("firewall.json", `{"version":1,"backend":"nft"}`, 0o644) }, "backend"},
		{"bad listener", func(e *env) {
			e.write("firewall.json", `{"version":1,"backend":"ufw","listeners":[{"protocol":"tcp","port":0}]}`, 0o644)
		}, "listener"},
		{"bad maximum range", func(e *env) {
			e.write("firewall.json", `{"version":1,"backend":"ufw","max_range":{"from":1,"to":70000}}`, 0o644)
		}, "max_range"},
		{"an unknown field", func(e *env) { e.write("firewall.json", `{"version":1,"backend":"ufw","allow":["22/tcp"]}`, 0o644) }, "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, boundsOn)
			e.desired(rng("tcp", 20000, 20010))
			e.u.add("22/tcp", "")
			e.u.add("80/tcp", Marker)
			tc.break_(e)
			st := e.apply()
			if st.State != Failed || !strings.Contains(st.Reason, tc.want) || !strings.Contains(st.Reason, "nothing was changed") {
				t.Errorf("status = %+v, want failed with %q", st, tc.want)
			}
			if len(e.u.calls) != 0 {
				t.Errorf("ufw ran: %v", e.u.calls)
			}
		})
	}
}

// TestFirewall_OnlyOwnRulesTouched: only rules that carry exactly the marker are deleted, by
// number and highest first; the operator's, also for a port rpmgr opens, and those that only
// contain the marker stay through a run, a failing run and a switch-off.
func TestFirewall_OnlyOwnRulesTouched(t *testing.T) {
	setup := func(t *testing.T, bounds string) *env {
		e := newEnv(t, bounds)
		e.u.add("22/tcp", "")
		e.u.add("20000:20199/tcp", "mine")
		e.u.add("5000/tcp", Marker+"-old")
		e.u.add("5001/tcp", "not "+Marker)
		e.u.add("9999/tcp", Marker) // stale of ours
		e.u.rules = append(e.u.rules, fakeRule{"9999/tcp (v6)", "Anywhere (v6)", Marker})
		e.u.add("3000/udp", Marker)
		return e
	}
	others := func(e *env) []string {
		var out []string
		for _, r := range e.u.rules {
			if r.comment != Marker {
				out = append(out, r.to+"|"+r.comment)
			}
		}
		return out
	}
	t.Run("a run", func(t *testing.T) {
		e := setup(t, boundsOn)
		before := others(e)
		e.desired(rng("tcp", 20000, 20099)) // the operator's rule is for a wider range: ours is added beside it
		if st := e.apply(); st.State != Applied {
			t.Fatalf("status = %+v", st)
		}
		if got := others(e); !slices.Equal(got, before) {
			t.Errorf("rules of others changed: %v, was %v", got, before)
		}
		if got := e.u.marked(); !slices.Equal(got, []string{"80/tcp", "443/tcp", "20000:20099/tcp", "443/udp"}) {
			t.Errorf("own rules = %v", got)
		}
		if !slices.IsSortedFunc(e.u.deletedBy, func(a, b int) int { return b - a }) {
			t.Errorf("rules were not deleted highest number first: %v", e.u.deletedBy)
		}
	})
	t.Run("a failing delete", func(t *testing.T) {
		e := setup(t, boundsOn)
		before := others(e)
		e.u.failOn = "delete"
		e.desired()
		if st := e.apply(); st.State != Failed || !strings.Contains(st.Reason, "could not delete") {
			t.Errorf("status = %+v", st)
		}
		if got := others(e); !slices.Equal(got, before) {
			t.Errorf("rules of others changed: %v", got)
		}
	})
	for name, bounds := range map[string]string{"backend off": `{"version":1,"backend":"off"}`, "backend empty": `{"version":1,"backend":""}`, "no file": ""} {
		t.Run("switch-off, "+name, func(t *testing.T) {
			e := setup(t, bounds)
			before := others(e)
			e.desired(rng("tcp", 20000, 20010))
			st := e.apply()
			if st.State != Off || !strings.Contains(st.Reason, "removed") {
				t.Errorf("status = %+v", st)
			}
			if got := e.u.marked(); len(got) != 0 {
				t.Errorf("own rules remain: %v", got)
			}
			if got := others(e); !slices.Equal(got, before) {
				t.Errorf("rules of others changed: %v, was %v", got, before)
			}
			if len(e.u.allowed()) != 0 {
				t.Errorf("a switched-off helper opened %v", e.u.allowed())
			}
		})
	}
}

func TestRemovalDeletesHighestNumberFirst(t *testing.T) {
	e := newEnv(t, `{"version":1,"backend":"off"}`)
	for _, to := range []string{"1000/tcp", "1001/tcp", "1002/tcp"} {
		e.u.add(to, Marker)
		e.u.add("22/tcp", "")
	}
	e.apply()
	if !slices.Equal(e.u.deletedBy, []int{5, 3, 1}) {
		t.Errorf("deleted %v, want 5, 3, 1", e.u.deletedBy)
	}
}

func TestResizeAddsBeforeItDeletes(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.desired(rng("tcp", 20000, 20099))
	e.apply()
	e.desired(rng("tcp", 20000, 20199))
	e.u.calls = nil
	if st := e.apply(); st.State != Applied {
		t.Fatalf("status = %+v", st)
	}
	var kinds []string
	for _, c := range e.u.calls {
		if c[0] == "allow" || c[0] == "--force" {
			kinds = append(kinds, c[0])
		}
	}
	if !slices.Equal(kinds, []string{"allow", "--force", "--force"}) { // the old rule has an IPv4 and an IPv6 line
		t.Errorf("order = %v", kinds)
	}
	if got := e.u.marked(); !slices.Contains(got, "20000:20199/tcp") || slices.Contains(got, "20000:20099/tcp") {
		t.Errorf("rules = %v", got)
	}
}

func TestApplyingTwiceChangesNothing(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.desired(rng("tcp", 20000, 20999), rng("udp", 21000, 21010))
	first := e.apply()
	e.u.calls = nil
	rules := slices.Clone(e.u.rules)
	second := e.apply()
	if e.u.mutations() != 0 {
		t.Errorf("the second run changed rules: %v", e.u.calls)
	}
	if !slices.Equal(e.u.rules, rules) || first.State != Applied || second.State != Applied || !slices.Equal(first.Rules, second.Rules) {
		t.Errorf("first %+v, second %+v", first, second)
	}
}

func TestUfwMissing(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.u.missing = true
	st, err := e.a.Apply(context.Background())
	if err == nil || st.State != Failed || !strings.Contains(st.Reason, "not installed") || !strings.Contains(st.Reason, "nothing was changed") {
		t.Errorf("switched on: %+v, %v", st, err)
	}
	if read, err := ReadStatus(e.a.StatusFile); err != nil || read.State != Failed {
		t.Errorf("status file: %+v, %v", read, err)
	}
	e = newEnv(t, `{"version":1,"backend":"off"}`)
	e.u.missing = true
	if st, err := e.a.Apply(context.Background()); err != nil || st.State != Off {
		t.Errorf("switched off: %+v, %v", st, err)
	}
}

func TestUfwInactive(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.u.inactive = true
	e.desired(rng("tcp", 20000, 20010))
	st := e.apply()
	if st.State != Failed || !strings.Contains(st.Reason, "inactive") || e.u.mutations() != 0 {
		t.Errorf("status = %+v, calls %v", st, e.u.calls)
	}
	e = newEnv(t, `{"version":1,"backend":"off"}`)
	e.u.inactive = true
	e.u.add("80/tcp", Marker)
	if st := e.apply(); st.State != Off || e.u.mutations() != 0 {
		t.Errorf("switched off and inactive: %+v", st)
	}
}

func TestUfwCommandFailing(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.u.failOn = "allow"
	e.desired(rng("tcp", 20000, 20010))
	st, err := e.a.Apply(context.Background())
	if err == nil || st.State != Failed || !strings.Contains(st.Reason, "problem running ufw-init") || len(st.Rules) != 0 {
		t.Errorf("status = %+v, %v", st, err)
	}
	// A run after the failure is gone finishes the job.
	e.u.failOn = ""
	if st := e.apply(); st.State != Applied {
		t.Errorf("after the failure: %+v", st)
	}
}

func TestUfwOutputThatIsNoStatus(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.a.Ufw = outputRunner("ERROR: you need to be root\n")
	if st := e.apply(); st.State != Failed || !strings.Contains(st.Reason, "unexpected output") {
		t.Errorf("status = %+v", st)
	}
}

type outputRunner string

func (o outputRunner) Run(context.Context, ...string) ([]byte, error) { return []byte(o), nil }

func TestOperatorRuleWithoutTheMarkerIsNotOurs(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.u.add("443/tcp", "") // the operator's own, for a port we open
	e.desired()
	e.apply()
	if !slices.Contains(e.u.marked(), "80/tcp") {
		t.Errorf("rules = %v", e.u.rules)
	}
	// ufw skipped our identical rule; the operator's survives our switch-off.
	e.write("firewall.json", `{"version":1,"backend":"off"}`, 0o644)
	e.apply()
	if !slices.ContainsFunc(e.u.rules, func(r fakeRule) bool { return r.to == "443/tcp" && r.comment == "" }) {
		t.Errorf("the operator's rule was deleted: %v", e.u.rules)
	}
}

func TestRepeatedOwnRuleIsDeletedOnce(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.desired()
	e.apply()
	e.u.add("80/tcp", Marker) // a repeat of ours
	e.u.calls = nil
	e.apply()
	if n := strings.Count(strings.Join(e.u.marked(), " "), "80/tcp"); n != 1 {
		t.Errorf("80/tcp held %d times: %v", n, e.u.marked())
	}
}

func TestStatusIsNotWrittenThroughALink(t *testing.T) {
	e := newEnv(t, boundsOn)
	target := filepath.Join(e.dir, "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(e.a.StatusFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, e.a.StatusFile); err != nil {
		t.Fatal(err)
	}
	e.apply()
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("the status was written through a link: %q", b)
	}
}

func TestDesiredFileThatIsALinkIsRefused(t *testing.T) {
	e := newEnv(t, boundsOn)
	e.write("real.json", `{"version":1,"ranges":[]}`, 0o644)
	if err := os.Symlink(filepath.Join(e.dir, "real.json"), e.a.Desired); err != nil {
		t.Fatal(err)
	}
	if st := e.apply(); st.State != Failed || e.u.mutations() != 0 {
		t.Errorf("status = %+v", st)
	}
}
