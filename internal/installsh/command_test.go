// SPDX-License-Identifier: Apache-2.0

package installsh_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/installsh"
)

// TestQuote: a shell reads back exactly what was quoted, quotes, spaces, globs, variables and
// command substitutions included.
func TestQuote(t *testing.T) {
	for _, s := range []string{"", "plain", "it's", "''", "a b", "$HOME", "`id`", "$(id)", "*", "back\\slash", "a'b'c", "\"double\""} {
		out, err := exec.Command("/bin/sh", "-c", "printf '%s' "+installsh.Quote(s)).Output()
		if err != nil || string(out) != s {
			t.Errorf("%q came back as %q: %v", s, out, err)
		}
	}
}

// TestCommand runs the install command with a curl and a sudo that record their arguments: curl
// downloads the script into the current directory, and sudo runs that file, so that its standard
// input stays the terminal (sudo-rs passes typed input on only then); a failed download runs
// nothing. A gateway's command takes no targets, and a target that is not one is refused.
func TestCommand(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{
		"curl": `echo "curl $*" >>calls; [ -z "$CURL_FAILS" ] || exit 22; echo 'echo script' >install.sh`,
		"sudo": `echo "sudo $*" >>calls`,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil { //nolint:gosec // G306: a test's stub
			t.Fatal(err)
		}
	}
	run := func(cmd string, env ...string) (string, error) {
		dir := t.TempDir()
		c := exec.Command("/bin/sh", "-c", cmd)
		c.Dir, c.Env = dir, append([]string{"PATH=" + bin + ":/usr/bin:/bin"}, env...)
		err := c.Run()
		calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return string(calls), err
	}

	cmd, err := installsh.Command("https://panel.example.com/", "sha256:3q2+7w==", false, []string{"10.0.0.5:5432", "/run/a b.sock"})
	if err != nil {
		t.Fatal(err)
	}
	calls, err := run(cmd)
	want := "curl -fsSLO https://panel.example.com/install.sh\n" +
		"sudo sh install.sh --controller https://panel.example.com --ca-pin sha256:3q2+7w== --allow-target 10.0.0.5:5432 --allow-target /run/a b.sock\n"
	if err != nil || calls != want {
		t.Fatalf("calls:\n%s\nwant:\n%s(%v)", calls, want, err)
	}
	if calls, err := run(cmd, "CURL_FAILS=1"); err == nil || strings.Contains(calls, "sudo") {
		t.Fatalf("a failed download: %v\n%s", err, calls)
	}

	gw, err := installsh.Command("https://panel.example.com", "sha256:3q2+7w==", true, nil)
	if err != nil || !strings.HasSuffix(gw, " \\\n  --role gateway") {
		t.Fatalf("a gateway's command:\n%s\n%v", gw, err)
	}
	if _, err := installsh.Command("https://panel.example.com", "sha256:3q2+7w==", true, []string{"10.0.0.5:5432"}); err == nil {
		t.Fatal("a gateway took a target")
	}
	for _, tg := range []string{"10.0.0.5", "/run/a'b.sock", "/run/a\nb.sock"} {
		if _, err := installsh.Command("https://panel.example.com", "sha256:3q2+7w==", false, []string{tg}); err == nil {
			t.Errorf("the target %q was taken", tg)
		}
	}
}
