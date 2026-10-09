// SPDX-License-Identifier: Apache-2.0

package totp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/totp"
)

// rfcSeed is the SHA-1 seed of RFC 6238, appendix B.
var rfcSeed = []byte("12345678901234567890")

// TestCode_RFC6238: the SHA-1 test vectors of RFC 6238, appendix B, in their last 6 digits, which
// are the 6-digit codes of the same steps.
func TestCode_RFC6238(t *testing.T) {
	for unix, want := range map[int64]string{
		59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924",
		2000000000: "279037", 20000000000: "353130",
	} {
		if got := totp.Code(rfcSeed, totp.StepOf(time.Unix(unix, 0))); got != want {
			t.Errorf("T=%d: %s, want %s", unix, got, want)
		}
	}
}

// TestVerify: codes of the current step and one step either side pass, two steps do not; a code
// of a step not later than the last one used never passes again; malformed codes fail.
func TestVerify(t *testing.T) {
	now := time.Unix(1_800_000_015, 0)
	cur := totp.StepOf(now)
	for d, ok := range map[int64]bool{-2: false, -1: true, 0: true, 1: true, 2: false} {
		step, got := totp.Verify(rfcSeed, totp.Code(rfcSeed, cur+d), now, 0)
		if got != ok || ok && step != cur+d {
			t.Errorf("%+d steps: %v at %d", d, got, step)
		}
	}
	code := totp.Code(rfcSeed, cur)
	step, ok := totp.Verify(rfcSeed, code, now, 0)
	if !ok {
		t.Fatal("the current code")
	}
	if _, ok := totp.Verify(rfcSeed, code, now, step); ok {
		t.Fatal("a code replayed in its step")
	}
	if _, ok := totp.Verify(rfcSeed, totp.Code(rfcSeed, cur-1), now, step); ok {
		t.Fatal("an older code after a newer one")
	}
	if _, ok := totp.Verify(rfcSeed, totp.Code(rfcSeed, cur+1), now, step); !ok {
		t.Fatal("the next step's code after the current one")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", " " + code[1:]} {
		if _, ok := totp.Verify(rfcSeed, bad, now, 0); ok {
			t.Errorf("%q passed", bad)
		}
	}
	other, _ := totp.NewSecret()
	if _, ok := totp.Verify(other, code, now, 0); ok {
		t.Fatal("another secret's code")
	}
}

// TestURI: the otpauth URI carries the base32 secret and the parameters authenticator apps need.
func TestURI(t *testing.T) {
	s, err := totp.NewSecret()
	if err != nil || len(s) != totp.SecretSize {
		t.Fatalf("%x %v", s, err)
	}
	u := totp.URI(rfcSeed, "rpmgr panel.example.com", "ada@example.com")
	for _, want := range []string{"otpauth://totp/rpmgr%20panel.example.com:ada@example.com?", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		"algorithm=SHA1", "digits=6", "period=30", "issuer=rpmgr+panel.example.com"} {
		if !strings.Contains(u, want) {
			t.Errorf("%s lacks %s", u, want)
		}
	}
}
