// SPDX-License-Identifier: Apache-2.0

package headermatch_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/headermatch"
)

func TestCheck(t *testing.T) {
	nine := make([]headermatch.Match, headermatch.Max+1)
	for i := range nine {
		nine[i] = headermatch.Match{Name: "X-H" + strings.Repeat("a", i+1), Present: true}
	}
	for _, tc := range []struct {
		name string
		ms   []headermatch.Match
		ok   bool
	}{
		{"none", nil, true},
		{"value and presence", []headermatch.Match{{Name: "x-env", Value: "prod"}, {Name: "X-Beta", Present: true}}, true},
		{"eight", nine[:headermatch.Max], true},
		{"nine", nine, false},
		{"bad name", []headermatch.Match{{Name: "X Env", Value: "a"}}, false},
		{"empty name", []headermatch.Match{{Value: "a"}}, false},
		{"CR in value", []headermatch.Match{{Name: "X-Env", Value: "a\r\nX-Evil: 1"}}, false},
		{"LF in value", []headermatch.Match{{Name: "X-Env", Value: "a\nb"}}, false},
		{"empty value", []headermatch.Match{{Name: "X-Env"}}, false},
		{"value and present", []headermatch.Match{{Name: "X-Env", Value: "a", Present: true}}, false},
		{"twice, other case", []headermatch.Match{{Name: "X-Env", Value: "a"}, {Name: "x-env", Value: "b"}}, false},
		{"host", []headermatch.Match{{Name: "host", Value: "a"}}, false},
		{"identity header", []headermatch.Match{{Name: "rpmgr-user-email", Present: true}}, false},
		{"any identity header, with underscores", []headermatch.Match{{Name: "rpmgr_user_role", Present: true}}, false},
		{"content-length", []headermatch.Match{{Name: "content-length", Value: "0"}}, false},
		{"transfer-encoding", []headermatch.Match{{Name: "Transfer-Encoding", Value: "chunked"}}, false},
		{"trailer", []headermatch.Match{{Name: "trailer", Present: true}}, false},
		{"a leading blank", []headermatch.Match{{Name: "X-Env", Value: " beta"}}, false},
		{"a trailing tab", []headermatch.Match{{Name: "X-Env", Value: "beta\t"}}, false},
		{"a blank inside", []headermatch.Match{{Name: "X-Env", Value: "beta 2"}}, true},
	} {
		err := headermatch.Check(tc.ms)
		if (err == nil) != tc.ok || err != nil && !errors.Is(err, headermatch.ErrInvalid) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestKey(t *testing.T) {
	a := []headermatch.Match{{Name: "x-env", Value: "prod"}, {Name: "X-Beta", Present: true}}
	b := []headermatch.Match{{Name: "X-Beta", Present: true}, {Name: "X-ENV", Value: "prod"}}
	if headermatch.Key(nil) != "" || headermatch.Key(a) == "" || headermatch.Key(a) != headermatch.Key(b) {
		t.Fatal("the key depends on order or case")
	}
	for _, other := range [][]headermatch.Match{
		{{Name: "X-Env", Value: "Prod"}, {Name: "X-Beta", Present: true}}, // values compare exactly
		{{Name: "X-Env", Value: "prod"}},
		{{Name: "X-Env", Present: true}, {Name: "X-Beta", Present: true}},
		{{Name: "X-Env", Value: "prod"}, {Name: "X-Beta", Value: "p"}},
	} {
		if headermatch.Key(other) == headermatch.Key(a) {
			t.Errorf("%v has the key of %v", other, a)
		}
	}
	if got := headermatch.Canonical(b); got[0].Name != "X-Beta" || got[1].Name != "X-Env" {
		t.Errorf("Canonical: %v", got)
	}
}

func TestHolds(t *testing.T) {
	ms := []headermatch.Match{{Name: "X-Env", Value: "prod"}, {Name: "x-beta", Present: true}}
	for _, tc := range []struct {
		name string
		h    http.Header
		want bool
	}{
		{"both", http.Header{"X-Env": {"prod"}, "X-Beta": {""}}, true},
		{"one of several values", http.Header{"X-Env": {"dev", "prod"}, "X-Beta": {"1"}}, true},
		{"value of other case", http.Header{"X-Env": {"PROD"}, "X-Beta": {"1"}}, false},
		{"missing presence", http.Header{"X-Env": {"prod"}}, false},
		{"missing value", http.Header{"X-Beta": {"1"}}, false},
		{"list in one line", http.Header{"X-Env": {"dev, prod"}, "X-Beta": {"1"}}, false},
	} {
		if got := headermatch.Holds(tc.h, ms); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
	if !headermatch.Holds(http.Header{}, nil) {
		t.Error("no matches must hold")
	}
}
