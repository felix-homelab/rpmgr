// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const plain = "hunter2-very-secret"

// holder has the Value in an unexported field, where fmt cannot call Value's methods.
type holder struct {
	name   string
	secret Value
}

// Exported has the Value in an exported field.
type Exported struct {
	Name   string
	Secret Value
	Ptr    *Value
}

func TestReveal(t *testing.T) {
	if got := New(plain).Reveal(); got != plain {
		t.Errorf("Reveal() = %q, want %q", got, plain)
	}
	var zero Value
	if zero.Reveal() != "" || !zero.IsZero() {
		t.Errorf("zero Value: Reveal %q, IsZero %v; want empty and true", zero.Reveal(), zero.IsZero())
	}
	if !New("").IsZero() || New("x").IsZero() {
		t.Error("IsZero wrong for empty or non-empty secret")
	}
}

func TestFromBytesCopies(t *testing.T) {
	b := []byte(plain)
	v := FromBytes(b)
	b[0] = 'X'
	if v.Reveal() != plain {
		t.Errorf("changing the input changed the secret: %q", v.Reveal())
	}
}

func TestNeverPrinted(t *testing.T) {
	v := New(plain)
	p := &v
	h := holder{name: "n", secret: v}
	e := Exported{Name: "n", Secret: v, Ptr: p}
	cases := map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%10s", "%-10v", "%d", "%T"} {
		cases["value "+verb] = fmt.Sprintf(verb, v)
		cases["pointer "+verb] = fmt.Sprintf(verb, p)
		cases["unexported field "+verb] = fmt.Sprintf(verb, h)
		cases["exported field "+verb] = fmt.Sprintf(verb, e)
		cases["slice "+verb] = fmt.Sprintf(verb, []Value{v})
		cases["map "+verb] = fmt.Sprintf(verb, map[string]Value{"k": v})
		cases["pointer to unexported field "+verb] = fmt.Sprintf(verb, &h)
		cases["nested unexported "+verb] = fmt.Sprintf(verb, struct{ h holder }{h})
	}
	cases["Print"] = fmt.Sprint(v, p, h, e)
	cases["Println"] = fmt.Sprintln(v, p, h, e)
	cases["error %v"] = fmt.Errorf("connect: %v", v).Error()
	cases["error %w chain"] = fmt.Errorf("outer: %w", errors.New(v.String())).Error()
	for name, out := range cases {
		if strings.Contains(out, plain) || strings.Contains(out, fmt.Sprintf("%x", plain)) ||
			strings.Contains(out, fmt.Sprintf("%X", plain)) || strings.Contains(out, fmt.Sprintf("%d", []byte(plain))) {
			t.Errorf("%s leaks the secret: %q", name, out)
		}
	}
	if s := fmt.Sprintf("%v|%s|%#v", v, v, v); s != Redacted+"|"+Redacted+"|"+Redacted {
		t.Errorf("formats = %q, want %s three times", s, Redacted)
	}
}

func TestMarshalling(t *testing.T) {
	v := New(plain)
	j, err := json.Marshal(Exported{Name: "n", Secret: v, Ptr: &v})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(j), plain) || !strings.Contains(string(j), `"Secret":"[REDACTED]"`) {
		t.Errorf("json = %s", j)
	}
	if mj, _ := json.Marshal(map[string]Value{"k": v}); strings.Contains(string(mj), plain) {
		t.Errorf("json map leaks: %s", mj)
	}
	txt, err := v.MarshalText()
	if err != nil || string(txt) != Redacted {
		t.Errorf("MarshalText = %q, %v", txt, err)
	}
}

func TestSlog(t *testing.T) {
	v := New(plain)
	for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	} {
		var buf bytes.Buffer
		l := slog.New(h(&buf))
		l.Info("login", "pw", v, "ptr", &v, slog.Group("g", "inner", v), "struct", Exported{Secret: v}, "hidden", holder{secret: v})
		l.With("bound", v).Info("again")
		if strings.Contains(buf.String(), plain) {
			t.Errorf("%s handler leaks the secret:\n%s", name, buf.String())
		}
		if !strings.Contains(buf.String(), Redacted) {
			t.Errorf("%s handler shows no %s:\n%s", name, Redacted, buf.String())
		}
	}
}
