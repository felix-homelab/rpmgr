// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
	"reflect"
	"regexp"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/felix-homelab/rpmgr/internal/config"
)

// roles makes an empty boot file of each role; the fuzzer picks one with the input's first byte.
var roles = []func() config.File{
	func() config.File { return &config.Controller{} },
	func() config.File { return &config.Gateway{} },
	func() config.File { return &config.Connector{} },
	func() config.File { return &config.AllInOne{} },
}

// FuzzBootFile: a boot file of any role either is refused with an error or parses into a file
// that is valid and stays the same when written out and read again, so nothing is accepted half
// read. Seeds are the documented boot files of docs/10-operations.md.
func FuzzBootFile(f *testing.F) {
	doc, err := os.ReadFile("../../docs/10-operations.md")
	if err != nil {
		f.Fatal(err)
	}
	index := map[string]byte{"controller": 0, "gateway": 1, "connector": 2, "all-in-one": 3}
	for _, b := range regexp.MustCompile("(?s)```yaml\n(# /etc/rpmgr/(\\w[\\w-]*)\\.yaml\n.*?)```").FindAllStringSubmatch(string(doc), -1) {
		if i, ok := index[b[2]]; ok {
			f.Add(i, []byte(b[1]))
		}
	}
	f.Add(byte(3), []byte("version: 1\npublic_url: https://home.example.com\nlisten: {http: \"\"}\n"))
	f.Add(byte(0), []byte("version: 1\npublic_url: https://p.example\ntracing: {otlp_endpoint: http://c:4318/v1/traces, sample_ratio: 0.5}\n"))
	f.Add(byte(1), []byte("version: 1\n---\nversion: 1\n"))
	f.Fuzz(func(t *testing.T, role byte, in []byte) {
		newFile := roles[int(role)%len(roles)]
		file := newFile()
		if err := config.Parse(in, file); err != nil {
			return
		}
		if v := reflect.ValueOf(file).Elem().FieldByName("Version").Int(); v != config.Version {
			t.Fatalf("version %d accepted from %q", v, in)
		}
		if r := reflect.ValueOf(file).Elem().FieldByName("Tracing").Interface().(config.Tracing).SampleRatio; r != nil && !(*r >= 0 && *r <= 1) {
			t.Fatalf("sample ratio %v accepted from %q", *r, in)
		}
		out, err := yaml.Marshal(file)
		if err != nil {
			t.Fatalf("an accepted file cannot be written: %v", err)
		}
		again := newFile()
		if err := config.Parse(out, again); err != nil {
			t.Fatalf("an accepted file, written out, is refused: %v\n%s", err, out)
		}
		// Compared as written: a list read as empty and one never set are the same file.
		if out2, err := yaml.Marshal(again); err != nil || string(out2) != string(out) {
			t.Fatalf("an accepted file changed when written out and read again (%v):\n%s\n%s", err, out, out2)
		}
	})
}
