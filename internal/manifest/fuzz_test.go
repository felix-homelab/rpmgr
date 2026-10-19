// SPDX-License-Identifier: Apache-2.0

package manifest_test

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/felix-homelab/rpmgr/internal/manifest"
)

// FuzzManifestRead: a YAML stream of manifests either is refused with an error or reads into
// manifests that write and read back unchanged. A manifest whose resource parses writes a manifest
// that parses to the same resource, so reading and writing settle after one round.
func FuzzManifestRead(f *testing.F) {
	ctx := context.Background()
	d, err := manifest.Of(ctx, resolver, stored())
	if err != nil {
		f.Fatal(err)
	}
	var b bytes.Buffer
	if err := manifest.Write(&b, []*manifest.Doc{d, d}); err != nil {
		f.Fatal(err)
	}
	f.Add(b.Bytes())
	f.Add([]byte("kind: Connector\nmetadata: {name: nas, labels: {a: b}}\nspec: {description: x}\n---\nkind: AccessPolicy\nmetadata: {name: office}\nspec: {}\n"))
	f.Add([]byte("kind: Route\nmetadata: &m {name: a}\nspec: {gatewayGroup: eu, policies: [office, office]}\n---\nkind: Route\nmetadata: *m\n"))
	f.Add([]byte("kind: Route\nmetadata: {name: a}\nunknown: 1\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		docs, err := manifest.Read(bytes.NewReader(in))
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := manifest.Write(&out, docs); err != nil {
			return // a value YAML reads but cannot write, such as a key that is not a string
		}
		again, err := manifest.Read(bytes.NewReader(out.Bytes()))
		if err != nil {
			t.Fatalf("manifests that were read and written are refused: %v\n%s", err, out.Bytes())
		}
		var out2 bytes.Buffer
		if err := manifest.Write(&out2, again); err != nil || !bytes.Equal(out.Bytes(), out2.Bytes()) {
			t.Fatalf("manifests changed when written and read again (%v):\n%s\n%s", err, out.Bytes(), out2.Bytes())
		}
		for _, d := range docs {
			m, err := manifest.Parse(ctx, resolver, d)
			if err != nil {
				continue
			}
			d2, err := manifest.Of(ctx, resolver, m)
			if err != nil {
				continue // an ID the spec named directly that the resolver does not know
			}
			m2, err := manifest.Parse(ctx, resolver, d2)
			if err != nil {
				t.Fatalf("the manifest written for a parsed resource is refused: %v\n%+v", err, d2)
			}
			d3, err := manifest.Of(ctx, resolver, m2)
			if err != nil {
				t.Fatalf("a parsed resource cannot be written again: %v", err)
			}
			if m3, err := manifest.Parse(ctx, resolver, d3); err != nil || !proto.Equal(m2, m3) {
				t.Fatalf("a resource changed when written and parsed again (%v):\n%v\n%v", err, m2, m3)
			}
		}
	})
}
