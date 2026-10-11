// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"strings"
	"testing"

	"entgo.io/ent/entc/load"
)

// TestSecretColumnsAreSensitive (docs/04-security.md, "Secrets at rest and in logs"): every column
// sealed under the KEK (`*_enc`), and the password hash, is marked Sensitive, so that the generated
// code never prints or marshals it.
func TestSecretColumnsAreSensitive(t *testing.T) {
	spec, err := (&load.Config{Path: "."}).Load()
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, s := range spec.Schemas {
		for _, f := range s.Fields {
			if !strings.HasSuffix(f.Name, "_enc") && f.Name != "password_hash" {
				continue
			}
			checked++
			if !f.Sensitive {
				t.Errorf("%s.%s holds a secret but is not Sensitive()", s.Name, f.Name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no secret column found: the schema did not load as expected")
	}
}
