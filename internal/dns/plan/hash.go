// SPDX-License-Identifier: Apache-2.0

package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/dns"
)

// EncodingVersion is the first line of Encode. A change of the encoding changes it.
const EncodingVersion = "rpmgr-dns-plan/1"

// Encode returns the canonical text of the plan, the input of its hash (docs/15-dns.md, "Plan
// hash"). It is the version line, then one line per item in this order: creates, updates, deletes,
// conflicts, orphans, shadows, lost. Every string is written with strconv.Quote and every field is
// separated by one space; a line ends with a line feed. The lists are sorted by name, type,
// content and ID, so the same plan in any input order has the same text.
//
//	create|update|delete|orphan  id type name content ttl proxied comment
//	conflict                     name kind
//	conflict-record              name id type content
//	shadow                       name
//	lost                         ledger-id record-id
func (p Plan) Encode() []byte {
	var b strings.Builder
	line := func(kind string, fields ...string) {
		b.WriteString(kind)
		for _, f := range fields {
			b.WriteByte(' ')
			b.WriteString(strconv.Quote(f))
		}
		b.WriteByte('\n')
	}
	rec := func(kind string, rs []dns.Record) {
		for _, r := range rs {
			line(kind, r.ID, r.Type, r.Name, r.Content, strconv.Itoa(r.TTL), strconv.FormatBool(r.Proxied), r.Comment)
		}
	}
	b.WriteString(EncodingVersion + "\n")
	rec("create", p.Creates)
	rec("update", p.Updates)
	rec("delete", p.Deletes)
	for _, c := range p.Conflicts {
		line("conflict", c.Name, string(c.Kind))
		for _, r := range c.Records {
			line("conflict-record", c.Name, r.ID, r.Type, r.Content)
		}
	}
	rec("orphan", p.Orphans)
	for _, s := range p.Shadows {
		line("shadow", s)
	}
	for _, o := range p.Lost {
		line("lost", o.LedgerID, o.RecordID)
	}
	return []byte(b.String())
}

// hash is the lower-case hex SHA-256 of Encode.
func (p Plan) hash() string {
	sum := sha256.Sum256(p.Encode())
	return hex.EncodeToString(sum[:])
}
