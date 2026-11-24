// SPDX-License-Identifier: Apache-2.0

package agentproto_test

import (
	"bytes"
	"os"
	"regexp"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
)

// TestCapabilitiesDocumented: the capability table in docs/03 lists exactly the Phase 1
// capabilities, so the document and the code cannot drift apart.
func TestCapabilitiesDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/03-connections.md")
	if err != nil {
		t.Fatal(err)
	}
	var documented []string
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z0-9.-]+)` \\| P1 \\|").FindAllStringSubmatch(string(doc), -1) {
		documented = append(documented, m[1])
	}
	want := slices.Sorted(slices.Values(agentproto.Phase1))
	if slices.Sort(documented); !slices.Equal(documented, want) {
		t.Fatalf("docs/03 lists %v, the code %v", documented, want)
	}
}

// snapshotOf returns a ControllerMessage carrying a signed snapshot of n payload bytes.
func snapshotOf(n int) *agentv1.ControllerMessage {
	return &agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: &agentv1.Signed{
		Payload: bytes.Repeat([]byte{1}, n), Signature: make([]byte, 72), KeyId: "k"}}}
}

// TestMaxControlMessage: a message of exactly 4 MiB passes, one byte more does not.
func TestMaxControlMessage(t *testing.T) {
	overhead := proto.Size(snapshotOf(agentproto.MaxControlMessage)) - agentproto.MaxControlMessage
	exact := snapshotOf(agentproto.MaxControlMessage - overhead)
	if n := proto.Size(exact); n != agentproto.MaxControlMessage {
		t.Fatalf("built %d bytes, want exactly %d", n, agentproto.MaxControlMessage)
	}
	if err := agentproto.CheckSize(exact); err != nil {
		t.Errorf("exactly 4 MiB: %v", err)
	}
	if err := agentproto.CheckSize(snapshotOf(agentproto.MaxControlMessage - overhead + 1)); err == nil {
		t.Error("4 MiB and one byte passed")
	}
}

// TestSignedKeepsBytes: a signed message keeps its payload byte for byte through encoding, which is
// what lets agents verify and persist exactly what was signed (R14), and unknown fields in the
// payload survive as bytes.
func TestSignedKeepsBytes(t *testing.T) {
	snap, err := proto.Marshal(&agentv1.Snapshot{Revision: &agentv1.Revision{DbEpoch: "e", Seq: 7}, Agent: "spiffe://x"})
	if err != nil {
		t.Fatal(err)
	}
	payload := append(snap, 0xf8, 0x07, 0x01) // an unknown field 127 from a newer controller
	wire, err := proto.Marshal(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: &agentv1.Signed{Payload: payload}}})
	if err != nil {
		t.Fatal(err)
	}
	var got agentv1.ControllerMessage
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.GetSnapshot().GetPayload(), payload) {
		t.Fatal("the signed payload changed on the way")
	}
	var s agentv1.Snapshot
	if err := proto.Unmarshal(payload, &s); err != nil || s.GetRevision().GetSeq() != 7 {
		t.Fatalf("a payload with an unknown field: %v, %v", &s, err)
	}
}
