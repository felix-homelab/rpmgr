// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// webhookSink posts each item as a webhook: signed with the sink's secret, with the type of the item
// as the event type and its ID as the event ID (docs/04-security.md, "Audit log"). It is set by the
// Instance Admin, so it may reach private ranges and loopback; the guard still refuses link-local,
// metadata, multicast and broadcast addresses (D145, E5).
type webhookSink struct {
	sender *webhook.Sender
	url    string
	secret secret.Value
}

func openWebhook(o Options, s *ent.AuditSink) (Sink, error) {
	url := s.Settings["url"]
	if url == "" {
		return nil, errors.New("the webhook sink has no url")
	}
	if s.SecretEnc == nil || len(*s.SecretEnc) == 0 {
		return nil, errors.New("the webhook sink has no secret")
	}
	key, err := o.Sealer.Open(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: s.ID}, *s.SecretEnc)
	if err != nil {
		return nil, errors.New("the webhook sink's secret cannot be opened")
	}
	return &webhookSink{sender: o.Sender, url: url, secret: key}, nil
}

func (w *webhookSink) Ship(ctx context.Context, it Item) error {
	code, err := w.sender.Send(ctx, webhook.Delivery{URL: w.url, EventID: it.ID, EventType: it.Type, Body: it.Body,
		Secrets: []secret.Value{w.secret}, Policy: egress.Policy{Internal: true}})
	if err != nil && permanentStatus(code) {
		return &PermanentError{Status: code, Err: err}
	}
	return err
}

// permanentStatus reports whether a receiver's answer says that sending the same item again will
// fail the same way: a 4xx other than 408 (timeout) and 429 (rate limit), which pass.
func permanentStatus(code int) bool {
	return code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests
}

// PermanentError is a refusal of an item that a retry will not change: the receiver answered with a
// 4xx other than 408 and 429. The sink's cursor on that chain waits until the receiver accepts the
// item, so the error says so, and the runner retries it only at the slowest pace.
type PermanentError struct {
	Status int
	Err    error
	// Msg, if set, is the text instead of the receiver's refusal: a sink that is not a receiver
	// of requests says in its own words why it waits.
	Msg string
}

func (e *PermanentError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return fmt.Sprintf("the receiver refused an item with %d; the sink ships nothing more of that chain until the receiver accepts it", e.Status)
}

func (e *PermanentError) Unwrap() error { return e.Err }

// checkpointBody is the JSON of a checkpoint.
type checkpointBody struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Time      time.Time `json:"time"`
	OrgID     *string   `json:"org_id"`
	Chain     string    `json:"chain"`
	Seq       int64     `json:"seq"`
	HeadHash  string    `json:"head_hash"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature"`
}

// entryBody is the JSON of an entry. Truncated says that the diff was left out to fit a delivery.
type entryBody struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Time         time.Time `json:"time"`
	OrgID        *string   `json:"org_id"`
	Chain        string    `json:"chain"`
	Seq          int64     `json:"seq"`
	PrevHash     string    `json:"prev_hash"`
	Hash         string    `json:"hash"`
	ActorType    string    `json:"actor_type"`
	ActorID      string    `json:"actor_id"`
	CredentialID string    `json:"credential_id"`
	AuthMethod   string    `json:"auth_method"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	RequestID    string    `json:"request_id"`
	Action       string    `json:"action"`
	TargetType   string    `json:"target_type"`
	TargetID     string    `json:"target_id"`
	Result       string    `json:"result"`
	Diff         string    `json:"diff"`
	Reason       string    `json:"reason"`
	Truncated    bool      `json:"truncated,omitempty"`
}

func orgPtr(org string) *string {
	if org == "" {
		return nil
	}
	return &org
}

func checkpointItem(c audit.Checkpoint) Item {
	body, _ := json.Marshal(checkpointBody{ID: c.ID, Type: EventCheckpoint, Time: c.Time, OrgID: orgPtr(c.OrgID), Chain: c.Chain(), Seq: c.Seq,
		HeadHash: hex.EncodeToString(c.HeadHash), KeyID: c.KeyID, Signature: base64.StdEncoding.EncodeToString(c.Signature)})
	return Item{ID: c.ID, Type: EventCheckpoint, Chain: c.Chain(), Seq: c.Seq, Time: c.Time, Body: body}
}

func entryItem(e audit.Entry) Item {
	b := entryBody{ID: e.ID, Type: EventEntry, Time: e.Time, OrgID: orgPtr(e.OrgID), Chain: e.Chain(), Seq: e.Seq,
		PrevHash: hex.EncodeToString(e.PrevHash), Hash: hex.EncodeToString(e.Hash), ActorType: string(e.ActorType), ActorID: e.ActorID,
		CredentialID: e.CredentialID, AuthMethod: e.AuthMethod, IP: e.IP, UserAgent: e.UserAgent, RequestID: e.RequestID, Action: e.Action,
		TargetType: e.TargetType, TargetID: e.TargetID, Result: string(e.Result), Diff: e.Diff, Reason: e.Reason}
	body, _ := json.Marshal(b)
	if len(body) > webhook.MaxBody {
		// A delivery that can never be sent would hold the sink's cursor for good.
		b.Diff, b.Truncated = "", true
		body, _ = json.Marshal(b)
	}
	return Item{ID: e.ID, Type: EventEntry, Chain: e.Chain(), Seq: e.Seq, Time: e.Time, Body: body}
}
