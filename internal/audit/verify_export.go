// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/felix-homelab/rpmgr/internal/pki"
)

// ErrExportFormat is returned for an export that is not in the format ExportFormat names, or
// whose lines are not what the format says.
var ErrExportFormat = errors.New("audit: not an audit export of this version")

// ErrExportPin is returned when the export's root does not match the pin.
var ErrExportPin = errors.New("audit: the export's root certificate does not match the pin")

// maxExportLine bounds one line of an export read offline; an entry's diff is bounded far below.
const maxExportLine = 4 << 20

// ExportResult is what a verified export holds.
type ExportResult struct {
	Chain       string
	Entries     int
	Checkpoints int
	FirstSeq    int64
	LastSeq     int64
	// AnchoredSeq is the seq of the newest checkpoint, 0 for none; Unanchored counts the entries
	// after it, which no signature covers yet.
	AnchoredSeq int64
	Unanchored  int
	// Root is the pin of the root the checkpoints verify against.
	Root string
}

// VerifyExport verifies an export (docs/04-security.md, "Audit log") against the pin of the CA's
// root alone: the root must match pin; every checkpoint must verify with a key that root certifies
// for audit checkpoints at the checkpoint's time; the entries must be consecutive, each linked to
// the one before and hashed as the chain hashes it, from the chain's genesis or from the
// checkpoint that anchors the first entry; every checkpoint must carry the hash of its entry. An
// edited, removed or reordered entry, a forged checkpoint and a cut-off export are an *ChainError.
// The entries after the newest checkpoint are counted, not refused.
func VerifyExport(r io.Reader, pin string) (ExportResult, error) {
	if !pki.ValidPin(pin) {
		return ExportResult{}, errors.New("audit: the pin is not sha256:<base64 of 32 bytes>")
	}
	br := bufio.NewReaderSize(r, 64<<10)
	next := func() ([]byte, error) {
		var line []byte
		for {
			part, err := br.ReadSlice('\n')
			line = append(line, part...)
			if len(line) > maxExportLine {
				return nil, fmt.Errorf("%w: a line is longer than %d bytes", ErrExportFormat, maxExportLine)
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
				return nil, err
			}
			return bytes.TrimRight(line, "\r\n"), nil
		}
	}
	first, err := next()
	if err != nil {
		return ExportResult{}, fmt.Errorf("%w: no header: %w", ErrExportFormat, err)
	}
	var h ExportHeader
	if err := json.Unmarshal(first, &h); err != nil || h.Type != LineHeader {
		return ExportResult{}, fmt.Errorf("%w: the first line is not a header", ErrExportFormat)
	}
	if h.Format != ExportFormat {
		return ExportResult{}, fmt.Errorf("%w: format %q, this verifier reads %q", ErrExportFormat, h.Format, ExportFormat)
	}
	trust, err := h.trust(pin)
	if err != nil {
		return ExportResult{}, err
	}
	chain := h.Chain
	org := chain
	if chain == InstanceChain {
		org = ""
	}
	res := ExportResult{Chain: chain, FirstSeq: h.FirstSeq, LastSeq: h.LastSeq, AnchoredSeq: h.AnchoredSeq, Root: pin}
	broken := func(seq int64, format string, a ...any) (ExportResult, error) {
		return ExportResult{}, &ChainError{chain, seq, fmt.Sprintf(format, a...)}
	}

	var head Head // the last verified entry, or the anchor before the first
	var started bool
	var cpSeq int64 // the seq of the last checkpoint line
	for {
		line, err := next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ExportResult{}, err
		}
		var typ struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &typ); err != nil {
			return ExportResult{}, fmt.Errorf("%w: a line is not JSON", ErrExportFormat)
		}
		switch typ.Type {
		case LineCheckpoint:
			var c ExportCheckpoint
			if err := json.Unmarshal(line, &c); err != nil {
				return ExportResult{}, fmt.Errorf("%w: a checkpoint line", ErrExportFormat)
			}
			cp := Checkpoint{OrgID: org, Seq: c.Seq, HeadHash: c.HeadHash, Time: c.Time, KeyID: c.KeyID, Signature: c.Signature}
			if err := trust.VerifySignature(cp); err != nil {
				return broken(c.Seq, "checkpoint: %v", err)
			}
			switch {
			case c.Seq <= cpSeq:
				return broken(c.Seq, "the checkpoint is out of order")
			case !started && c.Seq == h.FirstSeq-1:
				head = Head{Chain: chain, Seq: c.Seq, Hash: c.HeadHash} // the anchor of a chain retention cut
			case c.Seq < head.Seq:
				return broken(c.Seq, "the checkpoint is before the entries that follow it")
			case c.Seq > head.Seq && started:
				return broken(c.Seq, "the checkpoint covers an entry the export does not hold")
			case c.Seq == head.Seq && started && !bytes.Equal(c.HeadHash, head.Hash):
				return broken(c.Seq, "the checkpoint does not match the chain")
			}
			cpSeq = c.Seq
			res.Checkpoints++
		case LineEntry:
			var en ExportEntry
			if err := json.Unmarshal(line, &en); err != nil {
				return ExportResult{}, fmt.Errorf("%w: an entry line", ErrExportFormat)
			}
			if !started {
				started = true
				switch {
				case en.Seq == 1:
					head = Head{Chain: chain, Hash: genesis(chain)}
				case head.Seq != en.Seq-1:
					return broken(en.Seq-1, "entries were removed without a checkpoint")
				}
			}
			e := Entry{ID: en.ID, Seq: en.Seq, OrgID: org, Time: en.Time, ActorType: ActorType(en.ActorType), ActorID: en.ActorID,
				CredentialID: en.CredentialID, AuthMethod: en.AuthMethod, IP: en.IP, UserAgent: en.UserAgent, RequestID: en.RequestID,
				Action: en.Action, TargetType: en.TargetType, TargetID: en.TargetID, Result: Result(en.Result), Diff: en.Diff, Reason: en.Reason}
			switch want := head.Seq + 1; {
			case e.Seq > want:
				return broken(want, "the entry is missing")
			case e.Seq < want:
				return broken(e.Seq, "the entry is out of order")
			case !bytes.Equal(en.PrevHash, head.Hash):
				return broken(e.Seq, "prev_hash is not the hash of the entry before")
			case !bytes.Equal(chainHash(head.Hash, e), en.Hash):
				return broken(e.Seq, "the hash does not match the entry")
			case en.Unanchored != (e.Seq > h.AnchoredSeq):
				return broken(e.Seq, "the entry is flagged wrongly as anchored or not")
			}
			head = Head{Chain: chain, Seq: e.Seq, Hash: en.Hash}
			res.Entries++
			if en.Unanchored {
				res.Unanchored++
			}
		default:
			return ExportResult{}, fmt.Errorf("%w: a line of type %q", ErrExportFormat, typ.Type)
		}
	}
	if cpSeq != h.AnchoredSeq {
		return broken(h.AnchoredSeq, "the export ends before its newest checkpoint")
	}
	if h.LastSeq != 0 && head.Seq != h.LastSeq || h.LastSeq == 0 && res.Entries > 0 {
		return broken(h.LastSeq, "the export ends before its last entry")
	}
	return res, nil
}

// trust is the certificates of the header, accepted only when the root matches pin.
func (h ExportHeader) trust(pin string) (Trust, error) {
	root, err := x509.ParseCertificate(h.Root)
	if err != nil {
		return Trust{}, fmt.Errorf("%w: the root certificate", ErrExportFormat)
	}
	if pki.RootPin(root) != pin {
		return Trust{}, ErrExportPin
	}
	if root.CheckSignatureFrom(root) != nil {
		return Trust{}, fmt.Errorf("%w: the pinned certificate is not a self-signed root", ErrExportPin)
	}
	t := Trust{Root: root}
	for _, b := range h.Intermediates {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return Trust{}, fmt.Errorf("%w: an intermediate certificate", ErrExportFormat)
		}
		t.Intermediates = append(t.Intermediates, c)
	}
	for _, b := range h.Signers {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return Trust{}, fmt.Errorf("%w: a signer certificate", ErrExportFormat)
		}
		t.Signers = append(t.Signers, c)
	}
	return t, nil
}
