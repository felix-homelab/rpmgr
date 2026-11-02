// SPDX-License-Identifier: Apache-2.0

// Package sinkverify holds the outcome of reading an object-storage audit sink back
// (docs/04-security.md, "Audit log"). The store keeps it as JSON on the sink's row, so the type
// lives apart from both the store's schema and the sink code, which each import it.
package sinkverify

import "time"

// Verification is the outcome of the last read-back of a sink: when it ran and, per chain, how far
// the sink verified.
type Verification struct {
	Time   time.Time `json:"time"`
	Chains []Chain   `json:"chains"`
}

// Chain is one chain's part: the last checkpoint of the sink that verified, how many checkpoints
// were read, and what is missing or wrong, empty when nothing is.
type Chain struct {
	Chain          string    `json:"chain"`
	Checked        int       `json:"checked"`
	CheckpointSeq  int64     `json:"checkpoint_seq"`
	CheckpointTime time.Time `json:"checkpoint_time"`
	Gap            string    `json:"gap,omitempty"`
	Problem        string    `json:"problem,omitempty"`
}

// Intact reports whether the chain has neither a gap nor a problem.
func (c Chain) Intact() bool { return c.Gap == "" && c.Problem == "" }
