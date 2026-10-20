// SPDX-License-Identifier: Apache-2.0

package store

import (
	"crypto/sha256"
	"encoding/binary"
)

// RolloutBuckets is the number of buckets a rollout's percentages count in.
const RolloutBuckets = 100

// RolloutBucket places an agent in a rollout's percentages (docs/06-data-model.md, "Webhooks and
// releases (Phase 2)"; D121): the first two bytes of the SHA-256 of its ID, big-endian, modulo
// 100. A stage of p % takes every agent whose bucket is below p, so a later stage includes every
// agent of an earlier one, and an agent keeps its bucket in every rollout.
func RolloutBucket(agentID string) int {
	sum := sha256.Sum256([]byte(agentID))
	return int(binary.BigEndian.Uint16(sum[:2]) % RolloutBuckets)
}
