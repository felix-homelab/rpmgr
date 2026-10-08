// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// ErrItemHash is returned for a fetched item that does not match the hash its snapshot names.
var ErrItemHash = errors.New("agent: the fetched item does not match its hash")

// Fetch returns a large snapshot item by its ID and content hash over the current control session
// (docs/03-connections.md, "Control session"), checked against the hash.
func (c *Client) Fetch(ctx context.Context, id string, hash []byte) ([]byte, error) {
	c.sendMu.Lock()
	conn := c.conn
	c.sendMu.Unlock()
	if conn == nil {
		return nil, errNoSession
	}
	resp, err := agentv1.NewControlClient(conn).FetchResource(ctx, &agentv1.FetchResourceRequest{Id: id, Hash: hash})
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(resp.GetContent()); !bytes.Equal(sum[:], hash) {
		return nil, ErrItemHash
	}
	return resp.GetContent(), nil
}

// Fetch returns a large snapshot item, as Client.Fetch does.
func (c *Control) Fetch(ctx context.Context, id string, hash []byte) ([]byte, error) {
	return c.client.Fetch(ctx, id, hash)
}
