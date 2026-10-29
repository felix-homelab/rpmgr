// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/handoff"
)

// DrainingProcessOf is what a new process reports to the controller about the old one that told
// it d.
func DrainingProcessOf(d handoff.Drain) *agentv1.DrainingProcess {
	return &agentv1.DrainingProcess{Active: true, Connections: d.Conns, Flows: d.Flows, Sessions: d.Sessions,
		Since: timestamppb.New(d.Since), Ends: timestamppb.New(d.Ends)}
}

// DrainGone is what a new process reports once the old one has exited.
func DrainGone() *agentv1.DrainingProcess { return &agentv1.DrainingProcess{} }
