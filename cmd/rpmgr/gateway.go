// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/felix-homelab/rpmgr/internal/cli"

// infrastructureCommands are the create and update commands of gateway groups, gateways and port
// pools.
func infrastructureCommands() (create, update []*cli.Command) {
	for _, r := range []struct {
		kind   string
		fields []field
	}{
		{"gateway-group", []field{
			{flag: "name", name: "name", usage: "the group's name, unique in the org", update: true},
			{flag: "region", name: "region", usage: "where its gateways are, for people", update: true},
			{flag: "public-hostname", name: "public_hostnames", usage: "a name under which its gateways are reached", update: true},
			{flag: "trusted-proxy", name: "trusted_proxy_cidrs", usage: "a CIDR of a proxy in front of its gateways whose X-Forwarded-For counts", update: true}}},
		{"gateway", []field{
			{flag: "group", name: "gateway_group_id", usage: "its gateway group, by name or ID", ref: "gateway-group"},
			{flag: "name", name: "name", usage: "the gateway's name, unique in the org", update: true},
			{flag: "tunnel-endpoint", name: "tunnel_endpoints", usage: "a host:port at which connectors reach it", update: true}}},
		{"port-pool", []field{
			{flag: "group", name: "gateway_group_id", usage: "its gateway group, by name or ID", ref: "gateway-group"},
			{flag: "protocol", name: "protocol", usage: "tcp or udp"},
			{flag: "from", name: "port_from", usage: "its first port", update: true},
			{flag: "to", name: "port_to", usage: "its last port", update: true}}},
	} {
		c, u := resourceCommands(r.kind, r.fields)
		create, update = append(create, c), append(update, u)
	}
	return create, update
}
