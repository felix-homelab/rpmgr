-- Create index "routetcp_route_id" to table: "route_tcp"
CREATE UNIQUE INDEX `routetcp_route_id` ON `route_tcp` (`route_id`);
-- Create index "routetcp_port_allocation_id" to table: "route_tcp"
CREATE UNIQUE INDEX `routetcp_port_allocation_id` ON `route_tcp` (`port_allocation_id`);
