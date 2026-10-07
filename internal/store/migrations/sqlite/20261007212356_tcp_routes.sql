-- Create "port_allocations" table
CREATE TABLE `port_allocations` (`id` text NOT NULL, `org_id` text NOT NULL, `protocol` text NOT NULL, `port` integer NOT NULL, `route_id` text NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `port_allocations_gateway_groups_group` FOREIGN KEY (`gateway_group_id`) REFERENCES `gateway_groups` (`id`) ON DELETE NO ACTION, CONSTRAINT `port_allocations_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "portallocation_org_id_id" to table: "port_allocations"
CREATE UNIQUE INDEX `portallocation_org_id_id` ON `port_allocations` (`org_id`, `id`);
-- Create index "portallocation_gateway_group_id_protocol_port" to table: "port_allocations"
CREATE UNIQUE INDEX `portallocation_gateway_group_id_protocol_port` ON `port_allocations` (`gateway_group_id`, `protocol`, `port`);
-- Create "port_pools" table
CREATE TABLE `port_pools` (`id` text NOT NULL, `org_id` text NOT NULL, `protocol` text NOT NULL, `port_from` integer NOT NULL, `port_to` integer NOT NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `port_pools_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `port_pools_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "portpool_org_id_id" to table: "port_pools"
CREATE UNIQUE INDEX `portpool_org_id_id` ON `port_pools` (`org_id`, `id`);
-- Create "port_quotas" table
CREATE TABLE `port_quotas` (`id` text NOT NULL, `org_id` text NOT NULL, `protocol` text NOT NULL, `max_ports` integer NOT NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `port_quotas_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `port_quotas_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "portquota_org_id_id" to table: "port_quotas"
CREATE UNIQUE INDEX `portquota_org_id_id` ON `port_quotas` (`org_id`, `id`);
-- Create index "portquota_org_id_gateway_group_id_protocol" to table: "port_quotas"
CREATE UNIQUE INDEX `portquota_org_id_gateway_group_id_protocol` ON `port_quotas` (`org_id`, `gateway_group_id`, `protocol`);
-- Create "routes" table
CREATE TABLE `routes` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, `type` text NOT NULL, `enabled` bool NOT NULL DEFAULT (true), `transport` text NULL, `description` text NOT NULL DEFAULT (''), `labels` json NULL, `version` integer NOT NULL DEFAULT (1), `created_at` datetime NOT NULL, `updated_at` datetime NOT NULL, `updated_by` text NOT NULL DEFAULT (''), `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `routes_gateway_groups_group` FOREIGN KEY (`gateway_group_id`) REFERENCES `gateway_groups` (`id`) ON DELETE NO ACTION, CONSTRAINT `routes_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "route_org_id_id" to table: "routes"
CREATE UNIQUE INDEX `route_org_id_id` ON `routes` (`org_id`, `id`);
-- Create index "route_org_id_name" to table: "routes"
CREATE UNIQUE INDEX `route_org_id_name` ON `routes` (`org_id`, `name`);
-- Create "route_tcp" table
CREATE TABLE `route_tcp` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `listener_mode` text NOT NULL DEFAULT ('plain'), `idle_timeout_seconds` integer NOT NULL DEFAULT (3600), `route_id` text NOT NULL, `port_allocation_id` text NOT NULL, CONSTRAINT `route_tcp_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_tcp_port_allocations_port` FOREIGN KEY (`org_id`, `port_allocation_id`) REFERENCES `port_allocations` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_tcp_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetcp_org_id_id" to table: "route_tcp"
CREATE UNIQUE INDEX `routetcp_org_id_id` ON `route_tcp` (`org_id`, `id`);
-- Create "route_targets" table
CREATE TABLE `route_targets` (`id` text NOT NULL, `org_id` text NOT NULL, `kind` text NOT NULL, `host` text NOT NULL DEFAULT (''), `port` integer NOT NULL DEFAULT (0), `unix_path` text NOT NULL DEFAULT (''), `upstream_protocol` text NOT NULL DEFAULT ('tcp'), `tls_server_name` text NOT NULL DEFAULT (''), `tls_spki_sha256` text NOT NULL DEFAULT (''), `proxy_protocol` text NOT NULL DEFAULT ('none'), `weight` integer NOT NULL DEFAULT (1), `priority` integer NOT NULL DEFAULT (0), `enabled` bool NOT NULL DEFAULT (true), `route_id` text NOT NULL, `connector_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `route_targets_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_connectors_connector` FOREIGN KEY (`org_id`, `connector_id`) REFERENCES `connectors` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetarget_org_id_id" to table: "route_targets"
CREATE UNIQUE INDEX `routetarget_org_id_id` ON `route_targets` (`org_id`, `id`);
-- Create index "routetarget_route_id" to table: "route_targets"
CREATE INDEX `routetarget_route_id` ON `route_targets` (`route_id`);
-- Create index "routetarget_connector_id" to table: "route_targets"
CREATE INDEX `routetarget_connector_id` ON `route_targets` (`connector_id`);
