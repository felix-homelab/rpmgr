-- Create "connectors" table
CREATE TABLE `connectors` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `connectors_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "connector_org_id_id" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_id` ON `connectors` (`org_id`, `id`);
-- Create index "connector_org_id_name" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_name` ON `connectors` (`org_id`, `name`);
-- Create "gateway_groups" table
CREATE TABLE `gateway_groups` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `gateway_groups_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "gatewaygroup_org_id_id" to table: "gateway_groups"
CREATE UNIQUE INDEX `gatewaygroup_org_id_id` ON `gateway_groups` (`org_id`, `id`);
-- Create index "gatewaygroup_org_id_name" to table: "gateway_groups"
CREATE UNIQUE INDEX `gatewaygroup_org_id_name` ON `gateway_groups` (`org_id`, `name`);
-- Create "orgs" table
CREATE TABLE `orgs` (`id` text NOT NULL, `name` text NOT NULL, `slug` text NOT NULL, PRIMARY KEY (`id`));
-- Create index "orgs_slug_key" to table: "orgs"
CREATE UNIQUE INDEX `orgs_slug_key` ON `orgs` (`slug`);
-- Create "routes" table
CREATE TABLE `routes` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, `type` text NOT NULL, `enabled` bool NOT NULL DEFAULT (true), `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `routes_gateway_groups_routes` FOREIGN KEY (`gateway_group_id`) REFERENCES `gateway_groups` (`id`) ON DELETE NO ACTION, CONSTRAINT `routes_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "route_org_id_id" to table: "routes"
CREATE UNIQUE INDEX `route_org_id_id` ON `routes` (`org_id`, `id`);
-- Create index "route_org_id_name" to table: "routes"
CREATE UNIQUE INDEX `route_org_id_name` ON `routes` (`org_id`, `name`);
-- Create "route_targets" table
CREATE TABLE `route_targets` (`id` text NOT NULL, `org_id` text NOT NULL, `host` text NOT NULL, `port` integer NOT NULL, `connector_id` text NOT NULL, `route_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `route_targets_connectors_targets` FOREIGN KEY (`org_id`, `connector_id`) REFERENCES `connectors` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_routes_targets` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetarget_org_id_id" to table: "route_targets"
CREATE UNIQUE INDEX `routetarget_org_id_id` ON `route_targets` (`org_id`, `id`);
