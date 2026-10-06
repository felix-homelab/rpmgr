-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_routes" table
CREATE TABLE `new_routes` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, `type` text NOT NULL, `enabled` bool NOT NULL DEFAULT (true), `description` text NOT NULL DEFAULT (''), `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `routes_gateway_groups_routes` FOREIGN KEY (`gateway_group_id`) REFERENCES `gateway_groups` (`id`) ON DELETE NO ACTION, CONSTRAINT `routes_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "routes" to new temporary table "new_routes"
INSERT INTO `new_routes` (`id`, `org_id`, `name`, `type`, `enabled`, `gateway_group_id`) SELECT `id`, `org_id`, `name`, `type`, `enabled`, `gateway_group_id` FROM `routes`;
-- Drop "routes" table after copying rows
DROP TABLE `routes`;
-- Rename temporary table "new_routes" to "routes"
ALTER TABLE `new_routes` RENAME TO `routes`;
-- Create index "route_org_id_id" to table: "routes"
CREATE UNIQUE INDEX `route_org_id_id` ON `routes` (`org_id`, `id`);
-- Create index "route_org_id_name" to table: "routes"
CREATE UNIQUE INDEX `route_org_id_name` ON `routes` (`org_id`, `name`);
-- Create "new_route_targets" table
CREATE TABLE `new_route_targets` (`id` text NOT NULL, `org_id` text NOT NULL, `host` text NOT NULL, `port` integer NOT NULL, `connector_id` text NOT NULL, `health_check_id` text NULL, `route_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `route_targets_connectors_targets` FOREIGN KEY (`org_id`, `connector_id`) REFERENCES `connectors` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_health_checks_targets` FOREIGN KEY (`org_id`, `health_check_id`) REFERENCES `health_checks` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_routes_targets` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "route_targets" to new temporary table "new_route_targets"
INSERT INTO `new_route_targets` (`id`, `org_id`, `host`, `port`, `connector_id`, `route_id`) SELECT `id`, `org_id`, `host`, `port`, `connector_id`, `route_id` FROM `route_targets`;
-- Drop "route_targets" table after copying rows
DROP TABLE `route_targets`;
-- Rename temporary table "new_route_targets" to "route_targets"
ALTER TABLE `new_route_targets` RENAME TO `route_targets`;
-- Create index "routetarget_org_id_id" to table: "route_targets"
CREATE UNIQUE INDEX `routetarget_org_id_id` ON `route_targets` (`org_id`, `id`);
-- Create "health_checks" table
CREATE TABLE `health_checks` (`id` text NOT NULL, `org_id` text NOT NULL, `type` text NOT NULL, `interval_seconds` integer NOT NULL DEFAULT (10), PRIMARY KEY (`id`), CONSTRAINT `health_checks_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "healthcheck_org_id_id" to table: "health_checks"
CREATE UNIQUE INDEX `healthcheck_org_id_id` ON `health_checks` (`org_id`, `id`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
