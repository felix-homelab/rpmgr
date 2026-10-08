-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_gateway_groups" table
CREATE TABLE `new_gateway_groups` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `region` text NULL, `public_hostnames` json NULL, `trusted_proxy_cidrs` json NULL, PRIMARY KEY (`id`), CONSTRAINT `gateway_groups_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "gateway_groups" to new temporary table "new_gateway_groups"
INSERT INTO `new_gateway_groups` (`id`, `org_id`, `name`, `region`, `public_hostnames`, `trusted_proxy_cidrs`) SELECT `id`, `org_id`, `name`, `region`, `public_hostnames`, `trusted_proxy_cidrs` FROM `gateway_groups`;
-- Drop "gateway_groups" table after copying rows
DROP TABLE `gateway_groups`;
-- Rename temporary table "new_gateway_groups" to "gateway_groups"
ALTER TABLE `new_gateway_groups` RENAME TO `gateway_groups`;
-- Create index "gatewaygroup_org_id_id" to table: "gateway_groups"
CREATE UNIQUE INDEX `gatewaygroup_org_id_id` ON `gateway_groups` (`org_id`, `id`);
-- Create index "gatewaygroup_org_id_name" to table: "gateway_groups"
CREATE UNIQUE INDEX `gatewaygroup_org_id_name` ON `gateway_groups` (`org_id`, `name`);
-- Create "new_gateways" table
CREATE TABLE `new_gateways` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `slot` integer NOT NULL, `tunnel_endpoints` json NOT NULL, `spiffe_id` text NULL, `pubkey_sha256` text NULL, `enabled` bool NOT NULL DEFAULT (true), `desired_version` text NULL, `created_at` datetime NOT NULL, `decommissioned_at` datetime NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `gateways_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `gateways_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "gateways" to new temporary table "new_gateways"
INSERT INTO `new_gateways` (`id`, `org_id`, `name`, `slot`, `tunnel_endpoints`, `spiffe_id`, `pubkey_sha256`, `enabled`, `desired_version`, `created_at`, `decommissioned_at`, `gateway_group_id`) SELECT `id`, `org_id`, `name`, `slot`, `tunnel_endpoints`, `spiffe_id`, `pubkey_sha256`, `enabled`, `desired_version`, `created_at`, `decommissioned_at`, `gateway_group_id` FROM `gateways`;
-- Drop "gateways" table after copying rows
DROP TABLE `gateways`;
-- Rename temporary table "new_gateways" to "gateways"
ALTER TABLE `new_gateways` RENAME TO `gateways`;
-- Create index "gateway_org_id_id" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_id` ON `gateways` (`org_id`, `id`);
-- Create index "gateway_org_id_name" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_name` ON `gateways` (`org_id`, `name`);
-- Create index "gateway_gateway_group_id_slot" to table: "gateways"
CREATE UNIQUE INDEX `gateway_gateway_group_id_slot` ON `gateways` (`gateway_group_id`, `slot`) WHERE decommissioned_at IS NULL;
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
