-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_gateways" table
CREATE TABLE `new_gateways` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `slot` integer NOT NULL, `tunnel_endpoints` json NOT NULL, `spiffe_id` text NULL, `pubkey_sha256` text NULL, `enabled` bool NOT NULL DEFAULT (true), `desired_version` text NULL, `built_in` bool NOT NULL DEFAULT (false), `created_at` datetime NOT NULL, `decommissioned_at` datetime NULL, `wss_hostname` text NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `gateways_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `gateways_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "gateways" to new temporary table "new_gateways"
INSERT INTO `new_gateways` (`id`, `org_id`, `version`, `name`, `slot`, `tunnel_endpoints`, `spiffe_id`, `pubkey_sha256`, `enabled`, `desired_version`, `built_in`, `created_at`, `decommissioned_at`, `gateway_group_id`) SELECT `id`, `org_id`, `version`, `name`, `slot`, `tunnel_endpoints`, `spiffe_id`, `pubkey_sha256`, `enabled`, `desired_version`, `built_in`, `created_at`, `decommissioned_at`, `gateway_group_id` FROM `gateways`;
-- Drop "gateways" table after copying rows
DROP TABLE `gateways`;
-- Rename temporary table "new_gateways" to "gateways"
ALTER TABLE `new_gateways` RENAME TO `gateways`;
-- Create index "gateway_org_id_id" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_id` ON `gateways` (`org_id`, `id`);
-- Create index "gateway_org_id_name" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_name` ON `gateways` (`org_id`, `name`) WHERE decommissioned_at IS NULL;
-- Create index "gateway_gateway_group_id_slot" to table: "gateways"
CREATE UNIQUE INDEX `gateway_gateway_group_id_slot` ON `gateways` (`gateway_group_id`, `slot`) WHERE decommissioned_at IS NULL;
-- Create index "gateway_wss_hostname" to table: "gateways"
CREATE UNIQUE INDEX `gateway_wss_hostname` ON `gateways` (`wss_hostname`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
