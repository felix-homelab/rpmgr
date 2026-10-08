-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_port_pools" table
CREATE TABLE `new_port_pools` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `protocol` text NOT NULL, `port_from` integer NOT NULL, `port_to` integer NOT NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `port_pools_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `port_pools_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "port_pools" to new temporary table "new_port_pools"
INSERT INTO `new_port_pools` (`id`, `org_id`, `protocol`, `port_from`, `port_to`, `gateway_group_id`) SELECT `id`, `org_id`, `protocol`, `port_from`, `port_to`, `gateway_group_id` FROM `port_pools`;
-- Drop "port_pools" table after copying rows
DROP TABLE `port_pools`;
-- Rename temporary table "new_port_pools" to "port_pools"
ALTER TABLE `new_port_pools` RENAME TO `port_pools`;
-- Create index "portpool_org_id_id" to table: "port_pools"
CREATE UNIQUE INDEX `portpool_org_id_id` ON `port_pools` (`org_id`, `id`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
