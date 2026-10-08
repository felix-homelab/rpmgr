-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_connectors" table
CREATE TABLE `new_connectors` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `labels` json NULL, `spiffe_id` text NOT NULL, `pubkey_sha256` text NOT NULL, `ephemeral` bool NOT NULL DEFAULT (false), `enabled` bool NOT NULL DEFAULT (true), `transport` text NULL, `desired_version` text NULL, `created_at` datetime NOT NULL, `decommissioned_at` datetime NULL, PRIMARY KEY (`id`), CONSTRAINT `connectors_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "connectors" to new temporary table "new_connectors"
INSERT INTO `new_connectors` (`id`, `org_id`, `name`, `labels`, `spiffe_id`, `pubkey_sha256`, `ephemeral`, `enabled`, `transport`, `desired_version`, `created_at`, `decommissioned_at`) SELECT `id`, `org_id`, `name`, `labels`, `spiffe_id`, `pubkey_sha256`, `ephemeral`, `enabled`, `transport`, `desired_version`, `created_at`, `decommissioned_at` FROM `connectors`;
-- Drop "connectors" table after copying rows
DROP TABLE `connectors`;
-- Rename temporary table "new_connectors" to "connectors"
ALTER TABLE `new_connectors` RENAME TO `connectors`;
-- Create index "connector_org_id_id" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_id` ON `connectors` (`org_id`, `id`);
-- Create index "connector_org_id_name" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_name` ON `connectors` (`org_id`, `name`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
