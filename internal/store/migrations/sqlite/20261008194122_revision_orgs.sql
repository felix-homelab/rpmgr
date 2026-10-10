-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_config_revisions" table
CREATE TABLE `new_config_revisions` (`seq` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `db_epoch` text NOT NULL, `actor` text NOT NULL, `changed_resources` json NULL, `org_id` text NULL, `created_at` datetime NOT NULL, CONSTRAINT `config_revisions_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "config_revisions" to new temporary table "new_config_revisions"
INSERT INTO `new_config_revisions` (`seq`, `db_epoch`, `actor`, `changed_resources`, `created_at`) SELECT `seq`, `db_epoch`, `actor`, `changed_resources`, `created_at` FROM `config_revisions`;
-- Drop "config_revisions" table after copying rows
DROP TABLE `config_revisions`;
-- Rename temporary table "new_config_revisions" to "config_revisions"
ALTER TABLE `new_config_revisions` RENAME TO `config_revisions`;
-- Create index "configrevision_org_id_seq" to table: "config_revisions"
CREATE INDEX `configrevision_org_id_seq` ON `config_revisions` (`org_id`, `seq`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
