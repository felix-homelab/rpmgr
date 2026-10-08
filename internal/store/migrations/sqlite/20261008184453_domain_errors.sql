-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_domains" table
CREATE TABLE `new_domains` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `fqdn` text NOT NULL, `wildcard` bool NOT NULL DEFAULT (false), `status` text NOT NULL DEFAULT ('pending'), `method` text NOT NULL DEFAULT ('dns_txt'), `challenge_value` text NOT NULL, `created_at` datetime NOT NULL, `verified_at` datetime NULL, `last_checked_at` datetime NULL, `last_error` text NOT NULL DEFAULT (''), PRIMARY KEY (`id`), CONSTRAINT `domains_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "domains" to new temporary table "new_domains"
INSERT INTO `new_domains` (`id`, `org_id`, `version`, `fqdn`, `wildcard`, `status`, `method`, `challenge_value`, `created_at`, `verified_at`, `last_checked_at`) SELECT `id`, `org_id`, `version`, `fqdn`, `wildcard`, `status`, `method`, `challenge_value`, `created_at`, `verified_at`, `last_checked_at` FROM `domains`;
-- Drop "domains" table after copying rows
DROP TABLE `domains`;
-- Rename temporary table "new_domains" to "domains"
ALTER TABLE `new_domains` RENAME TO `domains`;
-- Create index "domain_org_id_id" to table: "domains"
CREATE UNIQUE INDEX `domain_org_id_id` ON `domains` (`org_id`, `id`);
-- Create index "domain_fqdn" to table: "domains"
CREATE UNIQUE INDEX `domain_fqdn` ON `domains` (`fqdn`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
