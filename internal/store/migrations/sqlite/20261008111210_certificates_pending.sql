-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_certificates" table
CREATE TABLE `new_certificates` (`id` text NOT NULL, `org_id` text NOT NULL, `source` text NOT NULL, `sans` json NOT NULL, `not_before` datetime NULL, `not_after` datetime NULL, `chain` blob NULL, `key_enc` blob NULL, `content_sha256` blob NULL, `status` text NOT NULL DEFAULT ('active'), `last_error` text NULL, `issuer` text NULL, `created_at` datetime NOT NULL, `version` integer NOT NULL DEFAULT (1), PRIMARY KEY (`id`), CONSTRAINT `certificates_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "certificates" to new temporary table "new_certificates"
INSERT INTO `new_certificates` (`id`, `org_id`, `source`, `sans`, `not_before`, `not_after`, `chain`, `key_enc`, `content_sha256`, `status`, `last_error`, `issuer`, `created_at`, `version`) SELECT `id`, `org_id`, `source`, `sans`, `not_before`, `not_after`, `chain`, `key_enc`, `content_sha256`, `status`, `last_error`, `issuer`, `created_at`, `version` FROM `certificates`;
-- Drop "certificates" table after copying rows
DROP TABLE `certificates`;
-- Rename temporary table "new_certificates" to "certificates"
ALTER TABLE `new_certificates` RENAME TO `certificates`;
-- Create index "certificate_org_id_id" to table: "certificates"
CREATE UNIQUE INDEX `certificate_org_id_id` ON `certificates` (`org_id`, `id`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
