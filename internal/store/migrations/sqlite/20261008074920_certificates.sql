-- Create "certificates" table
CREATE TABLE `certificates` (`id` text NOT NULL, `org_id` text NOT NULL, `source` text NOT NULL, `sans` json NOT NULL, `not_before` datetime NOT NULL, `not_after` datetime NOT NULL, `chain` blob NOT NULL, `key_enc` blob NOT NULL, `content_sha256` blob NOT NULL, `status` text NOT NULL DEFAULT ('active'), `last_error` text NULL, `issuer` text NULL, `created_at` datetime NOT NULL, `version` integer NOT NULL DEFAULT (1), PRIMARY KEY (`id`), CONSTRAINT `certificates_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "certificate_org_id_id" to table: "certificates"
CREATE UNIQUE INDEX `certificate_org_id_id` ON `certificates` (`org_id`, `id`);
