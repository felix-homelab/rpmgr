-- Create "domains" table
CREATE TABLE `domains` (`id` text NOT NULL, `org_id` text NOT NULL, `fqdn` text NOT NULL, `wildcard` bool NOT NULL DEFAULT (false), `status` text NOT NULL DEFAULT ('pending'), `method` text NOT NULL DEFAULT ('dns_txt'), `challenge_value` text NOT NULL, `created_at` datetime NOT NULL, `verified_at` datetime NULL, `last_checked_at` datetime NULL, `version` integer NOT NULL DEFAULT (1), PRIMARY KEY (`id`), CONSTRAINT `domains_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "domain_org_id_id" to table: "domains"
CREATE UNIQUE INDEX `domain_org_id_id` ON `domains` (`org_id`, `id`);
-- Create index "domain_fqdn" to table: "domains"
CREATE UNIQUE INDEX `domain_fqdn` ON `domains` (`fqdn`);
