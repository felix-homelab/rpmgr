-- Create "dns_providers" table
CREATE TABLE `dns_providers` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `kind` text NOT NULL, `name` text NOT NULL, `credential_enc` blob NOT NULL, `account_id` text NOT NULL DEFAULT (''), `status` text NOT NULL DEFAULT ('ok'), `token_expires_at` datetime NULL, `last_checked_at` datetime NULL, `last_error` text NOT NULL DEFAULT (''), `created_at` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `dns_providers_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "dnsprovider_org_id_id" to table: "dns_providers"
CREATE UNIQUE INDEX `dnsprovider_org_id_id` ON `dns_providers` (`org_id`, `id`);
-- Create index "dnsprovider_org_id_name" to table: "dns_providers"
CREATE UNIQUE INDEX `dnsprovider_org_id_name` ON `dns_providers` (`org_id`, `name`);
