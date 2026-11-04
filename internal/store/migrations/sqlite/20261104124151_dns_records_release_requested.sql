-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_dns_records" table
CREATE TABLE `new_dns_records` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, `type` text NOT NULL, `content` text NOT NULL, `ttl` integer NOT NULL, `proxied` bool NOT NULL DEFAULT (false), `provider_record_id` text NULL, `state` text NOT NULL DEFAULT ('creating'), `reason` text NOT NULL DEFAULT (''), `adopted_from` text NOT NULL DEFAULT (''), `adopted_at` datetime NULL, `last_synced_at` datetime NULL, `corrected_at` datetime NULL, `release_requested` text NOT NULL DEFAULT (''), `dns_zone_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `dns_records_dns_zones_zone` FOREIGN KEY (`org_id`, `dns_zone_id`) REFERENCES `dns_zones` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `dns_records_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "dns_records" to new temporary table "new_dns_records"
INSERT INTO `new_dns_records` (`id`, `org_id`, `name`, `type`, `content`, `ttl`, `proxied`, `provider_record_id`, `state`, `reason`, `adopted_from`, `adopted_at`, `last_synced_at`, `corrected_at`, `dns_zone_id`) SELECT `id`, `org_id`, `name`, `type`, `content`, `ttl`, `proxied`, `provider_record_id`, `state`, `reason`, `adopted_from`, `adopted_at`, `last_synced_at`, `corrected_at`, `dns_zone_id` FROM `dns_records`;
-- Drop "dns_records" table after copying rows
DROP TABLE `dns_records`;
-- Rename temporary table "new_dns_records" to "dns_records"
ALTER TABLE `new_dns_records` RENAME TO `dns_records`;
-- Create index "dnsrecord_org_id_id" to table: "dns_records"
CREATE UNIQUE INDEX `dnsrecord_org_id_id` ON `dns_records` (`org_id`, `id`);
-- Create index "dnsrecord_dns_zone_id_provider_record_id" to table: "dns_records"
CREATE UNIQUE INDEX `dnsrecord_dns_zone_id_provider_record_id` ON `dns_records` (`dns_zone_id`, `provider_record_id`);
-- Create index "dnsrecord_dns_zone_id_name" to table: "dns_records"
CREATE INDEX `dnsrecord_dns_zone_id_name` ON `dns_records` (`dns_zone_id`, `name`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
