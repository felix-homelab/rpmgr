-- Create "dns_records" table
CREATE TABLE `dns_records` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, `type` text NOT NULL, `content` text NOT NULL, `ttl` integer NOT NULL, `proxied` bool NOT NULL DEFAULT (false), `provider_record_id` text NULL, `state` text NOT NULL DEFAULT ('creating'), `reason` text NOT NULL DEFAULT (''), `adopted_from` text NOT NULL DEFAULT (''), `adopted_at` datetime NULL, `last_synced_at` datetime NULL, `dns_zone_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `dns_records_dns_zones_zone` FOREIGN KEY (`org_id`, `dns_zone_id`) REFERENCES `dns_zones` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `dns_records_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "dnsrecord_org_id_id" to table: "dns_records"
CREATE UNIQUE INDEX `dnsrecord_org_id_id` ON `dns_records` (`org_id`, `id`);
-- Create index "dnsrecord_dns_zone_id_provider_record_id" to table: "dns_records"
CREATE UNIQUE INDEX `dnsrecord_dns_zone_id_provider_record_id` ON `dns_records` (`dns_zone_id`, `provider_record_id`);
-- Create index "dnsrecord_dns_zone_id_name" to table: "dns_records"
CREATE INDEX `dnsrecord_dns_zone_id_name` ON `dns_records` (`dns_zone_id`, `name`);
