-- Create "dns_zones" table
CREATE TABLE `dns_zones` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `provider_zone_id` text NOT NULL, `name` text NOT NULL, `sync_state` text NOT NULL DEFAULT ('held'), `held_reason` text NOT NULL DEFAULT (''), `provider_status` text NOT NULL DEFAULT ('ok'), `publish_route_hostnames` bool NOT NULL DEFAULT (true), `allow_proxied` bool NOT NULL DEFAULT (false), `allow_wildcards` bool NOT NULL DEFAULT (false), `delete_threshold` integer NOT NULL DEFAULT (10), `default_ttl` integer NOT NULL DEFAULT (300), `last_synced_at` datetime NULL, `created_at` datetime NOT NULL, `dns_provider_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `dns_zones_dns_providers_dns_provider` FOREIGN KEY (`org_id`, `dns_provider_id`) REFERENCES `dns_providers` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `dns_zones_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "dnszone_org_id_id" to table: "dns_zones"
CREATE UNIQUE INDEX `dnszone_org_id_id` ON `dns_zones` (`org_id`, `id`);
-- Create index "dnszone_name" to table: "dns_zones"
CREATE UNIQUE INDEX `dnszone_name` ON `dns_zones` (`name`);
-- Create index "dnszone_dns_provider_id_provider_zone_id" to table: "dns_zones"
CREATE UNIQUE INDEX `dnszone_dns_provider_id_provider_zone_id` ON `dns_zones` (`dns_provider_id`, `provider_zone_id`);
