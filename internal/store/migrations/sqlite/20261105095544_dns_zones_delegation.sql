-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_dns_zones" table
CREATE TABLE `new_dns_zones` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `provider_zone_id` text NOT NULL, `name` text NOT NULL, `sync_state` text NOT NULL DEFAULT ('held'), `held_reason` text NOT NULL DEFAULT (''), `pending_plan` blob NULL, `pending_plan_hash` text NOT NULL DEFAULT (''), `provider_status` text NOT NULL DEFAULT ('ok'), `publish_route_hostnames` bool NOT NULL DEFAULT (true), `allow_proxied` bool NOT NULL DEFAULT (false), `allow_wildcards` bool NOT NULL DEFAULT (false), `delete_threshold` integer NOT NULL DEFAULT (10), `default_ttl` integer NOT NULL DEFAULT (300), `last_synced_at` datetime NULL, `removal_requested` bool NOT NULL DEFAULT (false), `sync_requested_at` datetime NULL, `assigned_nameservers` json NULL, `delegation_state` text NOT NULL DEFAULT ('unknown'), `delegation_nameservers` json NULL, `delegation_checked_at` datetime NULL, `created_at` datetime NOT NULL, `dns_provider_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `dns_zones_dns_providers_dns_provider` FOREIGN KEY (`org_id`, `dns_provider_id`) REFERENCES `dns_providers` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `dns_zones_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "dns_zones" to new temporary table "new_dns_zones"
INSERT INTO `new_dns_zones` (`id`, `org_id`, `version`, `provider_zone_id`, `name`, `sync_state`, `held_reason`, `pending_plan`, `pending_plan_hash`, `provider_status`, `publish_route_hostnames`, `allow_proxied`, `allow_wildcards`, `delete_threshold`, `default_ttl`, `last_synced_at`, `removal_requested`, `sync_requested_at`, `created_at`, `dns_provider_id`) SELECT `id`, `org_id`, `version`, `provider_zone_id`, `name`, `sync_state`, `held_reason`, `pending_plan`, `pending_plan_hash`, `provider_status`, `publish_route_hostnames`, `allow_proxied`, `allow_wildcards`, `delete_threshold`, `default_ttl`, `last_synced_at`, `removal_requested`, `sync_requested_at`, `created_at`, `dns_provider_id` FROM `dns_zones`;
-- Drop "dns_zones" table after copying rows
DROP TABLE `dns_zones`;
-- Rename temporary table "new_dns_zones" to "dns_zones"
ALTER TABLE `new_dns_zones` RENAME TO `dns_zones`;
-- Create index "dnszone_org_id_id" to table: "dns_zones"
CREATE UNIQUE INDEX `dnszone_org_id_id` ON `dns_zones` (`org_id`, `id`);
-- Create index "dnszone_name" to table: "dns_zones"
CREATE UNIQUE INDEX `dnszone_name` ON `dns_zones` (`name`);
-- Create index "dnszone_dns_provider_id_provider_zone_id" to table: "dns_zones"
CREATE UNIQUE INDEX `dnszone_dns_provider_id_provider_zone_id` ON `dns_zones` (`dns_provider_id`, `provider_zone_id`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
