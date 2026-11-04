-- Create "dns_name_status" table
CREATE TABLE `dns_name_status` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, `status` text NOT NULL, `reason` text NOT NULL DEFAULT (''), `since` datetime NOT NULL, `dns_zone_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `dns_name_status_dns_zones_zone` FOREIGN KEY (`org_id`, `dns_zone_id`) REFERENCES `dns_zones` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `dns_name_status_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "dnsnamestatus_org_id_id" to table: "dns_name_status"
CREATE UNIQUE INDEX `dnsnamestatus_org_id_id` ON `dns_name_status` (`org_id`, `id`);
-- Create index "dnsnamestatus_dns_zone_id_name" to table: "dns_name_status"
CREATE UNIQUE INDEX `dnsnamestatus_dns_zone_id_name` ON `dns_name_status` (`dns_zone_id`, `name`);
