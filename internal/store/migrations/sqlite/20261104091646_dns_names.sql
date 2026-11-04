-- Create "dns_names" table
CREATE TABLE `dns_names` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `fqdn` text NOT NULL, `ttl` integer NOT NULL DEFAULT (0), `created_at` datetime NOT NULL, `gateway_group_id` text NOT NULL, `domain_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `dns_names_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `dns_names_domains_domain` FOREIGN KEY (`org_id`, `domain_id`) REFERENCES `domains` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `dns_names_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "dnsname_org_id_id" to table: "dns_names"
CREATE UNIQUE INDEX `dnsname_org_id_id` ON `dns_names` (`org_id`, `id`);
-- Create index "dnsname_fqdn" to table: "dns_names"
CREATE UNIQUE INDEX `dnsname_fqdn` ON `dns_names` (`fqdn`);
-- Create index "dnsname_gateway_group_id" to table: "dns_names"
CREATE INDEX `dnsname_gateway_group_id` ON `dns_names` (`gateway_group_id`);
-- Create index "dnsname_domain_id" to table: "dns_names"
CREATE INDEX `dnsname_domain_id` ON `dns_names` (`domain_id`);
