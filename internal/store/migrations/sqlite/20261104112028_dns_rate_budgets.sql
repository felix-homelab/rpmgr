-- Create "dns_rate_budgets" table
CREATE TABLE `dns_rate_budgets` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `window_started_at` datetime NOT NULL, `used` integer NOT NULL DEFAULT (0), `dns01_used` integer NOT NULL DEFAULT (0), `blocked_until` datetime NULL, `dns_provider_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `dns_rate_budgets_dns_providers_dns_provider` FOREIGN KEY (`org_id`, `dns_provider_id`) REFERENCES `dns_providers` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `dns_rate_budgets_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "dnsratebudget_org_id_id" to table: "dns_rate_budgets"
CREATE UNIQUE INDEX `dnsratebudget_org_id_id` ON `dns_rate_budgets` (`org_id`, `id`);
-- Create index "dnsratebudget_dns_provider_id" to table: "dns_rate_budgets"
CREATE UNIQUE INDEX `dnsratebudget_dns_provider_id` ON `dns_rate_budgets` (`dns_provider_id`);
