-- Create "gateway_pages" table
CREATE TABLE `gateway_pages` (`id` text NOT NULL, `org_id` text NOT NULL, `kind` text NOT NULL, `html` text NOT NULL, `content_sha256` blob NOT NULL, `updated_at` datetime NOT NULL, `updated_by` text NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `gateway_pages_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `gateway_pages_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "gatewaypage_org_id_id" to table: "gateway_pages"
CREATE UNIQUE INDEX `gatewaypage_org_id_id` ON `gateway_pages` (`org_id`, `id`);
-- Create index "gatewaypage_gateway_group_id_kind" to table: "gateway_pages"
CREATE UNIQUE INDEX `gatewaypage_gateway_group_id_kind` ON `gateway_pages` (`gateway_group_id`, `kind`);
