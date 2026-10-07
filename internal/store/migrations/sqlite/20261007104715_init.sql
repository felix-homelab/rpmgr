-- Create "gateway_groups" table
CREATE TABLE `gateway_groups` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `gateway_groups_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "gatewaygroup_org_id_id" to table: "gateway_groups"
CREATE UNIQUE INDEX `gatewaygroup_org_id_id` ON `gateway_groups` (`org_id`, `id`);
-- Create index "gatewaygroup_org_id_name" to table: "gateway_groups"
CREATE UNIQUE INDEX `gatewaygroup_org_id_name` ON `gateway_groups` (`org_id`, `name`);
-- Create "orgs" table
CREATE TABLE `orgs` (`id` text NOT NULL, `name` text NOT NULL, `slug` text NOT NULL, `created_at` datetime NOT NULL, PRIMARY KEY (`id`));
-- Create index "orgs_slug_key" to table: "orgs"
CREATE UNIQUE INDEX `orgs_slug_key` ON `orgs` (`slug`);
