-- Add column "region" to table: "gateway_groups"
ALTER TABLE `gateway_groups` ADD COLUMN `region` text NULL;
-- Add column "public_hostnames" to table: "gateway_groups"
ALTER TABLE `gateway_groups` ADD COLUMN `public_hostnames` json NULL;
-- Add column "trusted_proxy_cidrs" to table: "gateway_groups"
ALTER TABLE `gateway_groups` ADD COLUMN `trusted_proxy_cidrs` json NULL;
-- Create "connectors" table
CREATE TABLE `connectors` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, `labels` json NULL, `spiffe_id` text NOT NULL, `pubkey_sha256` text NOT NULL, `ephemeral` bool NOT NULL DEFAULT (false), `enabled` bool NOT NULL DEFAULT (true), `transport` text NULL, `desired_version` text NULL, `created_at` datetime NOT NULL, `decommissioned_at` datetime NULL, PRIMARY KEY (`id`), CONSTRAINT `connectors_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "connector_org_id_id" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_id` ON `connectors` (`org_id`, `id`);
-- Create index "connector_org_id_name" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_name` ON `connectors` (`org_id`, `name`);
-- Create "enrollment_tokens" table
CREATE TABLE `enrollment_tokens` (`id` text NOT NULL, `org_id` text NOT NULL, `token_hash` blob NOT NULL, `role` text NOT NULL, `labels` json NULL, `ephemeral` bool NOT NULL DEFAULT (false), `max_uses` integer NOT NULL DEFAULT (1), `use_count` integer NOT NULL DEFAULT (0), `expires_at` datetime NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `last_used_at` datetime NULL, `last_used_ip` text NULL, `revoked_at` datetime NULL, `gateway_group_id` text NULL, `gateway_id` text NULL, `connector_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `enrollment_tokens_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_gateways_gateway` FOREIGN KEY (`org_id`, `gateway_id`) REFERENCES `gateways` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_connectors_connector` FOREIGN KEY (`org_id`, `connector_id`) REFERENCES `connectors` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "enrollment_tokens_token_hash_key" to table: "enrollment_tokens"
CREATE UNIQUE INDEX `enrollment_tokens_token_hash_key` ON `enrollment_tokens` (`token_hash`);
-- Create index "enrollmenttoken_org_id_id" to table: "enrollment_tokens"
CREATE UNIQUE INDEX `enrollmenttoken_org_id_id` ON `enrollment_tokens` (`org_id`, `id`);
-- Create "gateways" table
CREATE TABLE `gateways` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, `slot` integer NOT NULL, `tunnel_endpoints` json NOT NULL, `spiffe_id` text NULL, `pubkey_sha256` text NULL, `enabled` bool NOT NULL DEFAULT (true), `desired_version` text NULL, `created_at` datetime NOT NULL, `decommissioned_at` datetime NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `gateways_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `gateways_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "gateway_org_id_id" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_id` ON `gateways` (`org_id`, `id`);
-- Create index "gateway_org_id_name" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_name` ON `gateways` (`org_id`, `name`);
-- Create index "gateway_gateway_group_id_slot" to table: "gateways"
CREATE UNIQUE INDEX `gateway_gateway_group_id_slot` ON `gateways` (`gateway_group_id`, `slot`) WHERE decommissioned_at IS NULL;
