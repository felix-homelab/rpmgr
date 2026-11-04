-- Add column "dns_cname" to table: "gateway_groups"
ALTER TABLE `gateway_groups` ADD COLUMN `dns_cname` text NULL;
-- Add column "dns_addresses" to table: "gateway_groups"
ALTER TABLE `gateway_groups` ADD COLUMN `dns_addresses` json NULL;
