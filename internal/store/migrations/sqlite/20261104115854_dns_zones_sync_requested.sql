-- Add column "sync_requested_at" to table: "dns_zones"
ALTER TABLE `dns_zones` ADD COLUMN `sync_requested_at` datetime NULL;
