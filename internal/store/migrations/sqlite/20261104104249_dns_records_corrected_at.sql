-- Add column "corrected_at" to table: "dns_records"
ALTER TABLE `dns_records` ADD COLUMN `corrected_at` datetime NULL;
