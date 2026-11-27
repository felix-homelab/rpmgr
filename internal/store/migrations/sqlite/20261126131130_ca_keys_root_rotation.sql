-- Add column "cross_certificate" to table: "ca_keys"
ALTER TABLE `ca_keys` ADD COLUMN `cross_certificate` blob NULL;
-- Add column "rotated_at" to table: "ca_keys"
ALTER TABLE `ca_keys` ADD COLUMN `rotated_at` datetime NULL;
