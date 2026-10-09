-- Add column "restore_review_since" to table: "orgs"
ALTER TABLE `orgs` ADD COLUMN `restore_review_since` datetime NULL;
-- Add column "restore_review_since" to table: "instance"
ALTER TABLE `instance` ADD COLUMN `restore_review_since` datetime NULL;
-- Add column "suspended_at" to table: "api_tokens"
ALTER TABLE `api_tokens` ADD COLUMN `suspended_at` datetime NULL;
