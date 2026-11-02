-- Add column "verification" to table: "audit_sinks"
ALTER TABLE `audit_sinks` ADD COLUMN `verification` json NULL;
