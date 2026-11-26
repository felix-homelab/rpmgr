-- Add column "retired_at" to table: "instance"
ALTER TABLE `instance` ADD COLUMN `retired_at` datetime NULL;
-- Add column "retired_to" to table: "instance"
ALTER TABLE `instance` ADD COLUMN `retired_to` text NULL;
