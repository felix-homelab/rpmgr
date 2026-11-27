-- Add column "active_node" to table: "instance"
ALTER TABLE `instance` ADD COLUMN `active_node` text NULL;
-- Add column "fence_epoch" to table: "instance"
ALTER TABLE `instance` ADD COLUMN `fence_epoch` integer NULL;
