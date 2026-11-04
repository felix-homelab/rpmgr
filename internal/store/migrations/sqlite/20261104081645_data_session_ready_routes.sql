-- Add column "ready_routes" to table: "data_sessions"
ALTER TABLE `data_sessions` ADD COLUMN `ready_routes` json NULL;
