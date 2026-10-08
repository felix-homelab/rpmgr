-- Add column "disconnected_at" to table: "agent_sessions"
ALTER TABLE `agent_sessions` ADD COLUMN `disconnected_at` datetime NULL;
