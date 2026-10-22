-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_agent_sessions" table
CREATE TABLE `new_agent_sessions` (`agent_id` text NOT NULL, `org_id` text NOT NULL, `session_epoch` integer NOT NULL, `controller_node` text NOT NULL, `remote_addr` text NOT NULL DEFAULT (''), `agent_version` text NOT NULL DEFAULT (''), `capabilities` json NULL, `connected_at` datetime NOT NULL, `last_seen_at` datetime NOT NULL, `disconnected_at` datetime NULL, `last_goodbye` text NOT NULL DEFAULT (''), PRIMARY KEY (`agent_id`), CONSTRAINT `agent_sessions_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "agent_sessions" to new temporary table "new_agent_sessions"
INSERT INTO `new_agent_sessions` (`agent_id`, `org_id`, `session_epoch`, `controller_node`, `remote_addr`, `agent_version`, `capabilities`, `connected_at`, `last_seen_at`, `disconnected_at`) SELECT `agent_id`, `org_id`, `session_epoch`, `controller_node`, `remote_addr`, `agent_version`, `capabilities`, `connected_at`, `last_seen_at`, `disconnected_at` FROM `agent_sessions`;
-- Drop "agent_sessions" table after copying rows
DROP TABLE `agent_sessions`;
-- Rename temporary table "new_agent_sessions" to "agent_sessions"
ALTER TABLE `new_agent_sessions` RENAME TO `agent_sessions`;
-- Create index "agentsession_org_id_agent_id" to table: "agent_sessions"
CREATE UNIQUE INDEX `agentsession_org_id_agent_id` ON `agent_sessions` (`org_id`, `agent_id`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
