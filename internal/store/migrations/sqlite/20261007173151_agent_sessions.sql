-- Create "agent_sessions" table
CREATE TABLE `agent_sessions` (`agent_id` text NOT NULL, `org_id` text NOT NULL, `session_epoch` integer NOT NULL, `controller_node` text NOT NULL, `remote_addr` text NOT NULL DEFAULT (''), `agent_version` text NOT NULL DEFAULT (''), `capabilities` json NULL, `connected_at` datetime NOT NULL, `last_seen_at` datetime NOT NULL, PRIMARY KEY (`agent_id`), CONSTRAINT `agent_sessions_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "agentsession_org_id_agent_id" to table: "agent_sessions"
CREATE UNIQUE INDEX `agentsession_org_id_agent_id` ON `agent_sessions` (`org_id`, `agent_id`);
