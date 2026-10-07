-- Create "agent_state" table
CREATE TABLE `agent_state` (`agent_id` text NOT NULL, `org_id` text NOT NULL, `boot_id` text NOT NULL DEFAULT (''), `clock_offset_ms` integer NOT NULL DEFAULT (0), `applied_db_epoch` text NOT NULL DEFAULT (''), `applied_seq` integer NOT NULL DEFAULT (0), `applied_hash` blob NULL, `last_ack_at` datetime NULL, `pushed_db_epoch` text NOT NULL DEFAULT (''), `pushed_seq` integer NOT NULL DEFAULT (0), `pushed_hash` blob NULL, `pushed_at` datetime NULL, `rejected_db_epoch` text NOT NULL DEFAULT (''), `rejected_seq` integer NOT NULL DEFAULT (0), `rejected_hash` blob NULL, `last_rejection` json NULL, PRIMARY KEY (`agent_id`), CONSTRAINT `agent_state_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "agentstate_org_id_agent_id" to table: "agent_state"
CREATE UNIQUE INDEX `agentstate_org_id_agent_id` ON `agent_state` (`org_id`, `agent_id`);
-- Create "compiled_snapshots" table
CREATE TABLE `compiled_snapshots` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `agent_id` text NOT NULL, `db_epoch` text NOT NULL, `seq` integer NOT NULL, `hash` blob NOT NULL, `size_bytes` integer NOT NULL, `payload` blob NOT NULL, `signature` blob NOT NULL, `key_id` text NOT NULL, `created_at` datetime NOT NULL, CONSTRAINT `compiled_snapshots_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "compiledsnapshot_org_id_id" to table: "compiled_snapshots"
CREATE UNIQUE INDEX `compiledsnapshot_org_id_id` ON `compiled_snapshots` (`org_id`, `id`);
-- Create index "compiledsnapshot_agent_id_id" to table: "compiled_snapshots"
CREATE INDEX `compiledsnapshot_agent_id_id` ON `compiled_snapshots` (`agent_id`, `id`);
