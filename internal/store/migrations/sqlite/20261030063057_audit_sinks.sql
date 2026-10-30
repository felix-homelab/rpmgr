-- Create "audit_sinks" table
CREATE TABLE `audit_sinks` (`id` text NOT NULL, `kind` text NOT NULL, `name` text NOT NULL, `settings` json NULL, `secret_enc` blob NULL, `entries` bool NOT NULL DEFAULT (false), `enabled` bool NOT NULL DEFAULT (true), `last_error` text NOT NULL DEFAULT (''), `last_success_at` datetime NULL, `created_at` datetime NOT NULL, PRIMARY KEY (`id`));
-- Create index "auditsink_name" to table: "audit_sinks"
CREATE UNIQUE INDEX `auditsink_name` ON `audit_sinks` (`name`);
-- Create "audit_sink_cursors" table
CREATE TABLE `audit_sink_cursors` (`id` text NOT NULL, `chain` text NOT NULL, `entry_seq` integer NOT NULL DEFAULT (0), `checkpoint_seq` integer NOT NULL DEFAULT (0), `oldest_unshipped_at` datetime NULL, `sink_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `audit_sink_cursors_audit_sinks_sink` FOREIGN KEY (`sink_id`) REFERENCES `audit_sinks` (`id`) ON DELETE CASCADE);
-- Create index "auditsinkcursor_sink_id_chain" to table: "audit_sink_cursors"
CREATE UNIQUE INDEX `auditsinkcursor_sink_id_chain` ON `audit_sink_cursors` (`sink_id`, `chain`);
