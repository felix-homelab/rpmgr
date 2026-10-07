-- Create "audit_log" table
CREATE TABLE `audit_log` (`id` text NOT NULL, `org_id` text NULL, `seq` integer NOT NULL, `prev_hash` blob NOT NULL, `hash` blob NOT NULL, `ts` datetime NOT NULL, `actor_type` text NOT NULL, `actor_id` text NOT NULL DEFAULT (''), `credential_id` text NOT NULL DEFAULT (''), `auth_method` text NOT NULL DEFAULT (''), `ip` text NOT NULL DEFAULT (''), `user_agent` text NOT NULL DEFAULT (''), `request_id` text NOT NULL DEFAULT (''), `action` text NOT NULL, `target_type` text NOT NULL DEFAULT (''), `target_id` text NOT NULL DEFAULT (''), `result` text NOT NULL, `diff` text NOT NULL DEFAULT (''), `reason` text NOT NULL DEFAULT (''), PRIMARY KEY (`id`), CONSTRAINT `audit_log_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "auditentry_org_id_seq" to table: "audit_log"
CREATE UNIQUE INDEX `auditentry_org_id_seq` ON `audit_log` (`org_id`, `seq`);
-- Create index "auditentry_instance_seq" to table: "audit_log"
CREATE UNIQUE INDEX `auditentry_instance_seq` ON `audit_log` (`seq`) WHERE org_id IS NULL;
-- Create "audit_heads" table
CREATE TABLE `audit_heads` (`chain` text NOT NULL, `seq` integer NOT NULL, `hash` blob NOT NULL, PRIMARY KEY (`chain`));
