-- Create "mail_jobs" table
CREATE TABLE `mail_jobs` (`id` text NOT NULL, `org_id` text NULL, `event_id` text NOT NULL, `state` text NOT NULL, `attempts` integer NOT NULL DEFAULT (0), `next_attempt_at` datetime NOT NULL, `created_at` datetime NOT NULL, `done` json NULL, PRIMARY KEY (`id`), CONSTRAINT `mail_jobs_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "mail_jobs_event_id_key" to table: "mail_jobs"
CREATE UNIQUE INDEX `mail_jobs_event_id_key` ON `mail_jobs` (`event_id`);
-- Create index "mailjob_state_next_attempt_at" to table: "mail_jobs"
CREATE INDEX `mailjob_state_next_attempt_at` ON `mail_jobs` (`state`, `next_attempt_at`);
