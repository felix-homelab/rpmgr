-- Create "events" table
CREATE TABLE `events` (`id` text NOT NULL, `org_id` text NULL, `type` text NOT NULL, `ts` datetime NOT NULL, `actor_type` text NOT NULL, `actor_id` text NOT NULL DEFAULT (''), `subject_type` text NOT NULL DEFAULT (''), `subject_id` text NOT NULL DEFAULT (''), `subject_name` text NOT NULL DEFAULT (''), `summary` text NOT NULL DEFAULT (''), `changed` json NULL, PRIMARY KEY (`id`), CONSTRAINT `events_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "event_org_id_id" to table: "events"
CREATE INDEX `event_org_id_id` ON `events` (`org_id`, `id`);
-- Create index "event_ts" to table: "events"
CREATE INDEX `event_ts` ON `events` (`ts`);
