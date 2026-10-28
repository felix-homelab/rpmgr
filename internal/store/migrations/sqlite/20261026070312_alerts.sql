-- Create "alerts" table
CREATE TABLE `alerts` (`id` text NOT NULL, `org_id` text NULL, `kind` text NOT NULL, `subject_type` text NOT NULL, `subject_id` text NOT NULL, `subject_name` text NOT NULL DEFAULT (''), `state` text NOT NULL, `since` datetime NOT NULL, `fired_at` datetime NULL, `resolved_at` datetime NULL, PRIMARY KEY (`id`), CONSTRAINT `alerts_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "alert_state" to table: "alerts"
CREATE INDEX `alert_state` ON `alerts` (`state`);
-- Create index "alert_org_id_state" to table: "alerts"
CREATE INDEX `alert_org_id_state` ON `alerts` (`org_id`, `state`);
