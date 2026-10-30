-- Create "status_marks" table
CREATE TABLE `status_marks` (`id` text NOT NULL, `org_id` text NULL, `state` text NOT NULL, `changed_at` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `status_marks_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
