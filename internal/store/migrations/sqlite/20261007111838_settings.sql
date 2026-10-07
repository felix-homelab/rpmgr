-- Create "instance_settings" table
CREATE TABLE `instance_settings` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `value` blob NOT NULL, `version` integer NOT NULL, `updated_by` text NOT NULL, `updated_at` datetime NOT NULL);
-- Create "org_settings" table
CREATE TABLE `org_settings` (`id` text NOT NULL, `org_id` text NOT NULL, `value` blob NOT NULL, `version` integer NOT NULL, `updated_by` text NOT NULL, `updated_at` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `org_settings_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "orgsetting_org_id_id" to table: "org_settings"
CREATE UNIQUE INDEX `orgsetting_org_id_id` ON `org_settings` (`org_id`, `id`);
-- Create index "orgsetting_org_id" to table: "org_settings"
CREATE UNIQUE INDEX `orgsetting_org_id` ON `org_settings` (`org_id`);
