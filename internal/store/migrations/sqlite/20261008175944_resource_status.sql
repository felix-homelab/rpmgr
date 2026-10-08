-- Create "resource_status" table
CREATE TABLE `resource_status` (`id` text NOT NULL, `org_id` text NOT NULL, `agent_id` text NOT NULL, `resource_id` text NOT NULL, `reason` text NOT NULL, `detail` text NOT NULL DEFAULT (''), `since` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `resource_status_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "resourcestatus_org_id_id" to table: "resource_status"
CREATE UNIQUE INDEX `resourcestatus_org_id_id` ON `resource_status` (`org_id`, `id`);
-- Create index "resourcestatus_agent_id_resource_id" to table: "resource_status"
CREATE UNIQUE INDEX `resourcestatus_agent_id_resource_id` ON `resource_status` (`agent_id`, `resource_id`);
