-- Create "access_policies" table
CREATE TABLE `access_policies` (`id` text NOT NULL, `org_id` text NOT NULL, `name` text NOT NULL, `description` text NOT NULL DEFAULT (''), `version` integer NOT NULL DEFAULT (1), PRIMARY KEY (`id`), CONSTRAINT `access_policies_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "accesspolicy_org_id_id" to table: "access_policies"
CREATE UNIQUE INDEX `accesspolicy_org_id_id` ON `access_policies` (`org_id`, `id`);
-- Create index "accesspolicy_org_id_name" to table: "access_policies"
CREATE UNIQUE INDEX `accesspolicy_org_id_name` ON `access_policies` (`org_id`, `name`);
-- Create "policy_rules" table
CREATE TABLE `policy_rules` (`id` text NOT NULL, `org_id` text NOT NULL, `position` integer NOT NULL, `kind` text NOT NULL, `params` blob NOT NULL, `policy_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `policy_rules_access_policies_policy` FOREIGN KEY (`org_id`, `policy_id`) REFERENCES `access_policies` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `policy_rules_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "policyrule_org_id_id" to table: "policy_rules"
CREATE UNIQUE INDEX `policyrule_org_id_id` ON `policy_rules` (`org_id`, `id`);
-- Create index "policyrule_policy_id_position" to table: "policy_rules"
CREATE UNIQUE INDEX `policyrule_policy_id_position` ON `policy_rules` (`policy_id`, `position`);
-- Create "route_policies" table
CREATE TABLE `route_policies` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `position` integer NOT NULL, `route_id` text NOT NULL, `policy_id` text NOT NULL, CONSTRAINT `route_policies_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_policies_access_policies_policy` FOREIGN KEY (`org_id`, `policy_id`) REFERENCES `access_policies` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_policies_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routepolicy_org_id_id" to table: "route_policies"
CREATE UNIQUE INDEX `routepolicy_org_id_id` ON `route_policies` (`org_id`, `id`);
-- Create index "routepolicy_route_id_policy_id" to table: "route_policies"
CREATE UNIQUE INDEX `routepolicy_route_id_policy_id` ON `route_policies` (`route_id`, `policy_id`);
-- Create index "routepolicy_route_id_position" to table: "route_policies"
CREATE UNIQUE INDEX `routepolicy_route_id_position` ON `route_policies` (`route_id`, `position`);
-- Create index "routepolicy_policy_id" to table: "route_policies"
CREATE INDEX `routepolicy_policy_id` ON `route_policies` (`policy_id`);
