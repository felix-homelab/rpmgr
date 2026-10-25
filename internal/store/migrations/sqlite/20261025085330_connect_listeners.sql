-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_route_tcp" table
CREATE TABLE `new_route_tcp` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `listener_mode` text NOT NULL DEFAULT ('plain'), `idle_timeout_seconds` integer NOT NULL DEFAULT (3600), `route_id` text NOT NULL, `port_allocation_id` text NULL, `connect_listener_id` text NULL, CONSTRAINT `route_tcp_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_tcp_port_allocations_port` FOREIGN KEY (`org_id`, `port_allocation_id`) REFERENCES `port_allocations` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_tcp_connect_listeners_listener` FOREIGN KEY (`org_id`, `connect_listener_id`) REFERENCES `connect_listeners` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_tcp_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "route_tcp" to new temporary table "new_route_tcp"
INSERT INTO `new_route_tcp` (`id`, `org_id`, `listener_mode`, `idle_timeout_seconds`, `route_id`, `port_allocation_id`) SELECT `id`, `org_id`, `listener_mode`, `idle_timeout_seconds`, `route_id`, `port_allocation_id` FROM `route_tcp`;
-- Drop "route_tcp" table after copying rows
DROP TABLE `route_tcp`;
-- Rename temporary table "new_route_tcp" to "route_tcp"
ALTER TABLE `new_route_tcp` RENAME TO `route_tcp`;
-- Create index "routetcp_org_id_id" to table: "route_tcp"
CREATE UNIQUE INDEX `routetcp_org_id_id` ON `route_tcp` (`org_id`, `id`);
-- Create index "routetcp_route_id" to table: "route_tcp"
CREATE UNIQUE INDEX `routetcp_route_id` ON `route_tcp` (`route_id`);
-- Create index "routetcp_port_allocation_id" to table: "route_tcp"
CREATE UNIQUE INDEX `routetcp_port_allocation_id` ON `route_tcp` (`port_allocation_id`);
-- Create index "routetcp_connect_listener_id" to table: "route_tcp"
CREATE INDEX `routetcp_connect_listener_id` ON `route_tcp` (`connect_listener_id`);
-- Create "connect_authorities" table
CREATE TABLE `connect_authorities` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `authority` text NOT NULL, `connect_listener_id` text NOT NULL, `route_id` text NOT NULL, CONSTRAINT `connect_authorities_connect_listeners_listener` FOREIGN KEY (`org_id`, `connect_listener_id`) REFERENCES `connect_listeners` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `connect_authorities_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `connect_authorities_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "connectauthority_org_id_id" to table: "connect_authorities"
CREATE UNIQUE INDEX `connectauthority_org_id_id` ON `connect_authorities` (`org_id`, `id`);
-- Create index "connectauthority_connect_listener_id_authority" to table: "connect_authorities"
CREATE UNIQUE INDEX `connectauthority_connect_listener_id_authority` ON `connect_authorities` (`connect_listener_id`, `authority`);
-- Create index "connectauthority_route_id" to table: "connect_authorities"
CREATE INDEX `connectauthority_route_id` ON `connect_authorities` (`route_id`);
-- Create "connect_listeners" table
CREATE TABLE `connect_listeners` (`id` text NOT NULL, `org_id` text NOT NULL, `gateway_group_id` text NOT NULL, `auth_mode` text NOT NULL, `hostname` text NOT NULL DEFAULT (''), `port_allocation_id` text NOT NULL, `certificate_id` text NULL, `domain_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `connect_listeners_port_allocations_port` FOREIGN KEY (`org_id`, `port_allocation_id`) REFERENCES `port_allocations` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `connect_listeners_certificates_certificate` FOREIGN KEY (`org_id`, `certificate_id`) REFERENCES `certificates` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `connect_listeners_domains_domain` FOREIGN KEY (`org_id`, `domain_id`) REFERENCES `domains` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `connect_listeners_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "connectlistener_org_id_id" to table: "connect_listeners"
CREATE UNIQUE INDEX `connectlistener_org_id_id` ON `connect_listeners` (`org_id`, `id`);
-- Create index "connectlistener_port_allocation_id" to table: "connect_listeners"
CREATE UNIQUE INDEX `connectlistener_port_allocation_id` ON `connect_listeners` (`port_allocation_id`);
-- Create index "connectlistener_gateway_group_id" to table: "connect_listeners"
CREATE INDEX `connectlistener_gateway_group_id` ON `connect_listeners` (`gateway_group_id`);
-- Create index "connectlistener_certificate_id" to table: "connect_listeners"
CREATE INDEX `connectlistener_certificate_id` ON `connect_listeners` (`certificate_id`);
-- Create index "connectlistener_domain_id" to table: "connect_listeners"
CREATE INDEX `connectlistener_domain_id` ON `connect_listeners` (`domain_id`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
