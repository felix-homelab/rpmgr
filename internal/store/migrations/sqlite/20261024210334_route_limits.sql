-- Create "route_limits" table
CREATE TABLE `route_limits` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `max_connections` integer NOT NULL DEFAULT (0), `requests_per_sec` integer NOT NULL DEFAULT (0), `bandwidth_bytes_per_sec` integer NOT NULL DEFAULT (0), `route_id` text NOT NULL, CONSTRAINT `route_limits_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_limits_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routelimit_org_id_id" to table: "route_limits"
CREATE UNIQUE INDEX `routelimit_org_id_id` ON `route_limits` (`org_id`, `id`);
-- Create index "routelimit_route_id" to table: "route_limits"
CREATE UNIQUE INDEX `routelimit_route_id` ON `route_limits` (`route_id`);
