-- Create "route_http" table
CREATE TABLE `route_http` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `path_prefix` text NOT NULL DEFAULT (''), `header_matches` json NULL, `tls_mode` text NOT NULL DEFAULT ('acme'), `port80` text NOT NULL DEFAULT ('redirect'), `host_header` text NOT NULL DEFAULT ('preserve'), `request_headers_set` json NULL, `response_headers_set` json NULL, `websocket` bool NOT NULL DEFAULT (true), `max_body_bytes` integer NOT NULL DEFAULT (0), `dns_proxied` bool NOT NULL DEFAULT (false), `route_id` text NOT NULL, `certificate_id` text NULL, CONSTRAINT `route_http_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_http_certificates_certificate` FOREIGN KEY (`org_id`, `certificate_id`) REFERENCES `certificates` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_http_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routehttp_org_id_id" to table: "route_http"
CREATE UNIQUE INDEX `routehttp_org_id_id` ON `route_http` (`org_id`, `id`);
-- Create index "routehttp_route_id" to table: "route_http"
CREATE UNIQUE INDEX `routehttp_route_id` ON `route_http` (`route_id`);
-- Create index "routehttp_certificate_id" to table: "route_http"
CREATE INDEX `routehttp_certificate_id` ON `route_http` (`certificate_id`);
