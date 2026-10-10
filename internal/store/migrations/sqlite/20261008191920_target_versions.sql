-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_route_targets" table
CREATE TABLE `new_route_targets` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `kind` text NOT NULL, `host` text NOT NULL DEFAULT (''), `port` integer NOT NULL DEFAULT (0), `unix_path` text NOT NULL DEFAULT (''), `upstream_protocol` text NOT NULL DEFAULT ('tcp'), `tls_server_name` text NOT NULL DEFAULT (''), `tls_spki_sha256` text NOT NULL DEFAULT (''), `proxy_protocol` text NOT NULL DEFAULT ('none'), `weight` integer NOT NULL DEFAULT (1), `priority` integer NOT NULL DEFAULT (0), `enabled` bool NOT NULL DEFAULT (true), `route_id` text NOT NULL, `connector_id` text NOT NULL, `tls_ca_bundle_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `route_targets_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_connectors_connector` FOREIGN KEY (`org_id`, `connector_id`) REFERENCES `connectors` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_ca_bundles_ca_bundle` FOREIGN KEY (`org_id`, `tls_ca_bundle_id`) REFERENCES `ca_bundles` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "route_targets" to new temporary table "new_route_targets"
INSERT INTO `new_route_targets` (`id`, `org_id`, `kind`, `host`, `port`, `unix_path`, `upstream_protocol`, `tls_server_name`, `tls_spki_sha256`, `proxy_protocol`, `weight`, `priority`, `enabled`, `route_id`, `connector_id`, `tls_ca_bundle_id`) SELECT `id`, `org_id`, `kind`, `host`, `port`, `unix_path`, `upstream_protocol`, `tls_server_name`, `tls_spki_sha256`, `proxy_protocol`, `weight`, `priority`, `enabled`, `route_id`, `connector_id`, `tls_ca_bundle_id` FROM `route_targets`;
-- Drop "route_targets" table after copying rows
DROP TABLE `route_targets`;
-- Rename temporary table "new_route_targets" to "route_targets"
ALTER TABLE `new_route_targets` RENAME TO `route_targets`;
-- Create index "routetarget_org_id_id" to table: "route_targets"
CREATE UNIQUE INDEX `routetarget_org_id_id` ON `route_targets` (`org_id`, `id`);
-- Create index "routetarget_route_id" to table: "route_targets"
CREATE INDEX `routetarget_route_id` ON `route_targets` (`route_id`);
-- Create index "routetarget_connector_id" to table: "route_targets"
CREATE INDEX `routetarget_connector_id` ON `route_targets` (`connector_id`);
-- Create index "routetarget_tls_ca_bundle_id" to table: "route_targets"
CREATE INDEX `routetarget_tls_ca_bundle_id` ON `route_targets` (`tls_ca_bundle_id`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
