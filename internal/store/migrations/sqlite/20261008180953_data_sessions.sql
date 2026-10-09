-- Create "data_sessions" table
CREATE TABLE `data_sessions` (`id` text NOT NULL, `org_id` text NOT NULL, `gateway_id` text NOT NULL, `connector_id` text NOT NULL, `transport` text NOT NULL, `rtt_ms` integer NOT NULL DEFAULT (0), `established_at` datetime NOT NULL, `reported_at` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `data_sessions_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "datasession_org_id_id" to table: "data_sessions"
CREATE UNIQUE INDEX `datasession_org_id_id` ON `data_sessions` (`org_id`, `id`);
-- Create index "datasession_gateway_id_connector_id_transport" to table: "data_sessions"
CREATE UNIQUE INDEX `datasession_gateway_id_connector_id_transport` ON `data_sessions` (`gateway_id`, `connector_id`, `transport`);
-- Create index "datasession_connector_id" to table: "data_sessions"
CREATE INDEX `datasession_connector_id` ON `data_sessions` (`connector_id`);
