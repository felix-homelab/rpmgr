-- Create "port_allocations" table
CREATE TABLE "port_allocations" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "protocol" character varying NOT NULL, "port" bigint NOT NULL, "route_id" character varying NULL, "gateway_group_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "port_allocations_gateway_groups_group" FOREIGN KEY ("gateway_group_id") REFERENCES "gateway_groups" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "port_allocations_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "portallocation_gateway_group_id_protocol_port" to table: "port_allocations"
CREATE UNIQUE INDEX "portallocation_gateway_group_id_protocol_port" ON "port_allocations" ("gateway_group_id", "protocol", "port");
-- Create index "portallocation_org_id_id" to table: "port_allocations"
CREATE UNIQUE INDEX "portallocation_org_id_id" ON "port_allocations" ("org_id", "id");
-- Create "port_pools" table
CREATE TABLE "port_pools" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "protocol" character varying NOT NULL, "port_from" bigint NOT NULL, "port_to" bigint NOT NULL, "gateway_group_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "port_pools_gateway_groups_group" FOREIGN KEY ("org_id", "gateway_group_id") REFERENCES "gateway_groups" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "port_pools_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "portpool_org_id_id" to table: "port_pools"
CREATE UNIQUE INDEX "portpool_org_id_id" ON "port_pools" ("org_id", "id");
-- Create "port_quotas" table
CREATE TABLE "port_quotas" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "protocol" character varying NOT NULL, "max_ports" bigint NOT NULL, "gateway_group_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "port_quotas_gateway_groups_group" FOREIGN KEY ("org_id", "gateway_group_id") REFERENCES "gateway_groups" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "port_quotas_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "portquota_org_id_gateway_group_id_protocol" to table: "port_quotas"
CREATE UNIQUE INDEX "portquota_org_id_gateway_group_id_protocol" ON "port_quotas" ("org_id", "gateway_group_id", "protocol");
-- Create index "portquota_org_id_id" to table: "port_quotas"
CREATE UNIQUE INDEX "portquota_org_id_id" ON "port_quotas" ("org_id", "id");
-- Create "routes" table
CREATE TABLE "routes" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "name" character varying NOT NULL, "type" character varying NOT NULL, "enabled" boolean NOT NULL DEFAULT true, "transport" character varying NULL, "description" character varying NOT NULL DEFAULT '', "labels" jsonb NULL, "version" bigint NOT NULL DEFAULT 1, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "updated_by" character varying NOT NULL DEFAULT '', "gateway_group_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "routes_gateway_groups_group" FOREIGN KEY ("gateway_group_id") REFERENCES "gateway_groups" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "routes_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "route_org_id_id" to table: "routes"
CREATE UNIQUE INDEX "route_org_id_id" ON "routes" ("org_id", "id");
-- Create index "route_org_id_name" to table: "routes"
CREATE UNIQUE INDEX "route_org_id_name" ON "routes" ("org_id", "name");
-- Create "route_targets" table
CREATE TABLE "route_targets" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "kind" character varying NOT NULL, "host" character varying NOT NULL DEFAULT '', "port" bigint NOT NULL DEFAULT 0, "unix_path" character varying NOT NULL DEFAULT '', "upstream_protocol" character varying NOT NULL DEFAULT 'tcp', "tls_server_name" character varying NOT NULL DEFAULT '', "tls_spki_sha256" character varying NOT NULL DEFAULT '', "proxy_protocol" character varying NOT NULL DEFAULT 'none', "weight" bigint NOT NULL DEFAULT 1, "priority" bigint NOT NULL DEFAULT 0, "enabled" boolean NOT NULL DEFAULT true, "route_id" character varying NOT NULL, "connector_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "route_targets_connectors_connector" FOREIGN KEY ("org_id", "connector_id") REFERENCES "connectors" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "route_targets_routes_route" FOREIGN KEY ("org_id", "route_id") REFERENCES "routes" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "route_targets_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetarget_connector_id" to table: "route_targets"
CREATE INDEX "routetarget_connector_id" ON "route_targets" ("connector_id");
-- Create index "routetarget_org_id_id" to table: "route_targets"
CREATE UNIQUE INDEX "routetarget_org_id_id" ON "route_targets" ("org_id", "id");
-- Create index "routetarget_route_id" to table: "route_targets"
CREATE INDEX "routetarget_route_id" ON "route_targets" ("route_id");
-- Create "route_tcp" table
CREATE TABLE "route_tcp" ("id" bigint NOT NULL GENERATED BY DEFAULT AS IDENTITY, "org_id" character varying NOT NULL, "listener_mode" character varying NOT NULL DEFAULT 'plain', "idle_timeout_seconds" bigint NOT NULL DEFAULT 3600, "route_id" character varying NOT NULL, "port_allocation_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "route_tcp_port_allocations_port" FOREIGN KEY ("org_id", "port_allocation_id") REFERENCES "port_allocations" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "route_tcp_routes_route" FOREIGN KEY ("org_id", "route_id") REFERENCES "routes" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "route_tcp_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetcp_org_id_id" to table: "route_tcp"
CREATE UNIQUE INDEX "routetcp_org_id_id" ON "route_tcp" ("org_id", "id");
