-- Drop index "routehostname_gateway_group_id_hostname_path_prefix" from table: "route_hostnames"
DROP INDEX "routehostname_gateway_group_id_hostname_path_prefix";
-- Modify "route_hostnames" table
ALTER TABLE "route_hostnames" ADD COLUMN "match_key" character varying NOT NULL DEFAULT '';
-- Create index "routehostname_gateway_group_id_hostname_path_prefix_match_key" to table: "route_hostnames"
CREATE UNIQUE INDEX "routehostname_gateway_group_id_hostname_path_prefix_match_key" ON "route_hostnames" ("gateway_group_id", "hostname", "path_prefix", "match_key");
-- Modify "route_http" table
ALTER TABLE "route_http" ADD COLUMN "match_key" character varying NOT NULL DEFAULT '';
