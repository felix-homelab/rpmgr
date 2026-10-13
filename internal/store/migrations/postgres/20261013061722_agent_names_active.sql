-- Drop index "connector_org_id_name" from table: "connectors"
DROP INDEX "connector_org_id_name";
-- Create index "connector_org_id_name" to table: "connectors"
CREATE UNIQUE INDEX "connector_org_id_name" ON "connectors" ("org_id", "name") WHERE (decommissioned_at IS NULL);
-- Drop index "gateway_org_id_name" from table: "gateways"
DROP INDEX "gateway_org_id_name";
-- Create index "gateway_org_id_name" to table: "gateways"
CREATE UNIQUE INDEX "gateway_org_id_name" ON "gateways" ("org_id", "name") WHERE (decommissioned_at IS NULL);
