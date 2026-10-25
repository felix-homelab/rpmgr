-- Modify "gateways" table
ALTER TABLE "gateways" ADD COLUMN "wss_hostname" character varying NULL;
-- Create index "gateway_wss_hostname" to table: "gateways"
CREATE UNIQUE INDEX "gateway_wss_hostname" ON "gateways" ("wss_hostname");
