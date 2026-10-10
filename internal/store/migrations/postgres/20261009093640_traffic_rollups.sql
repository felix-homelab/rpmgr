-- Create "route_traffic_daily" table
CREATE TABLE "route_traffic_daily" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "route_id" character varying NOT NULL, "bucket" timestamptz NOT NULL, "bytes_in" bigint NOT NULL, "bytes_out" bigint NOT NULL, "connections" bigint NOT NULL, "errors" bigint NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "route_traffic_daily_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetrafficdaily_bucket" to table: "route_traffic_daily"
CREATE INDEX "routetrafficdaily_bucket" ON "route_traffic_daily" ("bucket");
-- Create index "routetrafficdaily_org_id_id" to table: "route_traffic_daily"
CREATE UNIQUE INDEX "routetrafficdaily_org_id_id" ON "route_traffic_daily" ("org_id", "id");
-- Create index "routetrafficdaily_route_id_bucket" to table: "route_traffic_daily"
CREATE UNIQUE INDEX "routetrafficdaily_route_id_bucket" ON "route_traffic_daily" ("route_id", "bucket");
-- Create "route_traffic_hourly" table
CREATE TABLE "route_traffic_hourly" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "route_id" character varying NOT NULL, "bucket" timestamptz NOT NULL, "bytes_in" bigint NOT NULL, "bytes_out" bigint NOT NULL, "connections" bigint NOT NULL, "errors" bigint NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "route_traffic_hourly_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetraffichourly_bucket" to table: "route_traffic_hourly"
CREATE INDEX "routetraffichourly_bucket" ON "route_traffic_hourly" ("bucket");
-- Create index "routetraffichourly_org_id_id" to table: "route_traffic_hourly"
CREATE UNIQUE INDEX "routetraffichourly_org_id_id" ON "route_traffic_hourly" ("org_id", "id");
-- Create index "routetraffichourly_route_id_bucket" to table: "route_traffic_hourly"
CREATE UNIQUE INDEX "routetraffichourly_route_id_bucket" ON "route_traffic_hourly" ("route_id", "bucket");
-- Create "traffic_baselines" table
CREATE TABLE "traffic_baselines" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "gateway_id" character varying NOT NULL, "route_id" character varying NOT NULL, "boot_id" character varying NOT NULL DEFAULT '', "bytes_in" bigint NOT NULL, "bytes_out" bigint NOT NULL, "connections" bigint NOT NULL, "errors" bigint NOT NULL, "reported_at" timestamptz NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "traffic_baselines_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "trafficbaseline_gateway_id_route_id" to table: "traffic_baselines"
CREATE UNIQUE INDEX "trafficbaseline_gateway_id_route_id" ON "traffic_baselines" ("gateway_id", "route_id");
-- Create index "trafficbaseline_org_id_id" to table: "traffic_baselines"
CREATE UNIQUE INDEX "trafficbaseline_org_id_id" ON "traffic_baselines" ("org_id", "id");
