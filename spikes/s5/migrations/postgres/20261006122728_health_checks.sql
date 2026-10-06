-- Modify "routes" table
ALTER TABLE "routes" ADD COLUMN "description" character varying NOT NULL DEFAULT '';
-- Create "health_checks" table
CREATE TABLE "health_checks" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "type" character varying NOT NULL, "interval_seconds" bigint NOT NULL DEFAULT 10, PRIMARY KEY ("id"), CONSTRAINT "health_checks_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "healthcheck_org_id_id" to table: "health_checks"
CREATE UNIQUE INDEX "healthcheck_org_id_id" ON "health_checks" ("org_id", "id");
-- Modify "route_targets" table
ALTER TABLE "route_targets" ADD COLUMN "health_check_id" character varying NULL, ADD CONSTRAINT "route_targets_health_checks_targets" FOREIGN KEY ("org_id", "health_check_id") REFERENCES "health_checks" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION;
