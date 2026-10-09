-- Create "resource_status" table
CREATE TABLE "resource_status" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "agent_id" character varying NOT NULL, "resource_id" character varying NOT NULL, "reason" character varying NOT NULL, "detail" character varying NOT NULL DEFAULT '', "since" timestamptz NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "resource_status_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "resourcestatus_agent_id_resource_id" to table: "resource_status"
CREATE UNIQUE INDEX "resourcestatus_agent_id_resource_id" ON "resource_status" ("agent_id", "resource_id");
-- Create index "resourcestatus_org_id_id" to table: "resource_status"
CREATE UNIQUE INDEX "resourcestatus_org_id_id" ON "resource_status" ("org_id", "id");
