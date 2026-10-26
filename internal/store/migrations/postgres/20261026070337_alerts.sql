-- Create "alerts" table
CREATE TABLE "alerts" ("id" character varying NOT NULL, "org_id" character varying NULL, "kind" character varying NOT NULL, "subject_type" character varying NOT NULL, "subject_id" character varying NOT NULL, "subject_name" character varying NOT NULL DEFAULT '', "state" character varying NOT NULL, "since" timestamptz NOT NULL, "fired_at" timestamptz NULL, "resolved_at" timestamptz NULL, PRIMARY KEY ("id"), CONSTRAINT "alerts_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "alert_org_id_state" to table: "alerts"
CREATE INDEX "alert_org_id_state" ON "alerts" ("org_id", "state");
-- Create index "alert_state" to table: "alerts"
CREATE INDEX "alert_state" ON "alerts" ("state");
