-- Create "events" table
CREATE TABLE "events" ("id" character varying NOT NULL, "org_id" character varying NULL, "type" character varying NOT NULL, "ts" timestamptz NOT NULL, "actor_type" character varying NOT NULL, "actor_id" character varying NOT NULL DEFAULT '', "subject_type" character varying NOT NULL DEFAULT '', "subject_id" character varying NOT NULL DEFAULT '', "subject_name" character varying NOT NULL DEFAULT '', "summary" character varying NOT NULL DEFAULT '', "changed" jsonb NULL, PRIMARY KEY ("id"), CONSTRAINT "events_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "event_org_id_id" to table: "events"
CREATE INDEX "event_org_id_id" ON "events" ("org_id", "id");
-- Create index "event_ts" to table: "events"
CREATE INDEX "event_ts" ON "events" ("ts");
