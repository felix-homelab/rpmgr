-- Create "status_marks" table
CREATE TABLE "status_marks" ("id" character varying NOT NULL, "org_id" character varying NULL, "state" character varying NOT NULL, "changed_at" timestamptz NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "status_marks_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
