-- Modify "config_revisions" table
ALTER TABLE "config_revisions" ADD COLUMN "org_id" character varying NULL, ADD CONSTRAINT "config_revisions_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Create index "configrevision_org_id_seq" to table: "config_revisions"
CREATE INDEX "configrevision_org_id_seq" ON "config_revisions" ("org_id", "seq");
