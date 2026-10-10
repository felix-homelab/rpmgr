-- Create "audit_checkpoints" table
CREATE TABLE "audit_checkpoints" ("id" character varying NOT NULL, "org_id" character varying NULL, "seq" bigint NOT NULL, "head_hash" bytea NOT NULL, "ts" timestamptz NOT NULL, "key_id" character varying NOT NULL, "signature" bytea NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "audit_checkpoints_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "auditcheckpoint_instance_seq" to table: "audit_checkpoints"
CREATE UNIQUE INDEX "auditcheckpoint_instance_seq" ON "audit_checkpoints" ("seq") WHERE (org_id IS NULL);
-- Create index "auditcheckpoint_org_id_seq" to table: "audit_checkpoints"
CREATE UNIQUE INDEX "auditcheckpoint_org_id_seq" ON "audit_checkpoints" ("org_id", "seq");
