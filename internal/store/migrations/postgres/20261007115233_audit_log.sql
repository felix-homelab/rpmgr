-- Create "audit_heads" table
CREATE TABLE "audit_heads" ("chain" character varying NOT NULL, "seq" bigint NOT NULL, "hash" bytea NOT NULL, PRIMARY KEY ("chain"));
-- Create "audit_log" table
CREATE TABLE "audit_log" ("id" character varying NOT NULL, "org_id" character varying NULL, "seq" bigint NOT NULL, "prev_hash" bytea NOT NULL, "hash" bytea NOT NULL, "ts" timestamptz NOT NULL, "actor_type" character varying NOT NULL, "actor_id" character varying NOT NULL DEFAULT '', "credential_id" character varying NOT NULL DEFAULT '', "auth_method" character varying NOT NULL DEFAULT '', "ip" character varying NOT NULL DEFAULT '', "user_agent" character varying NOT NULL DEFAULT '', "request_id" character varying NOT NULL DEFAULT '', "action" character varying NOT NULL, "target_type" character varying NOT NULL DEFAULT '', "target_id" character varying NOT NULL DEFAULT '', "result" character varying NOT NULL, "diff" text NOT NULL DEFAULT '', "reason" character varying NOT NULL DEFAULT '', PRIMARY KEY ("id"), CONSTRAINT "audit_log_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "auditentry_instance_seq" to table: "audit_log"
CREATE UNIQUE INDEX "auditentry_instance_seq" ON "audit_log" ("seq") WHERE (org_id IS NULL);
-- Create index "auditentry_org_id_seq" to table: "audit_log"
CREATE UNIQUE INDEX "auditentry_org_id_seq" ON "audit_log" ("org_id", "seq");
