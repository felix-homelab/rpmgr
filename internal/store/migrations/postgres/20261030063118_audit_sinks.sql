-- Create "audit_sinks" table
CREATE TABLE "audit_sinks" ("id" character varying NOT NULL, "kind" character varying NOT NULL, "name" character varying NOT NULL, "settings" jsonb NULL, "secret_enc" bytea NULL, "entries" boolean NOT NULL DEFAULT false, "enabled" boolean NOT NULL DEFAULT true, "last_error" character varying NOT NULL DEFAULT '', "last_success_at" timestamptz NULL, "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "auditsink_name" to table: "audit_sinks"
CREATE UNIQUE INDEX "auditsink_name" ON "audit_sinks" ("name");
-- Create "audit_sink_cursors" table
CREATE TABLE "audit_sink_cursors" ("id" character varying NOT NULL, "chain" character varying NOT NULL, "entry_seq" bigint NOT NULL DEFAULT 0, "checkpoint_seq" bigint NOT NULL DEFAULT 0, "oldest_unshipped_at" timestamptz NULL, "sink_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "audit_sink_cursors_audit_sinks_sink" FOREIGN KEY ("sink_id") REFERENCES "audit_sinks" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "auditsinkcursor_sink_id_chain" to table: "audit_sink_cursors"
CREATE UNIQUE INDEX "auditsinkcursor_sink_id_chain" ON "audit_sink_cursors" ("sink_id", "chain");
