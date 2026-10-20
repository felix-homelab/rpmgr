-- Create "releases" table
CREATE TABLE "releases" ("id" character varying NOT NULL, "version" character varying NOT NULL, "channel" character varying NOT NULL, "manifest_seq" bigint NOT NULL, "manifest" bytea NOT NULL, "signature" bytea NOT NULL, "signing_key_statement" bytea NOT NULL, "statement_signature" bytea NOT NULL, "source" character varying NOT NULL, "mirrored_at" timestamptz NULL, "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "release_version" to table: "releases"
CREATE UNIQUE INDEX "release_version" ON "releases" ("version");
-- Create "rollouts" table
CREATE TABLE "rollouts" ("id" character varying NOT NULL, "version" bigint NOT NULL DEFAULT 1, "stage" character varying NOT NULL DEFAULT 'canary', "percentage" bigint NOT NULL DEFAULT 0, "state" character varying NOT NULL DEFAULT 'running', "active" boolean NOT NULL DEFAULT true, "pause_reason" character varying NOT NULL DEFAULT '', "created_by" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_by" character varying NOT NULL DEFAULT '', "updated_at" timestamptz NOT NULL, "release_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "rollouts_releases_release" FOREIGN KEY ("release_id") REFERENCES "releases" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "rollout_active" to table: "rollouts"
CREATE UNIQUE INDEX "rollout_active" ON "rollouts" ("active") WHERE active;
-- Create "rollout_targets" table
CREATE TABLE "rollout_targets" ("id" character varying NOT NULL, "agent_id" character varying NOT NULL, "agent_kind" character varying NOT NULL, "canary" boolean NOT NULL DEFAULT false, "bucket" bigint NOT NULL, "state" character varying NOT NULL DEFAULT 'pending', "reason" character varying NOT NULL DEFAULT '', "version_before" character varying NOT NULL DEFAULT '', "updated_at" timestamptz NOT NULL, "rollout_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "rollout_targets_rollouts_rollout" FOREIGN KEY ("rollout_id") REFERENCES "rollouts" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "rollouttarget_agent_id" to table: "rollout_targets"
CREATE INDEX "rollouttarget_agent_id" ON "rollout_targets" ("agent_id");
-- Create index "rollouttarget_rollout_id_agent_id" to table: "rollout_targets"
CREATE UNIQUE INDEX "rollouttarget_rollout_id_agent_id" ON "rollout_targets" ("rollout_id", "agent_id");
