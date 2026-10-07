-- Create "agent_sessions" table
CREATE TABLE "agent_sessions" ("agent_id" character varying NOT NULL, "org_id" character varying NOT NULL, "session_epoch" bigint NOT NULL, "controller_node" character varying NOT NULL, "remote_addr" character varying NOT NULL DEFAULT '', "agent_version" character varying NOT NULL DEFAULT '', "capabilities" jsonb NULL, "connected_at" timestamptz NOT NULL, "last_seen_at" timestamptz NOT NULL, PRIMARY KEY ("agent_id"), CONSTRAINT "agent_sessions_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "agentsession_org_id_agent_id" to table: "agent_sessions"
CREATE UNIQUE INDEX "agentsession_org_id_agent_id" ON "agent_sessions" ("org_id", "agent_id");
