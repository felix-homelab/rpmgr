-- Modify "agent_sessions" table
ALTER TABLE "agent_sessions" ADD COLUMN "update_auto" character varying NOT NULL DEFAULT '', ADD COLUMN "update_channel" character varying NOT NULL DEFAULT '';
