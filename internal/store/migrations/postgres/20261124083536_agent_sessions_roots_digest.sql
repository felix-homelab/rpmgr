-- Modify "agent_sessions" table
ALTER TABLE "agent_sessions" ADD COLUMN "roots_digest" character varying NOT NULL DEFAULT '';
