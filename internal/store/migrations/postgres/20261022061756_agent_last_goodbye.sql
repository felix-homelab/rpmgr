-- Modify "agent_sessions" table
ALTER TABLE "agent_sessions" ADD COLUMN "last_goodbye" character varying NOT NULL DEFAULT '';
