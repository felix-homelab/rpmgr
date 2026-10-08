-- Modify "agent_sessions" table
ALTER TABLE "agent_sessions" ADD COLUMN "disconnected_at" timestamptz NULL;
