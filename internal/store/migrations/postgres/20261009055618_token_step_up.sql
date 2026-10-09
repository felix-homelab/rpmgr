-- Modify "api_tokens" table
ALTER TABLE "api_tokens" ADD COLUMN "step_up_at" timestamptz NULL;
