-- Modify "api_tokens" table
ALTER TABLE "api_tokens" ADD COLUMN "suspended_at" timestamptz NULL;
-- Modify "instance" table
ALTER TABLE "instance" ADD COLUMN "restore_review_since" timestamptz NULL;
-- Modify "orgs" table
ALTER TABLE "orgs" ADD COLUMN "restore_review_since" timestamptz NULL;
