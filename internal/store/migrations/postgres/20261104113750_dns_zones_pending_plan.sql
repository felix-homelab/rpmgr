-- Modify "dns_zones" table
ALTER TABLE "dns_zones" ADD COLUMN "pending_plan" bytea NULL, ADD COLUMN "pending_plan_hash" character varying NOT NULL DEFAULT '';
