-- Modify "connectors" table
ALTER TABLE "connectors" ADD COLUMN "built_in" boolean NOT NULL DEFAULT false;
-- Modify "enrollment_tokens" table
ALTER TABLE "enrollment_tokens" ADD COLUMN "built_in" boolean NOT NULL DEFAULT false;
-- Modify "gateways" table
ALTER TABLE "gateways" ADD COLUMN "built_in" boolean NOT NULL DEFAULT false;
