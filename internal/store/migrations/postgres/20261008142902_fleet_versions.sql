-- Modify "gateway_groups" table
ALTER TABLE "gateway_groups" ADD COLUMN "version" bigint NOT NULL DEFAULT 1;
-- Modify "gateways" table
ALTER TABLE "gateways" ADD COLUMN "version" bigint NOT NULL DEFAULT 1;
