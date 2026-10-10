-- Modify "route_targets" table
ALTER TABLE "route_targets" ADD COLUMN "version" bigint NOT NULL DEFAULT 1;
