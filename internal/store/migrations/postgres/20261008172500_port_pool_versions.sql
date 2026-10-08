-- Modify "port_pools" table
ALTER TABLE "port_pools" ADD COLUMN "version" bigint NOT NULL DEFAULT 1;
