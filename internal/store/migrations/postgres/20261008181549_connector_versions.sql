-- Modify "connectors" table
ALTER TABLE "connectors" ADD COLUMN "version" bigint NOT NULL DEFAULT 1;
