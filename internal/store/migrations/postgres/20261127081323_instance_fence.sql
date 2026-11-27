-- Modify "instance" table
ALTER TABLE "instance" ADD COLUMN "active_node" character varying NULL, ADD COLUMN "fence_epoch" bigint NULL;
