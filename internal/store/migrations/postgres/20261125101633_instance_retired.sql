-- Modify "instance" table
ALTER TABLE "instance" ADD COLUMN "retired_at" timestamptz NULL, ADD COLUMN "retired_to" character varying NULL;
