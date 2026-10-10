-- Modify "domains" table
ALTER TABLE "domains" ADD COLUMN "last_error" character varying NOT NULL DEFAULT '';
