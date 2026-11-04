-- Modify "dns_records" table
ALTER TABLE "dns_records" ADD COLUMN "release_requested" character varying NOT NULL DEFAULT '';
