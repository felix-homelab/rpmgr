-- Modify "dns_records" table
ALTER TABLE "dns_records" ADD COLUMN "corrected_at" timestamptz NULL;
