-- Modify "dns_zones" table
ALTER TABLE "dns_zones" ADD COLUMN "sync_requested_at" timestamptz NULL;
