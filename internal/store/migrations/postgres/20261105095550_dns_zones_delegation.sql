-- Modify "dns_zones" table
ALTER TABLE "dns_zones" ADD COLUMN "assigned_nameservers" jsonb NULL, ADD COLUMN "delegation_state" character varying NOT NULL DEFAULT 'unknown', ADD COLUMN "delegation_nameservers" jsonb NULL, ADD COLUMN "delegation_checked_at" timestamptz NULL;
