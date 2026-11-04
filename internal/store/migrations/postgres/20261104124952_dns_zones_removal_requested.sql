-- Modify "dns_zones" table
ALTER TABLE "dns_zones" ADD COLUMN "removal_requested" boolean NOT NULL DEFAULT false;
