-- Modify "gateway_groups" table
ALTER TABLE "gateway_groups" ADD COLUMN "dns_cname" character varying NULL, ADD COLUMN "dns_addresses" jsonb NULL;
