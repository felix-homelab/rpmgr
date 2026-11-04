-- Create "dns_records" table
CREATE TABLE "dns_records" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "name" character varying NOT NULL, "type" character varying NOT NULL, "content" character varying NOT NULL, "ttl" bigint NOT NULL, "proxied" boolean NOT NULL DEFAULT false, "provider_record_id" character varying NULL, "state" character varying NOT NULL DEFAULT 'creating', "reason" character varying NOT NULL DEFAULT '', "adopted_from" character varying NOT NULL DEFAULT '', "adopted_at" timestamptz NULL, "last_synced_at" timestamptz NULL, "dns_zone_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "dns_records_dns_zones_zone" FOREIGN KEY ("org_id", "dns_zone_id") REFERENCES "dns_zones" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "dns_records_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "dnsrecord_dns_zone_id_name" to table: "dns_records"
CREATE INDEX "dnsrecord_dns_zone_id_name" ON "dns_records" ("dns_zone_id", "name");
-- Create index "dnsrecord_dns_zone_id_provider_record_id" to table: "dns_records"
CREATE UNIQUE INDEX "dnsrecord_dns_zone_id_provider_record_id" ON "dns_records" ("dns_zone_id", "provider_record_id");
-- Create index "dnsrecord_org_id_id" to table: "dns_records"
CREATE UNIQUE INDEX "dnsrecord_org_id_id" ON "dns_records" ("org_id", "id");
