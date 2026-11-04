-- Create "dns_name_status" table
CREATE TABLE "dns_name_status" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "name" character varying NOT NULL, "status" character varying NOT NULL, "reason" character varying NOT NULL DEFAULT '', "since" timestamptz NOT NULL, "dns_zone_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "dns_name_status_dns_zones_zone" FOREIGN KEY ("org_id", "dns_zone_id") REFERENCES "dns_zones" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "dns_name_status_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "dnsnamestatus_dns_zone_id_name" to table: "dns_name_status"
CREATE UNIQUE INDEX "dnsnamestatus_dns_zone_id_name" ON "dns_name_status" ("dns_zone_id", "name");
-- Create index "dnsnamestatus_org_id_id" to table: "dns_name_status"
CREATE UNIQUE INDEX "dnsnamestatus_org_id_id" ON "dns_name_status" ("org_id", "id");
