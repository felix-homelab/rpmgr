-- Create "domains" table
CREATE TABLE "domains" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "fqdn" character varying NOT NULL, "wildcard" boolean NOT NULL DEFAULT false, "status" character varying NOT NULL DEFAULT 'pending', "method" character varying NOT NULL DEFAULT 'dns_txt', "challenge_value" character varying NOT NULL, "created_at" timestamptz NOT NULL, "verified_at" timestamptz NULL, "last_checked_at" timestamptz NULL, "version" bigint NOT NULL DEFAULT 1, PRIMARY KEY ("id"), CONSTRAINT "domains_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "domain_fqdn" to table: "domains"
CREATE UNIQUE INDEX "domain_fqdn" ON "domains" ("fqdn");
-- Create index "domain_org_id_id" to table: "domains"
CREATE UNIQUE INDEX "domain_org_id_id" ON "domains" ("org_id", "id");
