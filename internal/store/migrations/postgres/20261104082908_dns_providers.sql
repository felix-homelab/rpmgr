-- Create "dns_providers" table
CREATE TABLE "dns_providers" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "version" bigint NOT NULL DEFAULT 1, "kind" character varying NOT NULL, "name" character varying NOT NULL, "credential_enc" bytea NOT NULL, "account_id" character varying NOT NULL DEFAULT '', "status" character varying NOT NULL DEFAULT 'ok', "token_expires_at" timestamptz NULL, "last_checked_at" timestamptz NULL, "last_error" character varying NOT NULL DEFAULT '', "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "dns_providers_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "dnsprovider_org_id_id" to table: "dns_providers"
CREATE UNIQUE INDEX "dnsprovider_org_id_id" ON "dns_providers" ("org_id", "id");
-- Create index "dnsprovider_org_id_name" to table: "dns_providers"
CREATE UNIQUE INDEX "dnsprovider_org_id_name" ON "dns_providers" ("org_id", "name");
