-- Create "connectors" table
CREATE TABLE "connectors" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "name" character varying NOT NULL, "labels" jsonb NULL, "spiffe_id" character varying NOT NULL, "pubkey_sha256" character varying NOT NULL, "ephemeral" boolean NOT NULL DEFAULT false, "enabled" boolean NOT NULL DEFAULT true, "transport" character varying NULL, "desired_version" character varying NULL, "created_at" timestamptz NOT NULL, "decommissioned_at" timestamptz NULL, PRIMARY KEY ("id"), CONSTRAINT "connectors_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "connector_org_id_id" to table: "connectors"
CREATE UNIQUE INDEX "connector_org_id_id" ON "connectors" ("org_id", "id");
-- Create index "connector_org_id_name" to table: "connectors"
CREATE UNIQUE INDEX "connector_org_id_name" ON "connectors" ("org_id", "name");
-- Modify "gateway_groups" table
ALTER TABLE "gateway_groups" ADD COLUMN "region" character varying NULL, ADD COLUMN "public_hostnames" jsonb NULL, ADD COLUMN "trusted_proxy_cidrs" jsonb NULL;
-- Create "gateways" table
CREATE TABLE "gateways" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "name" character varying NOT NULL, "slot" bigint NOT NULL, "tunnel_endpoints" jsonb NOT NULL, "spiffe_id" character varying NULL, "pubkey_sha256" character varying NULL, "enabled" boolean NOT NULL DEFAULT true, "desired_version" character varying NULL, "created_at" timestamptz NOT NULL, "decommissioned_at" timestamptz NULL, "gateway_group_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "gateways_gateway_groups_group" FOREIGN KEY ("org_id", "gateway_group_id") REFERENCES "gateway_groups" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "gateways_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "gateway_gateway_group_id_slot" to table: "gateways"
CREATE UNIQUE INDEX "gateway_gateway_group_id_slot" ON "gateways" ("gateway_group_id", "slot") WHERE (decommissioned_at IS NULL);
-- Create index "gateway_org_id_id" to table: "gateways"
CREATE UNIQUE INDEX "gateway_org_id_id" ON "gateways" ("org_id", "id");
-- Create index "gateway_org_id_name" to table: "gateways"
CREATE UNIQUE INDEX "gateway_org_id_name" ON "gateways" ("org_id", "name");
-- Create "enrollment_tokens" table
CREATE TABLE "enrollment_tokens" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "token_hash" bytea NOT NULL, "role" character varying NOT NULL, "labels" jsonb NULL, "ephemeral" boolean NOT NULL DEFAULT false, "max_uses" bigint NOT NULL DEFAULT 1, "use_count" bigint NOT NULL DEFAULT 0, "expires_at" timestamptz NOT NULL, "created_by" character varying NOT NULL, "created_at" timestamptz NOT NULL, "last_used_at" timestamptz NULL, "last_used_ip" character varying NULL, "revoked_at" timestamptz NULL, "gateway_group_id" character varying NULL, "gateway_id" character varying NULL, "connector_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "enrollment_tokens_connectors_connector" FOREIGN KEY ("org_id", "connector_id") REFERENCES "connectors" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "enrollment_tokens_gateway_groups_group" FOREIGN KEY ("org_id", "gateway_group_id") REFERENCES "gateway_groups" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "enrollment_tokens_gateways_gateway" FOREIGN KEY ("org_id", "gateway_id") REFERENCES "gateways" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "enrollment_tokens_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "enrollment_tokens_token_hash_key" to table: "enrollment_tokens"
CREATE UNIQUE INDEX "enrollment_tokens_token_hash_key" ON "enrollment_tokens" ("token_hash");
-- Create index "enrollmenttoken_org_id_id" to table: "enrollment_tokens"
CREATE UNIQUE INDEX "enrollmenttoken_org_id_id" ON "enrollment_tokens" ("org_id", "id");
