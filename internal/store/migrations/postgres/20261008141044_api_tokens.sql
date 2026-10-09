-- Create "api_tokens" table
CREATE TABLE "api_tokens" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "owner_type" character varying NOT NULL, "owner_id" character varying NOT NULL, "name" character varying NOT NULL, "prefix" character varying NOT NULL, "token_hash" bytea NOT NULL, "scopes" jsonb NOT NULL, "mfa" boolean NOT NULL DEFAULT false, "created_at" timestamptz NOT NULL, "expires_at" timestamptz NOT NULL, "last_used_at" timestamptz NULL, "last_used_ip" character varying NULL, "revoked_at" timestamptz NULL, PRIMARY KEY ("id"), CONSTRAINT "api_tokens_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "apitoken_org_id_id" to table: "api_tokens"
CREATE UNIQUE INDEX "apitoken_org_id_id" ON "api_tokens" ("org_id", "id");
-- Create index "apitoken_org_id_owner_id" to table: "api_tokens"
CREATE INDEX "apitoken_org_id_owner_id" ON "api_tokens" ("org_id", "owner_id");
-- Create index "apitoken_token_hash" to table: "api_tokens"
CREATE UNIQUE INDEX "apitoken_token_hash" ON "api_tokens" ("token_hash");
