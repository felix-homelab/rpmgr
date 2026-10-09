-- Create "invitations" table
CREATE TABLE "invitations" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "email" character varying NOT NULL, "role" character varying NOT NULL, "token_hash" bytea NOT NULL, "created_by" character varying NOT NULL, "created_at" timestamptz NOT NULL, "expires_at" timestamptz NOT NULL, "accepted_at" timestamptz NULL, "accepted_by" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "invitations_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "invitation_org_id_id" to table: "invitations"
CREATE UNIQUE INDEX "invitation_org_id_id" ON "invitations" ("org_id", "id");
-- Create index "invitation_token_hash" to table: "invitations"
CREATE UNIQUE INDEX "invitation_token_hash" ON "invitations" ("token_hash");
