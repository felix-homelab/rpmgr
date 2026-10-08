-- Create "users" table
CREATE TABLE "users" ("id" character varying NOT NULL, "email" character varying NOT NULL, "display_name" character varying NOT NULL, "password_hash" character varying NULL, "status" character varying NOT NULL DEFAULT 'active', "instance_admin" boolean NOT NULL DEFAULT false, "created_at" timestamptz NOT NULL, "last_login_at" timestamptz NULL, PRIMARY KEY ("id"));
-- Create index "user_email" to table: "users"
CREATE UNIQUE INDEX "user_email" ON "users" ("email");
-- Create "memberships" table
CREATE TABLE "memberships" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "role" character varying NOT NULL, "created_by" character varying NOT NULL, "created_at" timestamptz NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "memberships_users_memberships" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "memberships_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "membership_org_id_id" to table: "memberships"
CREATE UNIQUE INDEX "membership_org_id_id" ON "memberships" ("org_id", "id");
-- Create index "membership_org_id_user_id" to table: "memberships"
CREATE UNIQUE INDEX "membership_org_id_user_id" ON "memberships" ("org_id", "user_id");
-- Create "password_resets" table
CREATE TABLE "password_resets" ("id" character varying NOT NULL, "token_hash" bytea NOT NULL, "created_by" character varying NOT NULL, "created_at" timestamptz NOT NULL, "expires_at" timestamptz NOT NULL, "used_at" timestamptz NULL, "user_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "password_resets_users_user" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "passwordreset_token_hash" to table: "password_resets"
CREATE UNIQUE INDEX "passwordreset_token_hash" ON "password_resets" ("token_hash");
