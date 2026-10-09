-- Create "recovery_codes" table
CREATE TABLE "recovery_codes" ("id" character varying NOT NULL, "code_hash" bytea NOT NULL, "created_at" timestamptz NOT NULL, "used_at" timestamptz NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "recovery_codes_users_user" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "recoverycode_code_hash" to table: "recovery_codes"
CREATE UNIQUE INDEX "recoverycode_code_hash" ON "recovery_codes" ("code_hash");
-- Create index "recoverycode_user_id" to table: "recovery_codes"
CREATE INDEX "recoverycode_user_id" ON "recovery_codes" ("user_id");
-- Create "totp_credentials" table
CREATE TABLE "totp_credentials" ("id" character varying NOT NULL, "seed_enc" bytea NOT NULL, "created_at" timestamptz NOT NULL, "confirmed_at" timestamptz NULL, "last_step" bigint NOT NULL DEFAULT 0, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "totp_credentials_users_user" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "totpcredential_user_id" to table: "totp_credentials"
CREATE UNIQUE INDEX "totpcredential_user_id" ON "totp_credentials" ("user_id");
