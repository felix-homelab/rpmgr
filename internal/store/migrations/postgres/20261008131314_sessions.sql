-- Create "sessions" table
CREATE TABLE "sessions" ("id" character varying NOT NULL, "token_hash" bytea NOT NULL, "created_at" timestamptz NOT NULL, "last_seen_at" timestamptz NOT NULL, "idle_expires_at" timestamptz NOT NULL, "absolute_expires_at" timestamptz NOT NULL, "elevated_until" timestamptz NULL, "amr" jsonb NOT NULL, "ip" character varying NOT NULL, "user_agent" character varying NOT NULL, "revoked_at" timestamptz NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "sessions_users_user" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "session_token_hash" to table: "sessions"
CREATE UNIQUE INDEX "session_token_hash" ON "sessions" ("token_hash");
-- Create index "session_user_id" to table: "sessions"
CREATE INDEX "session_user_id" ON "sessions" ("user_id");
