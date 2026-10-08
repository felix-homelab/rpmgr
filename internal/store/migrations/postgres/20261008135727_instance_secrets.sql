-- Create "instance_secrets" table
CREATE TABLE "instance_secrets" ("name" character varying NOT NULL, "value_enc" bytea NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("name"));
