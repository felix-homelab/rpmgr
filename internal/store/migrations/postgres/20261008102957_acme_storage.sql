-- Create "acme_storage" table
CREATE TABLE "acme_storage" ("key" character varying NOT NULL, "value_enc" bytea NOT NULL, "size" bigint NOT NULL, "modified_at" timestamptz NOT NULL, PRIMARY KEY ("key"));
