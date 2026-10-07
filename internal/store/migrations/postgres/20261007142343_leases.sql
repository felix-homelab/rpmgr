-- Create "leases" table
CREATE TABLE "leases" ("name" character varying NOT NULL, "holder" character varying NOT NULL, "fencing_token" bigint NOT NULL, "expires_at" bigint NOT NULL, PRIMARY KEY ("name"));
