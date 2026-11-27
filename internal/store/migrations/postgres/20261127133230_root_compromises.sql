-- Create "root_compromises" table
CREATE TABLE "root_compromises" ("id" character varying NOT NULL, "chain" character varying NOT NULL, "root_hash" character varying NOT NULL, "seq" bigint NOT NULL, "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "rootcompromise_chain_root_hash" to table: "root_compromises"
CREATE UNIQUE INDEX "rootcompromise_chain_root_hash" ON "root_compromises" ("chain", "root_hash");
