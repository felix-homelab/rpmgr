-- Create "ca_bundles" table
CREATE TABLE "ca_bundles" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "name" character varying NOT NULL, "pem" bytea NOT NULL, "created_at" timestamptz NOT NULL, "version" bigint NOT NULL DEFAULT 1, PRIMARY KEY ("id"), CONSTRAINT "ca_bundles_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "cabundle_org_id_id" to table: "ca_bundles"
CREATE UNIQUE INDEX "cabundle_org_id_id" ON "ca_bundles" ("org_id", "id");
-- Create index "cabundle_org_id_name" to table: "ca_bundles"
CREATE UNIQUE INDEX "cabundle_org_id_name" ON "ca_bundles" ("org_id", "name");
-- Modify "route_targets" table
ALTER TABLE "route_targets" ADD COLUMN "tls_ca_bundle_id" character varying NULL, ADD CONSTRAINT "route_targets_ca_bundles_ca_bundle" FOREIGN KEY ("org_id", "tls_ca_bundle_id") REFERENCES "ca_bundles" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Create index "routetarget_tls_ca_bundle_id" to table: "route_targets"
CREATE INDEX "routetarget_tls_ca_bundle_id" ON "route_targets" ("tls_ca_bundle_id");
