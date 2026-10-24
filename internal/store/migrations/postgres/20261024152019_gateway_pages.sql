-- Create "gateway_pages" table
CREATE TABLE "gateway_pages" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "kind" character varying NOT NULL, "html" character varying NOT NULL, "content_sha256" bytea NOT NULL, "updated_at" timestamptz NOT NULL, "updated_by" character varying NULL, "gateway_group_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "gateway_pages_gateway_groups_group" FOREIGN KEY ("org_id", "gateway_group_id") REFERENCES "gateway_groups" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "gateway_pages_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "gatewaypage_gateway_group_id_kind" to table: "gateway_pages"
CREATE UNIQUE INDEX "gatewaypage_gateway_group_id_kind" ON "gateway_pages" ("gateway_group_id", "kind");
-- Create index "gatewaypage_org_id_id" to table: "gateway_pages"
CREATE UNIQUE INDEX "gatewaypage_org_id_id" ON "gateway_pages" ("org_id", "id");
