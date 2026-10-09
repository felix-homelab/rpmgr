-- Create "data_sessions" table
CREATE TABLE "data_sessions" ("id" character varying NOT NULL, "org_id" character varying NOT NULL, "gateway_id" character varying NOT NULL, "connector_id" character varying NOT NULL, "transport" character varying NOT NULL, "rtt_ms" bigint NOT NULL DEFAULT 0, "established_at" timestamptz NOT NULL, "reported_at" timestamptz NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "data_sessions_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "datasession_connector_id" to table: "data_sessions"
CREATE INDEX "datasession_connector_id" ON "data_sessions" ("connector_id");
-- Create index "datasession_gateway_id_connector_id_transport" to table: "data_sessions"
CREATE UNIQUE INDEX "datasession_gateway_id_connector_id_transport" ON "data_sessions" ("gateway_id", "connector_id", "transport");
-- Create index "datasession_org_id_id" to table: "data_sessions"
CREATE UNIQUE INDEX "datasession_org_id_id" ON "data_sessions" ("org_id", "id");
