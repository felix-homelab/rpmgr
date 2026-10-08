-- Create "api_requests" table
CREATE TABLE "api_requests" ("id" character varying NOT NULL, "caller_id" character varying NOT NULL, "method" character varying NOT NULL, "request_id" character varying NOT NULL, "request_hash" bytea NOT NULL, "response_enc" bytea NULL, "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "apirequest_caller_id_method_request_id" to table: "api_requests"
CREATE UNIQUE INDEX "apirequest_caller_id_method_request_id" ON "api_requests" ("caller_id", "method", "request_id");
-- Create index "apirequest_created_at" to table: "api_requests"
CREATE INDEX "apirequest_created_at" ON "api_requests" ("created_at");
