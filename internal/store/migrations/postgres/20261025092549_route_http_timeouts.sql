-- Modify "route_http" table
ALTER TABLE "route_http" ADD COLUMN "upstream_response_header_timeout_seconds" bigint NOT NULL DEFAULT 0, ADD COLUMN "upstream_idle_timeout_seconds" bigint NOT NULL DEFAULT 0;
