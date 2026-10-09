-- Modify "route_http" table
ALTER TABLE "route_http" ADD COLUMN "hsts_max_age_seconds" bigint NOT NULL DEFAULT 0;
