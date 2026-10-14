-- Modify "route_http" table
ALTER TABLE "route_http" ADD COLUMN "maintenance" boolean NOT NULL DEFAULT false, ADD COLUMN "maintenance_message" character varying NOT NULL DEFAULT '';
