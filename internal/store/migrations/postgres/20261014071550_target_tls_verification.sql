-- Modify "route_targets" table
ALTER TABLE "route_targets" ADD COLUMN "tls_verification" character varying NOT NULL DEFAULT 'verified';
