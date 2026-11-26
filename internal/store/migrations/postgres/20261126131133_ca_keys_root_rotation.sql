-- Modify "ca_keys" table
ALTER TABLE "ca_keys" ADD COLUMN "cross_certificate" bytea NULL, ADD COLUMN "rotated_at" timestamptz NULL;
