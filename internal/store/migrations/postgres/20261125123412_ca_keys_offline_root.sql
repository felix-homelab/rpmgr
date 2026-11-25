-- Modify "ca_keys" table
ALTER TABLE "ca_keys" ALTER COLUMN "certificate" DROP NOT NULL, ADD COLUMN "csr" bytea NULL;
