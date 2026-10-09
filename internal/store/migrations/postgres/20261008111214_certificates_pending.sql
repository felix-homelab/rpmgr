-- Modify "certificates" table
ALTER TABLE "certificates" ALTER COLUMN "not_before" DROP NOT NULL, ALTER COLUMN "not_after" DROP NOT NULL, ALTER COLUMN "chain" DROP NOT NULL, ALTER COLUMN "key_enc" DROP NOT NULL, ALTER COLUMN "content_sha256" DROP NOT NULL;
