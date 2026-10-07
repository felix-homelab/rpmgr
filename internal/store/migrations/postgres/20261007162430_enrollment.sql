-- Modify "enrollment_tokens" table
ALTER TABLE "enrollment_tokens" ALTER COLUMN "max_uses" DROP NOT NULL, ALTER COLUMN "max_uses" DROP DEFAULT;
-- Modify "issued_certificates" table
ALTER TABLE "issued_certificates" ADD COLUMN "certificate" bytea NULL, ADD COLUMN "enrollment_token_id" character varying NULL, ADD CONSTRAINT "issued_certificates_enrollment_tokens_enrollment_token" FOREIGN KEY ("org_id", "enrollment_token_id") REFERENCES "enrollment_tokens" ("org_id", "id") ON UPDATE NO ACTION ON DELETE NO ACTION;
-- Create index "issuedcertificate_enrollment_token_id" to table: "issued_certificates"
CREATE INDEX "issuedcertificate_enrollment_token_id" ON "issued_certificates" ("enrollment_token_id");
