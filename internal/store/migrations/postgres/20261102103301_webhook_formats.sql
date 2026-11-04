-- Modify "webhooks" table
ALTER TABLE "webhooks" ADD COLUMN "format" character varying NOT NULL DEFAULT 'rpmgr', ADD COLUMN "url_enc" bytea NULL;
