-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_issued_certificates" table
CREATE TABLE `new_issued_certificates` (`serial` text NOT NULL, `org_id` text NULL, `subject_type` text NOT NULL, `subject_id` text NOT NULL, `spiffe_id` text NOT NULL, `pubkey_sha256` text NOT NULL, `not_before` datetime NOT NULL, `not_after` datetime NOT NULL, `first_seen_at` datetime NULL, `superseded_at` datetime NULL, `revoked_at` datetime NULL, `revocation_reason` text NOT NULL DEFAULT (''), `certificate` blob NULL, `enrollment_token_id` text NULL, PRIMARY KEY (`serial`), CONSTRAINT `issued_certificates_enrollment_tokens_enrollment_token` FOREIGN KEY (`org_id`, `enrollment_token_id`) REFERENCES `enrollment_tokens` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `issued_certificates_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "issued_certificates" to new temporary table "new_issued_certificates"
INSERT INTO `new_issued_certificates` (`serial`, `org_id`, `subject_type`, `subject_id`, `spiffe_id`, `pubkey_sha256`, `not_before`, `not_after`, `first_seen_at`, `superseded_at`, `revoked_at`, `revocation_reason`) SELECT `serial`, `org_id`, `subject_type`, `subject_id`, `spiffe_id`, `pubkey_sha256`, `not_before`, `not_after`, `first_seen_at`, `superseded_at`, `revoked_at`, `revocation_reason` FROM `issued_certificates`;
-- Drop "issued_certificates" table after copying rows
DROP TABLE `issued_certificates`;
-- Rename temporary table "new_issued_certificates" to "issued_certificates"
ALTER TABLE `new_issued_certificates` RENAME TO `issued_certificates`;
-- Create index "issuedcertificate_subject_id" to table: "issued_certificates"
CREATE INDEX `issuedcertificate_subject_id` ON `issued_certificates` (`subject_id`);
-- Create index "issuedcertificate_enrollment_token_id" to table: "issued_certificates"
CREATE INDEX `issuedcertificate_enrollment_token_id` ON `issued_certificates` (`enrollment_token_id`);
-- Create "new_enrollment_tokens" table
CREATE TABLE `new_enrollment_tokens` (`id` text NOT NULL, `org_id` text NOT NULL, `token_hash` blob NOT NULL, `role` text NOT NULL, `labels` json NULL, `ephemeral` bool NOT NULL DEFAULT (false), `max_uses` integer NULL, `use_count` integer NOT NULL DEFAULT (0), `expires_at` datetime NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `last_used_at` datetime NULL, `last_used_ip` text NULL, `revoked_at` datetime NULL, `gateway_group_id` text NULL, `gateway_id` text NULL, `connector_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `enrollment_tokens_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_gateways_gateway` FOREIGN KEY (`org_id`, `gateway_id`) REFERENCES `gateways` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_connectors_connector` FOREIGN KEY (`org_id`, `connector_id`) REFERENCES `connectors` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Copy rows from old table "enrollment_tokens" to new temporary table "new_enrollment_tokens"
INSERT INTO `new_enrollment_tokens` (`id`, `org_id`, `token_hash`, `role`, `labels`, `ephemeral`, `max_uses`, `use_count`, `expires_at`, `created_by`, `created_at`, `last_used_at`, `last_used_ip`, `revoked_at`, `gateway_group_id`, `gateway_id`, `connector_id`) SELECT `id`, `org_id`, `token_hash`, `role`, `labels`, `ephemeral`, `max_uses`, `use_count`, `expires_at`, `created_by`, `created_at`, `last_used_at`, `last_used_ip`, `revoked_at`, `gateway_group_id`, `gateway_id`, `connector_id` FROM `enrollment_tokens`;
-- Drop "enrollment_tokens" table after copying rows
DROP TABLE `enrollment_tokens`;
-- Rename temporary table "new_enrollment_tokens" to "enrollment_tokens"
ALTER TABLE `new_enrollment_tokens` RENAME TO `enrollment_tokens`;
-- Create index "enrollment_tokens_token_hash_key" to table: "enrollment_tokens"
CREATE UNIQUE INDEX `enrollment_tokens_token_hash_key` ON `enrollment_tokens` (`token_hash`);
-- Create index "enrollmenttoken_org_id_id" to table: "enrollment_tokens"
CREATE UNIQUE INDEX `enrollmenttoken_org_id_id` ON `enrollment_tokens` (`org_id`, `id`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
