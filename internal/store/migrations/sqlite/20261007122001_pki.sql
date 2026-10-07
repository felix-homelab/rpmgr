-- Create "ca_keys" table
CREATE TABLE `ca_keys` (`id` text NOT NULL, `kind` text NOT NULL, `algorithm` text NOT NULL, `public_key` blob NOT NULL, `certificate` blob NOT NULL, `key_enc` blob NULL, `not_before` datetime NOT NULL, `not_after` datetime NOT NULL, `status` text NOT NULL, PRIMARY KEY (`id`));
-- Create "issued_certificates" table
CREATE TABLE `issued_certificates` (`serial` text NOT NULL, `org_id` text NULL, `subject_type` text NOT NULL, `subject_id` text NOT NULL, `spiffe_id` text NOT NULL, `pubkey_sha256` text NOT NULL, `not_before` datetime NOT NULL, `not_after` datetime NOT NULL, `first_seen_at` datetime NULL, `superseded_at` datetime NULL, `revoked_at` datetime NULL, `revocation_reason` text NOT NULL DEFAULT (''), PRIMARY KEY (`serial`), CONSTRAINT `issued_certificates_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "issuedcertificate_subject_id" to table: "issued_certificates"
CREATE INDEX `issuedcertificate_subject_id` ON `issued_certificates` (`subject_id`);
-- Create "secrets_meta" table
CREATE TABLE `secrets_meta` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `table_name` text NOT NULL, `row_id` text NOT NULL, `column_name` text NOT NULL, `kek_version` text NOT NULL, `created_at` datetime NOT NULL);
-- Create index "secretmeta_table_name_row_id_column_name" to table: "secrets_meta"
CREATE UNIQUE INDEX `secretmeta_table_name_row_id_column_name` ON `secrets_meta` (`table_name`, `row_id`, `column_name`);
