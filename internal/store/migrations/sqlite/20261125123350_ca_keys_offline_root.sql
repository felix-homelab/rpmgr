-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_ca_keys" table
CREATE TABLE `new_ca_keys` (`id` text NOT NULL, `kind` text NOT NULL, `algorithm` text NOT NULL, `public_key` blob NOT NULL, `certificate` blob NULL, `csr` blob NULL, `key_enc` blob NULL, `not_before` datetime NOT NULL, `not_after` datetime NOT NULL, `status` text NOT NULL, PRIMARY KEY (`id`));
-- Copy rows from old table "ca_keys" to new temporary table "new_ca_keys"
INSERT INTO `new_ca_keys` (`id`, `kind`, `algorithm`, `public_key`, `certificate`, `key_enc`, `not_before`, `not_after`, `status`) SELECT `id`, `kind`, `algorithm`, `public_key`, `certificate`, `key_enc`, `not_before`, `not_after`, `status` FROM `ca_keys`;
-- Drop "ca_keys" table after copying rows
DROP TABLE `ca_keys`;
-- Rename temporary table "new_ca_keys" to "ca_keys"
ALTER TABLE `new_ca_keys` RENAME TO `ca_keys`;
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
