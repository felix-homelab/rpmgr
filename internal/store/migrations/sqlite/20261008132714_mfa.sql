-- Create "recovery_codes" table
CREATE TABLE `recovery_codes` (`id` text NOT NULL, `code_hash` blob NOT NULL, `created_at` datetime NOT NULL, `used_at` datetime NULL, `user_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `recovery_codes_users_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE);
-- Create index "recoverycode_code_hash" to table: "recovery_codes"
CREATE UNIQUE INDEX `recoverycode_code_hash` ON `recovery_codes` (`code_hash`);
-- Create index "recoverycode_user_id" to table: "recovery_codes"
CREATE INDEX `recoverycode_user_id` ON `recovery_codes` (`user_id`);
-- Create "totp_credentials" table
CREATE TABLE `totp_credentials` (`id` text NOT NULL, `seed_enc` blob NOT NULL, `created_at` datetime NOT NULL, `confirmed_at` datetime NULL, `last_step` integer NOT NULL DEFAULT (0), `user_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `totp_credentials_users_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE);
-- Create index "totpcredential_user_id" to table: "totp_credentials"
CREATE UNIQUE INDEX `totpcredential_user_id` ON `totp_credentials` (`user_id`);
