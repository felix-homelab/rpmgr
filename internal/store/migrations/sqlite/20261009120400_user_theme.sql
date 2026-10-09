-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_users" table
CREATE TABLE `new_users` (`id` text NOT NULL, `email` text NOT NULL, `display_name` text NOT NULL, `password_hash` text NULL, `status` text NOT NULL DEFAULT ('active'), `instance_admin` bool NOT NULL DEFAULT (false), `created_at` datetime NOT NULL, `last_login_at` datetime NULL, `theme` text NOT NULL DEFAULT ('system'), PRIMARY KEY (`id`));
-- Copy rows from old table "users" to new temporary table "new_users"
INSERT INTO `new_users` (`id`, `email`, `display_name`, `password_hash`, `status`, `instance_admin`, `created_at`, `last_login_at`) SELECT `id`, `email`, `display_name`, `password_hash`, `status`, `instance_admin`, `created_at`, `last_login_at` FROM `users`;
-- Drop "users" table after copying rows
DROP TABLE `users`;
-- Rename temporary table "new_users" to "users"
ALTER TABLE `new_users` RENAME TO `users`;
-- Create index "user_email" to table: "users"
CREATE UNIQUE INDEX `user_email` ON `users` (`email`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
