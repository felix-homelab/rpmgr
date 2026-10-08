-- Create "memberships" table
CREATE TABLE `memberships` (`id` text NOT NULL, `org_id` text NOT NULL, `role` text NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `user_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `memberships_users_memberships` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE NO ACTION, CONSTRAINT `memberships_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "membership_org_id_id" to table: "memberships"
CREATE UNIQUE INDEX `membership_org_id_id` ON `memberships` (`org_id`, `id`);
-- Create index "membership_org_id_user_id" to table: "memberships"
CREATE UNIQUE INDEX `membership_org_id_user_id` ON `memberships` (`org_id`, `user_id`);
-- Create "password_resets" table
CREATE TABLE `password_resets` (`id` text NOT NULL, `token_hash` blob NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `expires_at` datetime NOT NULL, `used_at` datetime NULL, `user_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `password_resets_users_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE);
-- Create index "passwordreset_token_hash" to table: "password_resets"
CREATE UNIQUE INDEX `passwordreset_token_hash` ON `password_resets` (`token_hash`);
-- Create "users" table
CREATE TABLE `users` (`id` text NOT NULL, `email` text NOT NULL, `display_name` text NOT NULL, `password_hash` text NULL, `status` text NOT NULL DEFAULT ('active'), `instance_admin` bool NOT NULL DEFAULT (false), `created_at` datetime NOT NULL, `last_login_at` datetime NULL, PRIMARY KEY (`id`));
-- Create index "user_email" to table: "users"
CREATE UNIQUE INDEX `user_email` ON `users` (`email`);
