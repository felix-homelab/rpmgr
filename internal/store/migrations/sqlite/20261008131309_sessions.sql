-- Create "sessions" table
CREATE TABLE `sessions` (`id` text NOT NULL, `token_hash` blob NOT NULL, `created_at` datetime NOT NULL, `last_seen_at` datetime NOT NULL, `idle_expires_at` datetime NOT NULL, `absolute_expires_at` datetime NOT NULL, `elevated_until` datetime NULL, `amr` json NOT NULL, `ip` text NOT NULL, `user_agent` text NOT NULL, `revoked_at` datetime NULL, `user_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `sessions_users_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE);
-- Create index "session_token_hash" to table: "sessions"
CREATE UNIQUE INDEX `session_token_hash` ON `sessions` (`token_hash`);
-- Create index "session_user_id" to table: "sessions"
CREATE INDEX `session_user_id` ON `sessions` (`user_id`);
