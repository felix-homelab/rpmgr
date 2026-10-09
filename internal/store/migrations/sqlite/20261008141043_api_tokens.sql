-- Create "api_tokens" table
CREATE TABLE `api_tokens` (`id` text NOT NULL, `org_id` text NOT NULL, `owner_type` text NOT NULL, `owner_id` text NOT NULL, `name` text NOT NULL, `prefix` text NOT NULL, `token_hash` blob NOT NULL, `scopes` json NOT NULL, `mfa` bool NOT NULL DEFAULT (false), `created_at` datetime NOT NULL, `expires_at` datetime NOT NULL, `last_used_at` datetime NULL, `last_used_ip` text NULL, `revoked_at` datetime NULL, PRIMARY KEY (`id`), CONSTRAINT `api_tokens_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "apitoken_org_id_id" to table: "api_tokens"
CREATE UNIQUE INDEX `apitoken_org_id_id` ON `api_tokens` (`org_id`, `id`);
-- Create index "apitoken_token_hash" to table: "api_tokens"
CREATE UNIQUE INDEX `apitoken_token_hash` ON `api_tokens` (`token_hash`);
-- Create index "apitoken_org_id_owner_id" to table: "api_tokens"
CREATE INDEX `apitoken_org_id_owner_id` ON `api_tokens` (`org_id`, `owner_id`);
