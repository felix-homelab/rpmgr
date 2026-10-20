-- Create "releases" table
CREATE TABLE `releases` (`id` text NOT NULL, `version` text NOT NULL, `channel` text NOT NULL, `manifest_seq` integer NOT NULL, `manifest` blob NOT NULL, `signature` blob NOT NULL, `signing_key_statement` blob NOT NULL, `statement_signature` blob NOT NULL, `source` text NOT NULL, `mirrored_at` datetime NULL, `created_at` datetime NOT NULL, PRIMARY KEY (`id`));
-- Create index "release_version" to table: "releases"
CREATE UNIQUE INDEX `release_version` ON `releases` (`version`);
-- Create "rollouts" table
CREATE TABLE `rollouts` (`id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `stage` text NOT NULL DEFAULT ('canary'), `percentage` integer NOT NULL DEFAULT (0), `state` text NOT NULL DEFAULT ('running'), `active` bool NOT NULL DEFAULT (true), `pause_reason` text NOT NULL DEFAULT (''), `created_by` text NOT NULL, `created_at` datetime NOT NULL, `updated_by` text NOT NULL DEFAULT (''), `updated_at` datetime NOT NULL, `release_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `rollouts_releases_release` FOREIGN KEY (`release_id`) REFERENCES `releases` (`id`) ON DELETE NO ACTION);
-- Create index "rollout_active" to table: "rollouts"
CREATE UNIQUE INDEX `rollout_active` ON `rollouts` (`active`) WHERE active;
-- Create "rollout_targets" table
CREATE TABLE `rollout_targets` (`id` text NOT NULL, `agent_id` text NOT NULL, `agent_kind` text NOT NULL, `canary` bool NOT NULL DEFAULT (false), `bucket` integer NOT NULL, `state` text NOT NULL DEFAULT ('pending'), `reason` text NOT NULL DEFAULT (''), `version_before` text NOT NULL DEFAULT (''), `updated_at` datetime NOT NULL, `rollout_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `rollout_targets_rollouts_rollout` FOREIGN KEY (`rollout_id`) REFERENCES `rollouts` (`id`) ON DELETE NO ACTION);
-- Create index "rollouttarget_rollout_id_agent_id" to table: "rollout_targets"
CREATE UNIQUE INDEX `rollouttarget_rollout_id_agent_id` ON `rollout_targets` (`rollout_id`, `agent_id`);
-- Create index "rollouttarget_agent_id" to table: "rollout_targets"
CREATE INDEX `rollouttarget_agent_id` ON `rollout_targets` (`agent_id`);
