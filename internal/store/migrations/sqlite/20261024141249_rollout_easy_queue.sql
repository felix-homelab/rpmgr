-- Disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- Create "new_rollouts" table
CREATE TABLE `new_rollouts` (`id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `mode` text NOT NULL DEFAULT ('advanced'), `stage` text NOT NULL DEFAULT ('canary'), `percentage` integer NOT NULL DEFAULT (0), `state` text NOT NULL DEFAULT ('running'), `active` bool NOT NULL DEFAULT (true), `pause_reason` text NOT NULL DEFAULT (''), `created_by` text NOT NULL, `created_at` datetime NOT NULL, `updated_by` text NOT NULL DEFAULT (''), `updated_at` datetime NOT NULL, `release_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `rollouts_releases_release` FOREIGN KEY (`release_id`) REFERENCES `releases` (`id`) ON DELETE NO ACTION);
-- Copy rows from old table "rollouts" to new temporary table "new_rollouts"
INSERT INTO `new_rollouts` (`id`, `version`, `stage`, `percentage`, `state`, `active`, `pause_reason`, `created_by`, `created_at`, `updated_by`, `updated_at`, `release_id`) SELECT `id`, `version`, `stage`, `percentage`, `state`, `active`, `pause_reason`, `created_by`, `created_at`, `updated_by`, `updated_at`, `release_id` FROM `rollouts`;
-- Drop "rollouts" table after copying rows
DROP TABLE `rollouts`;
-- Rename temporary table "new_rollouts" to "rollouts"
ALTER TABLE `new_rollouts` RENAME TO `rollouts`;
-- Create index "rollout_active" to table: "rollouts"
CREATE UNIQUE INDEX `rollout_active` ON `rollouts` (`active`) WHERE active;
-- Create "new_rollout_targets" table
CREATE TABLE `new_rollout_targets` (`id` text NOT NULL, `agent_id` text NOT NULL, `agent_kind` text NOT NULL, `canary` bool NOT NULL DEFAULT (false), `bucket` integer NOT NULL, `position` integer NULL, `state` text NOT NULL DEFAULT ('pending'), `reason` text NOT NULL DEFAULT (''), `version_before` text NOT NULL DEFAULT (''), `drain_started_at` datetime NULL, `updated_at` datetime NOT NULL, `rollout_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `rollout_targets_rollouts_rollout` FOREIGN KEY (`rollout_id`) REFERENCES `rollouts` (`id`) ON DELETE NO ACTION);
-- Copy rows from old table "rollout_targets" to new temporary table "new_rollout_targets"
INSERT INTO `new_rollout_targets` (`id`, `agent_id`, `agent_kind`, `canary`, `bucket`, `state`, `reason`, `version_before`, `drain_started_at`, `updated_at`, `rollout_id`) SELECT `id`, `agent_id`, `agent_kind`, `canary`, `bucket`, `state`, `reason`, `version_before`, `drain_started_at`, `updated_at`, `rollout_id` FROM `rollout_targets`;
-- Drop "rollout_targets" table after copying rows
DROP TABLE `rollout_targets`;
-- Rename temporary table "new_rollout_targets" to "rollout_targets"
ALTER TABLE `new_rollout_targets` RENAME TO `rollout_targets`;
-- Create index "rollouttarget_rollout_id_agent_id" to table: "rollout_targets"
CREATE UNIQUE INDEX `rollouttarget_rollout_id_agent_id` ON `rollout_targets` (`rollout_id`, `agent_id`);
-- Create index "rollouttarget_rollout_id_position" to table: "rollout_targets"
CREATE UNIQUE INDEX `rollouttarget_rollout_id_position` ON `rollout_targets` (`rollout_id`, `position`);
-- Create index "rollouttarget_agent_id" to table: "rollout_targets"
CREATE INDEX `rollouttarget_agent_id` ON `rollout_targets` (`agent_id`);
-- Enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;
