-- Modify "rollout_targets" table
ALTER TABLE "rollout_targets" ADD COLUMN "position" bigint NULL;
-- Create index "rollouttarget_rollout_id_position" to table: "rollout_targets"
CREATE UNIQUE INDEX "rollouttarget_rollout_id_position" ON "rollout_targets" ("rollout_id", "position");
-- Modify "rollouts" table
ALTER TABLE "rollouts" ADD COLUMN "mode" character varying NOT NULL DEFAULT 'advanced';
