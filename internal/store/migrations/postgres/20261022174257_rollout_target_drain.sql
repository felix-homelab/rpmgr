-- Add column "drain_started_at" to table: "rollout_targets"
ALTER TABLE "rollout_targets" ADD COLUMN "drain_started_at" timestamptz NULL;
