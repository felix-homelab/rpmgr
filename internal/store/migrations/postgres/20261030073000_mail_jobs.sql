-- Create "mail_jobs" table
CREATE TABLE "mail_jobs" ("id" character varying NOT NULL, "org_id" character varying NULL, "event_id" character varying NOT NULL, "state" character varying NOT NULL, "attempts" bigint NOT NULL DEFAULT 0, "next_attempt_at" timestamptz NOT NULL, "created_at" timestamptz NOT NULL, "done" jsonb NULL, PRIMARY KEY ("id"), CONSTRAINT "mail_jobs_orgs" FOREIGN KEY ("org_id") REFERENCES "orgs" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "mail_jobs_event_id_key" to table: "mail_jobs"
CREATE UNIQUE INDEX "mail_jobs_event_id_key" ON "mail_jobs" ("event_id");
-- Create index "mailjob_state_next_attempt_at" to table: "mail_jobs"
CREATE INDEX "mailjob_state_next_attempt_at" ON "mail_jobs" ("state", "next_attempt_at");
