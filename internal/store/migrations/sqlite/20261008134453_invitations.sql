-- Create "invitations" table
CREATE TABLE `invitations` (`id` text NOT NULL, `org_id` text NOT NULL, `email` text NOT NULL, `role` text NOT NULL, `token_hash` blob NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `expires_at` datetime NOT NULL, `accepted_at` datetime NULL, `accepted_by` text NULL, PRIMARY KEY (`id`), CONSTRAINT `invitations_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "invitation_org_id_id" to table: "invitations"
CREATE UNIQUE INDEX `invitation_org_id_id` ON `invitations` (`org_id`, `id`);
-- Create index "invitation_token_hash" to table: "invitations"
CREATE UNIQUE INDEX `invitation_token_hash` ON `invitations` (`token_hash`);
