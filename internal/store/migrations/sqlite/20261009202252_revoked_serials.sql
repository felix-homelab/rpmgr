-- Create "revoked_serials" table
CREATE TABLE `revoked_serials` (`serial` text NOT NULL, `org_id` text NULL, `revoked_at` datetime NOT NULL, `reason` text NOT NULL DEFAULT (''), `not_after` datetime NOT NULL, PRIMARY KEY (`serial`), CONSTRAINT `revoked_serials_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
