-- Create "leases" table
CREATE TABLE `leases` (`name` text NOT NULL, `holder` text NOT NULL, `fencing_token` integer NOT NULL, `expires_at` integer NOT NULL, PRIMARY KEY (`name`));
