-- Create "instance_secrets" table
CREATE TABLE `instance_secrets` (`name` text NOT NULL, `value_enc` blob NOT NULL, `updated_at` datetime NOT NULL, PRIMARY KEY (`name`));
