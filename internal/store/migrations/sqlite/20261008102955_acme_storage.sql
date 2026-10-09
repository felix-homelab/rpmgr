-- Create "acme_storage" table
CREATE TABLE `acme_storage` (`key` text NOT NULL, `value_enc` blob NOT NULL, `size` integer NOT NULL, `modified_at` datetime NOT NULL, PRIMARY KEY (`key`));
