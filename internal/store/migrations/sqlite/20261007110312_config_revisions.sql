-- Create "config_revisions" table
CREATE TABLE `config_revisions` (`seq` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `db_epoch` text NOT NULL, `actor` text NOT NULL, `changed_resources` json NULL, `created_at` datetime NOT NULL);
-- Create "config_seq" table
CREATE TABLE `config_seq` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `seq` integer NOT NULL);
-- Create "instance" table
CREATE TABLE `instance` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `trust_domain` text NOT NULL, `db_epoch` text NOT NULL, `created_at` datetime NOT NULL);
