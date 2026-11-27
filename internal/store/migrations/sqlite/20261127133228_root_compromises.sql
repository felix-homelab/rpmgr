-- Create "root_compromises" table
CREATE TABLE `root_compromises` (`id` text NOT NULL, `chain` text NOT NULL, `root_hash` text NOT NULL, `seq` integer NOT NULL, `created_at` datetime NOT NULL, PRIMARY KEY (`id`));
-- Create index "rootcompromise_chain_root_hash" to table: "root_compromises"
CREATE UNIQUE INDEX `rootcompromise_chain_root_hash` ON `root_compromises` (`chain`, `root_hash`);
