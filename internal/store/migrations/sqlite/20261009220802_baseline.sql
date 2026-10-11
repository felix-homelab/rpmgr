-- Create "acme_storage" table
CREATE TABLE `acme_storage` (`key` text NOT NULL, `value_enc` blob NOT NULL, `size` integer NOT NULL, `modified_at` datetime NOT NULL, PRIMARY KEY (`key`));
-- Create "api_requests" table
CREATE TABLE `api_requests` (`id` text NOT NULL, `caller_id` text NOT NULL, `method` text NOT NULL, `request_id` text NOT NULL, `request_hash` blob NOT NULL, `response_enc` blob NULL, `created_at` datetime NOT NULL, PRIMARY KEY (`id`));
-- Create index "apirequest_caller_id_method_request_id" to table: "api_requests"
CREATE UNIQUE INDEX `apirequest_caller_id_method_request_id` ON `api_requests` (`caller_id`, `method`, `request_id`);
-- Create index "apirequest_created_at" to table: "api_requests"
CREATE INDEX `apirequest_created_at` ON `api_requests` (`created_at`);
-- Create "api_tokens" table
CREATE TABLE `api_tokens` (`id` text NOT NULL, `org_id` text NOT NULL, `owner_type` text NOT NULL, `owner_id` text NOT NULL, `name` text NOT NULL, `prefix` text NOT NULL, `token_hash` blob NOT NULL, `scopes` json NOT NULL, `mfa` bool NOT NULL DEFAULT (false), `created_at` datetime NOT NULL, `expires_at` datetime NOT NULL, `last_used_at` datetime NULL, `last_used_ip` text NULL, `revoked_at` datetime NULL, `step_up_at` datetime NULL, `suspended_at` datetime NULL, PRIMARY KEY (`id`), CONSTRAINT `api_tokens_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "apitoken_org_id_id" to table: "api_tokens"
CREATE UNIQUE INDEX `apitoken_org_id_id` ON `api_tokens` (`org_id`, `id`);
-- Create index "apitoken_token_hash" to table: "api_tokens"
CREATE UNIQUE INDEX `apitoken_token_hash` ON `api_tokens` (`token_hash`);
-- Create index "apitoken_org_id_owner_id" to table: "api_tokens"
CREATE INDEX `apitoken_org_id_owner_id` ON `api_tokens` (`org_id`, `owner_id`);
-- Create "access_policies" table
CREATE TABLE `access_policies` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `description` text NOT NULL DEFAULT (''), PRIMARY KEY (`id`), CONSTRAINT `access_policies_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "accesspolicy_org_id_id" to table: "access_policies"
CREATE UNIQUE INDEX `accesspolicy_org_id_id` ON `access_policies` (`org_id`, `id`);
-- Create index "accesspolicy_org_id_name" to table: "access_policies"
CREATE UNIQUE INDEX `accesspolicy_org_id_name` ON `access_policies` (`org_id`, `name`);
-- Create "agent_sessions" table
CREATE TABLE `agent_sessions` (`agent_id` text NOT NULL, `org_id` text NOT NULL, `session_epoch` integer NOT NULL, `controller_node` text NOT NULL, `remote_addr` text NOT NULL DEFAULT (''), `agent_version` text NOT NULL DEFAULT (''), `capabilities` json NULL, `connected_at` datetime NOT NULL, `last_seen_at` datetime NOT NULL, `disconnected_at` datetime NULL, PRIMARY KEY (`agent_id`), CONSTRAINT `agent_sessions_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "agentsession_org_id_agent_id" to table: "agent_sessions"
CREATE UNIQUE INDEX `agentsession_org_id_agent_id` ON `agent_sessions` (`org_id`, `agent_id`);
-- Create "agent_state" table
CREATE TABLE `agent_state` (`agent_id` text NOT NULL, `org_id` text NOT NULL, `boot_id` text NOT NULL DEFAULT (''), `clock_offset_ms` integer NOT NULL DEFAULT (0), `applied_db_epoch` text NOT NULL DEFAULT (''), `applied_seq` integer NOT NULL DEFAULT (0), `applied_hash` blob NULL, `last_ack_at` datetime NULL, `pushed_db_epoch` text NOT NULL DEFAULT (''), `pushed_seq` integer NOT NULL DEFAULT (0), `pushed_hash` blob NULL, `pushed_at` datetime NULL, `rejected_db_epoch` text NOT NULL DEFAULT (''), `rejected_seq` integer NOT NULL DEFAULT (0), `rejected_hash` blob NULL, `last_rejection` json NULL, PRIMARY KEY (`agent_id`), CONSTRAINT `agent_state_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "agentstate_org_id_agent_id" to table: "agent_state"
CREATE UNIQUE INDEX `agentstate_org_id_agent_id` ON `agent_state` (`org_id`, `agent_id`);
-- Create "audit_checkpoints" table
CREATE TABLE `audit_checkpoints` (`id` text NOT NULL, `org_id` text NULL, `seq` integer NOT NULL, `head_hash` blob NOT NULL, `ts` datetime NOT NULL, `key_id` text NOT NULL, `signature` blob NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `audit_checkpoints_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "auditcheckpoint_org_id_seq" to table: "audit_checkpoints"
CREATE UNIQUE INDEX `auditcheckpoint_org_id_seq` ON `audit_checkpoints` (`org_id`, `seq`);
-- Create index "auditcheckpoint_instance_seq" to table: "audit_checkpoints"
CREATE UNIQUE INDEX `auditcheckpoint_instance_seq` ON `audit_checkpoints` (`seq`) WHERE org_id IS NULL;
-- Create "audit_log" table
CREATE TABLE `audit_log` (`id` text NOT NULL, `org_id` text NULL, `seq` integer NOT NULL, `prev_hash` blob NOT NULL, `hash` blob NOT NULL, `ts` datetime NOT NULL, `actor_type` text NOT NULL, `actor_id` text NOT NULL DEFAULT (''), `credential_id` text NOT NULL DEFAULT (''), `auth_method` text NOT NULL DEFAULT (''), `ip` text NOT NULL DEFAULT (''), `user_agent` text NOT NULL DEFAULT (''), `request_id` text NOT NULL DEFAULT (''), `action` text NOT NULL, `target_type` text NOT NULL DEFAULT (''), `target_id` text NOT NULL DEFAULT (''), `result` text NOT NULL, `diff` text NOT NULL DEFAULT (''), `reason` text NOT NULL DEFAULT (''), PRIMARY KEY (`id`), CONSTRAINT `audit_log_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "auditentry_org_id_seq" to table: "audit_log"
CREATE UNIQUE INDEX `auditentry_org_id_seq` ON `audit_log` (`org_id`, `seq`);
-- Create index "auditentry_instance_seq" to table: "audit_log"
CREATE UNIQUE INDEX `auditentry_instance_seq` ON `audit_log` (`seq`) WHERE org_id IS NULL;
-- Create "audit_heads" table
CREATE TABLE `audit_heads` (`chain` text NOT NULL, `seq` integer NOT NULL, `hash` blob NOT NULL, PRIMARY KEY (`chain`));
-- Create "ca_bundles" table
CREATE TABLE `ca_bundles` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `pem` blob NOT NULL, `created_at` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `ca_bundles_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "cabundle_org_id_id" to table: "ca_bundles"
CREATE UNIQUE INDEX `cabundle_org_id_id` ON `ca_bundles` (`org_id`, `id`);
-- Create index "cabundle_org_id_name" to table: "ca_bundles"
CREATE UNIQUE INDEX `cabundle_org_id_name` ON `ca_bundles` (`org_id`, `name`);
-- Create "ca_keys" table
CREATE TABLE `ca_keys` (`id` text NOT NULL, `kind` text NOT NULL, `algorithm` text NOT NULL, `public_key` blob NOT NULL, `certificate` blob NOT NULL, `key_enc` blob NULL, `not_before` datetime NOT NULL, `not_after` datetime NOT NULL, `status` text NOT NULL, PRIMARY KEY (`id`));
-- Create "certificates" table
CREATE TABLE `certificates` (`id` text NOT NULL, `org_id` text NOT NULL, `source` text NOT NULL, `sans` json NOT NULL, `not_before` datetime NULL, `not_after` datetime NULL, `chain` blob NULL, `key_enc` blob NULL, `content_sha256` blob NULL, `status` text NOT NULL DEFAULT ('active'), `last_error` text NULL, `issuer` text NULL, `created_at` datetime NOT NULL, `version` integer NOT NULL DEFAULT (1), PRIMARY KEY (`id`), CONSTRAINT `certificates_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "certificate_org_id_id" to table: "certificates"
CREATE UNIQUE INDEX `certificate_org_id_id` ON `certificates` (`org_id`, `id`);
-- Create "compiled_snapshots" table
CREATE TABLE `compiled_snapshots` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `agent_id` text NOT NULL, `db_epoch` text NOT NULL, `seq` integer NOT NULL, `hash` blob NOT NULL, `size_bytes` integer NOT NULL, `payload` blob NOT NULL, `signature` blob NOT NULL, `key_id` text NOT NULL, `created_at` datetime NOT NULL, CONSTRAINT `compiled_snapshots_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "compiledsnapshot_org_id_id" to table: "compiled_snapshots"
CREATE UNIQUE INDEX `compiledsnapshot_org_id_id` ON `compiled_snapshots` (`org_id`, `id`);
-- Create index "compiledsnapshot_agent_id_id" to table: "compiled_snapshots"
CREATE INDEX `compiledsnapshot_agent_id_id` ON `compiled_snapshots` (`agent_id`, `id`);
-- Create "config_revisions" table
CREATE TABLE `config_revisions` (`seq` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `db_epoch` text NOT NULL, `actor` text NOT NULL, `changed_resources` json NULL, `org_id` text NULL, `created_at` datetime NOT NULL, CONSTRAINT `config_revisions_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "configrevision_org_id_seq" to table: "config_revisions"
CREATE INDEX `configrevision_org_id_seq` ON `config_revisions` (`org_id`, `seq`);
-- Create "config_seq" table
CREATE TABLE `config_seq` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `seq` integer NOT NULL);
-- Create "connectors" table
CREATE TABLE `connectors` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `labels` json NULL, `spiffe_id` text NOT NULL, `pubkey_sha256` text NOT NULL, `ephemeral` bool NOT NULL DEFAULT (false), `enabled` bool NOT NULL DEFAULT (true), `transport` text NULL, `desired_version` text NULL, `created_at` datetime NOT NULL, `decommissioned_at` datetime NULL, PRIMARY KEY (`id`), CONSTRAINT `connectors_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "connector_org_id_id" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_id` ON `connectors` (`org_id`, `id`);
-- Create index "connector_org_id_name" to table: "connectors"
CREATE UNIQUE INDEX `connector_org_id_name` ON `connectors` (`org_id`, `name`);
-- Create "data_sessions" table
CREATE TABLE `data_sessions` (`id` text NOT NULL, `org_id` text NOT NULL, `gateway_id` text NOT NULL, `connector_id` text NOT NULL, `transport` text NOT NULL, `rtt_ms` integer NOT NULL DEFAULT (0), `established_at` datetime NOT NULL, `reported_at` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `data_sessions_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "datasession_org_id_id" to table: "data_sessions"
CREATE UNIQUE INDEX `datasession_org_id_id` ON `data_sessions` (`org_id`, `id`);
-- Create index "datasession_gateway_id_connector_id_transport" to table: "data_sessions"
CREATE UNIQUE INDEX `datasession_gateway_id_connector_id_transport` ON `data_sessions` (`gateway_id`, `connector_id`, `transport`);
-- Create index "datasession_connector_id" to table: "data_sessions"
CREATE INDEX `datasession_connector_id` ON `data_sessions` (`connector_id`);
-- Create "domains" table
CREATE TABLE `domains` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `fqdn` text NOT NULL, `wildcard` bool NOT NULL DEFAULT (false), `status` text NOT NULL DEFAULT ('pending'), `method` text NOT NULL DEFAULT ('dns_txt'), `challenge_value` text NOT NULL, `created_at` datetime NOT NULL, `verified_at` datetime NULL, `last_checked_at` datetime NULL, `last_error` text NOT NULL DEFAULT (''), PRIMARY KEY (`id`), CONSTRAINT `domains_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "domain_org_id_id" to table: "domains"
CREATE UNIQUE INDEX `domain_org_id_id` ON `domains` (`org_id`, `id`);
-- Create index "domain_fqdn" to table: "domains"
CREATE UNIQUE INDEX `domain_fqdn` ON `domains` (`fqdn`);
-- Create "enrollment_tokens" table
CREATE TABLE `enrollment_tokens` (`id` text NOT NULL, `org_id` text NOT NULL, `token_hash` blob NOT NULL, `role` text NOT NULL, `labels` json NULL, `ephemeral` bool NOT NULL DEFAULT (false), `max_uses` integer NULL, `use_count` integer NOT NULL DEFAULT (0), `expires_at` datetime NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `last_used_at` datetime NULL, `last_used_ip` text NULL, `revoked_at` datetime NULL, `gateway_group_id` text NULL, `gateway_id` text NULL, `connector_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `enrollment_tokens_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_gateways_gateway` FOREIGN KEY (`org_id`, `gateway_id`) REFERENCES `gateways` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_connectors_connector` FOREIGN KEY (`org_id`, `connector_id`) REFERENCES `connectors` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `enrollment_tokens_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "enrollment_tokens_token_hash_key" to table: "enrollment_tokens"
CREATE UNIQUE INDEX `enrollment_tokens_token_hash_key` ON `enrollment_tokens` (`token_hash`);
-- Create index "enrollmenttoken_org_id_id" to table: "enrollment_tokens"
CREATE UNIQUE INDEX `enrollmenttoken_org_id_id` ON `enrollment_tokens` (`org_id`, `id`);
-- Create "gateways" table
CREATE TABLE `gateways` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `slot` integer NOT NULL, `tunnel_endpoints` json NOT NULL, `spiffe_id` text NULL, `pubkey_sha256` text NULL, `enabled` bool NOT NULL DEFAULT (true), `desired_version` text NULL, `created_at` datetime NOT NULL, `decommissioned_at` datetime NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `gateways_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `gateways_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "gateway_org_id_id" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_id` ON `gateways` (`org_id`, `id`);
-- Create index "gateway_org_id_name" to table: "gateways"
CREATE UNIQUE INDEX `gateway_org_id_name` ON `gateways` (`org_id`, `name`);
-- Create index "gateway_gateway_group_id_slot" to table: "gateways"
CREATE UNIQUE INDEX `gateway_gateway_group_id_slot` ON `gateways` (`gateway_group_id`, `slot`) WHERE decommissioned_at IS NULL;
-- Create "gateway_groups" table
CREATE TABLE `gateway_groups` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `region` text NULL, `public_hostnames` json NULL, `trusted_proxy_cidrs` json NULL, PRIMARY KEY (`id`), CONSTRAINT `gateway_groups_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "gatewaygroup_org_id_id" to table: "gateway_groups"
CREATE UNIQUE INDEX `gatewaygroup_org_id_id` ON `gateway_groups` (`org_id`, `id`);
-- Create index "gatewaygroup_org_id_name" to table: "gateway_groups"
CREATE UNIQUE INDEX `gatewaygroup_org_id_name` ON `gateway_groups` (`org_id`, `name`);
-- Create "instance" table
CREATE TABLE `instance` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `trust_domain` text NOT NULL, `db_epoch` text NOT NULL, `created_at` datetime NOT NULL, `restore_review_since` datetime NULL);
-- Create "instance_secrets" table
CREATE TABLE `instance_secrets` (`name` text NOT NULL, `value_enc` blob NOT NULL, `updated_at` datetime NOT NULL, PRIMARY KEY (`name`));
-- Create "instance_settings" table
CREATE TABLE `instance_settings` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `value` blob NOT NULL, `version` integer NOT NULL, `updated_by` text NOT NULL, `updated_at` datetime NOT NULL);
-- Create "invitations" table
CREATE TABLE `invitations` (`id` text NOT NULL, `org_id` text NOT NULL, `email` text NOT NULL, `role` text NOT NULL, `token_hash` blob NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `expires_at` datetime NOT NULL, `accepted_at` datetime NULL, `accepted_by` text NULL, PRIMARY KEY (`id`), CONSTRAINT `invitations_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "invitation_org_id_id" to table: "invitations"
CREATE UNIQUE INDEX `invitation_org_id_id` ON `invitations` (`org_id`, `id`);
-- Create index "invitation_token_hash" to table: "invitations"
CREATE UNIQUE INDEX `invitation_token_hash` ON `invitations` (`token_hash`);
-- Create "issued_certificates" table
CREATE TABLE `issued_certificates` (`serial` text NOT NULL, `org_id` text NULL, `subject_type` text NOT NULL, `subject_id` text NOT NULL, `spiffe_id` text NOT NULL, `pubkey_sha256` text NOT NULL, `not_before` datetime NOT NULL, `not_after` datetime NOT NULL, `first_seen_at` datetime NULL, `superseded_at` datetime NULL, `revoked_at` datetime NULL, `revocation_reason` text NOT NULL DEFAULT (''), `certificate` blob NULL, `enrollment_token_id` text NULL, PRIMARY KEY (`serial`), CONSTRAINT `issued_certificates_enrollment_tokens_enrollment_token` FOREIGN KEY (`org_id`, `enrollment_token_id`) REFERENCES `enrollment_tokens` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `issued_certificates_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "issuedcertificate_subject_id" to table: "issued_certificates"
CREATE INDEX `issuedcertificate_subject_id` ON `issued_certificates` (`subject_id`);
-- Create index "issuedcertificate_enrollment_token_id" to table: "issued_certificates"
CREATE INDEX `issuedcertificate_enrollment_token_id` ON `issued_certificates` (`enrollment_token_id`);
-- Create "leases" table
CREATE TABLE `leases` (`name` text NOT NULL, `holder` text NOT NULL, `fencing_token` integer NOT NULL, `expires_at` integer NOT NULL, PRIMARY KEY (`name`));
-- Create "memberships" table
CREATE TABLE `memberships` (`id` text NOT NULL, `org_id` text NOT NULL, `role` text NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `user_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `memberships_users_memberships` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE NO ACTION, CONSTRAINT `memberships_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "membership_org_id_id" to table: "memberships"
CREATE UNIQUE INDEX `membership_org_id_id` ON `memberships` (`org_id`, `id`);
-- Create index "membership_org_id_user_id" to table: "memberships"
CREATE UNIQUE INDEX `membership_org_id_user_id` ON `memberships` (`org_id`, `user_id`);
-- Create "orgs" table
CREATE TABLE `orgs` (`id` text NOT NULL, `name` text NOT NULL, `slug` text NOT NULL, `created_at` datetime NOT NULL, `restore_review_since` datetime NULL, PRIMARY KEY (`id`));
-- Create index "orgs_slug_key" to table: "orgs"
CREATE UNIQUE INDEX `orgs_slug_key` ON `orgs` (`slug`);
-- Create "org_settings" table
CREATE TABLE `org_settings` (`id` text NOT NULL, `org_id` text NOT NULL, `value` blob NOT NULL, `version` integer NOT NULL, `updated_by` text NOT NULL, `updated_at` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `org_settings_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "orgsetting_org_id_id" to table: "org_settings"
CREATE UNIQUE INDEX `orgsetting_org_id_id` ON `org_settings` (`org_id`, `id`);
-- Create index "orgsetting_org_id" to table: "org_settings"
CREATE UNIQUE INDEX `orgsetting_org_id` ON `org_settings` (`org_id`);
-- Create "password_resets" table
CREATE TABLE `password_resets` (`id` text NOT NULL, `token_hash` blob NOT NULL, `created_by` text NOT NULL, `created_at` datetime NOT NULL, `expires_at` datetime NOT NULL, `used_at` datetime NULL, `user_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `password_resets_users_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE);
-- Create index "passwordreset_token_hash" to table: "password_resets"
CREATE UNIQUE INDEX `passwordreset_token_hash` ON `password_resets` (`token_hash`);
-- Create "policy_rules" table
CREATE TABLE `policy_rules` (`id` text NOT NULL, `org_id` text NOT NULL, `position` integer NOT NULL, `kind` text NOT NULL, `params` blob NOT NULL, `policy_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `policy_rules_access_policies_policy` FOREIGN KEY (`org_id`, `policy_id`) REFERENCES `access_policies` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `policy_rules_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "policyrule_org_id_id" to table: "policy_rules"
CREATE UNIQUE INDEX `policyrule_org_id_id` ON `policy_rules` (`org_id`, `id`);
-- Create index "policyrule_policy_id_position" to table: "policy_rules"
CREATE UNIQUE INDEX `policyrule_policy_id_position` ON `policy_rules` (`policy_id`, `position`);
-- Create "port_allocations" table
CREATE TABLE `port_allocations` (`id` text NOT NULL, `org_id` text NOT NULL, `protocol` text NOT NULL, `port` integer NOT NULL, `route_id` text NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `port_allocations_gateway_groups_group` FOREIGN KEY (`gateway_group_id`) REFERENCES `gateway_groups` (`id`) ON DELETE NO ACTION, CONSTRAINT `port_allocations_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "portallocation_org_id_id" to table: "port_allocations"
CREATE UNIQUE INDEX `portallocation_org_id_id` ON `port_allocations` (`org_id`, `id`);
-- Create index "portallocation_gateway_group_id_protocol_port" to table: "port_allocations"
CREATE UNIQUE INDEX `portallocation_gateway_group_id_protocol_port` ON `port_allocations` (`gateway_group_id`, `protocol`, `port`);
-- Create "port_pools" table
CREATE TABLE `port_pools` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `protocol` text NOT NULL, `port_from` integer NOT NULL, `port_to` integer NOT NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `port_pools_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `port_pools_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "portpool_org_id_id" to table: "port_pools"
CREATE UNIQUE INDEX `portpool_org_id_id` ON `port_pools` (`org_id`, `id`);
-- Create "port_quotas" table
CREATE TABLE `port_quotas` (`id` text NOT NULL, `org_id` text NOT NULL, `protocol` text NOT NULL, `max_ports` integer NOT NULL, `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `port_quotas_gateway_groups_group` FOREIGN KEY (`org_id`, `gateway_group_id`) REFERENCES `gateway_groups` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `port_quotas_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "portquota_org_id_id" to table: "port_quotas"
CREATE UNIQUE INDEX `portquota_org_id_id` ON `port_quotas` (`org_id`, `id`);
-- Create index "portquota_org_id_gateway_group_id_protocol" to table: "port_quotas"
CREATE UNIQUE INDEX `portquota_org_id_gateway_group_id_protocol` ON `port_quotas` (`org_id`, `gateway_group_id`, `protocol`);
-- Create "recovery_codes" table
CREATE TABLE `recovery_codes` (`id` text NOT NULL, `code_hash` blob NOT NULL, `created_at` datetime NOT NULL, `used_at` datetime NULL, `user_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `recovery_codes_users_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE);
-- Create index "recoverycode_code_hash" to table: "recovery_codes"
CREATE UNIQUE INDEX `recoverycode_code_hash` ON `recovery_codes` (`code_hash`);
-- Create index "recoverycode_user_id" to table: "recovery_codes"
CREATE INDEX `recoverycode_user_id` ON `recovery_codes` (`user_id`);
-- Create "resource_status" table
CREATE TABLE `resource_status` (`id` text NOT NULL, `org_id` text NOT NULL, `agent_id` text NOT NULL, `resource_id` text NOT NULL, `reason` text NOT NULL, `detail` text NOT NULL DEFAULT (''), `since` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `resource_status_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "resourcestatus_org_id_id" to table: "resource_status"
CREATE UNIQUE INDEX `resourcestatus_org_id_id` ON `resource_status` (`org_id`, `id`);
-- Create index "resourcestatus_agent_id_resource_id" to table: "resource_status"
CREATE UNIQUE INDEX `resourcestatus_agent_id_resource_id` ON `resource_status` (`agent_id`, `resource_id`);
-- Create "revoked_identities" table
CREATE TABLE `revoked_identities` (`spiffe_id` text NOT NULL, `org_id` text NULL, `subject_type` text NOT NULL, `subject_id` text NOT NULL, `revoked_at` datetime NOT NULL, `reason` text NOT NULL DEFAULT (''), `not_after` datetime NOT NULL, PRIMARY KEY (`spiffe_id`), CONSTRAINT `revoked_identities_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create "revoked_serials" table
CREATE TABLE `revoked_serials` (`serial` text NOT NULL, `org_id` text NULL, `revoked_at` datetime NOT NULL, `reason` text NOT NULL DEFAULT (''), `not_after` datetime NOT NULL, PRIMARY KEY (`serial`), CONSTRAINT `revoked_serials_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create "routes" table
CREATE TABLE `routes` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `name` text NOT NULL, `type` text NOT NULL, `enabled` bool NOT NULL DEFAULT (true), `transport` text NULL, `description` text NOT NULL DEFAULT (''), `labels` json NULL, `created_at` datetime NOT NULL, `updated_at` datetime NOT NULL, `updated_by` text NOT NULL DEFAULT (''), `gateway_group_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `routes_gateway_groups_group` FOREIGN KEY (`gateway_group_id`) REFERENCES `gateway_groups` (`id`) ON DELETE NO ACTION, CONSTRAINT `routes_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "route_org_id_id" to table: "routes"
CREATE UNIQUE INDEX `route_org_id_id` ON `routes` (`org_id`, `id`);
-- Create index "route_org_id_name" to table: "routes"
CREATE UNIQUE INDEX `route_org_id_name` ON `routes` (`org_id`, `name`);
-- Create "route_http" table
CREATE TABLE `route_http` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `path_prefix` text NOT NULL DEFAULT (''), `header_matches` json NULL, `tls_mode` text NOT NULL DEFAULT ('acme'), `port80` text NOT NULL DEFAULT ('redirect'), `hsts_max_age_seconds` integer NOT NULL DEFAULT (0), `host_header` text NOT NULL DEFAULT ('preserve'), `request_headers_set` json NULL, `response_headers_set` json NULL, `websocket` bool NOT NULL DEFAULT (true), `max_body_bytes` integer NOT NULL DEFAULT (0), `dns_proxied` bool NOT NULL DEFAULT (false), `route_id` text NOT NULL, `certificate_id` text NULL, CONSTRAINT `route_http_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_http_certificates_certificate` FOREIGN KEY (`org_id`, `certificate_id`) REFERENCES `certificates` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_http_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routehttp_org_id_id" to table: "route_http"
CREATE UNIQUE INDEX `routehttp_org_id_id` ON `route_http` (`org_id`, `id`);
-- Create index "routehttp_route_id" to table: "route_http"
CREATE UNIQUE INDEX `routehttp_route_id` ON `route_http` (`route_id`);
-- Create index "routehttp_certificate_id" to table: "route_http"
CREATE INDEX `routehttp_certificate_id` ON `route_http` (`certificate_id`);
-- Create "route_hostnames" table
CREATE TABLE `route_hostnames` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `gateway_group_id` text NOT NULL, `route_type` text NOT NULL, `hostname` text NOT NULL, `path_prefix` text NOT NULL DEFAULT (''), `route_id` text NOT NULL, `domain_id` text NOT NULL, CONSTRAINT `route_hostnames_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_hostnames_domains_domain` FOREIGN KEY (`org_id`, `domain_id`) REFERENCES `domains` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_hostnames_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routehostname_org_id_id" to table: "route_hostnames"
CREATE UNIQUE INDEX `routehostname_org_id_id` ON `route_hostnames` (`org_id`, `id`);
-- Create index "routehostname_gateway_group_id_hostname_path_prefix" to table: "route_hostnames"
CREATE UNIQUE INDEX `routehostname_gateway_group_id_hostname_path_prefix` ON `route_hostnames` (`gateway_group_id`, `hostname`, `path_prefix`);
-- Create index "routehostname_route_id" to table: "route_hostnames"
CREATE INDEX `routehostname_route_id` ON `route_hostnames` (`route_id`);
-- Create "route_policies" table
CREATE TABLE `route_policies` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `position` integer NOT NULL, `route_id` text NOT NULL, `policy_id` text NOT NULL, CONSTRAINT `route_policies_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_policies_access_policies_policy` FOREIGN KEY (`org_id`, `policy_id`) REFERENCES `access_policies` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_policies_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routepolicy_org_id_id" to table: "route_policies"
CREATE UNIQUE INDEX `routepolicy_org_id_id` ON `route_policies` (`org_id`, `id`);
-- Create index "routepolicy_route_id_policy_id" to table: "route_policies"
CREATE UNIQUE INDEX `routepolicy_route_id_policy_id` ON `route_policies` (`route_id`, `policy_id`);
-- Create index "routepolicy_route_id_position" to table: "route_policies"
CREATE UNIQUE INDEX `routepolicy_route_id_position` ON `route_policies` (`route_id`, `position`);
-- Create index "routepolicy_policy_id" to table: "route_policies"
CREATE INDEX `routepolicy_policy_id` ON `route_policies` (`policy_id`);
-- Create "route_tcp" table
CREATE TABLE `route_tcp` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `listener_mode` text NOT NULL DEFAULT ('plain'), `idle_timeout_seconds` integer NOT NULL DEFAULT (3600), `route_id` text NOT NULL, `port_allocation_id` text NOT NULL, CONSTRAINT `route_tcp_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_tcp_port_allocations_port` FOREIGN KEY (`org_id`, `port_allocation_id`) REFERENCES `port_allocations` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_tcp_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetcp_org_id_id" to table: "route_tcp"
CREATE UNIQUE INDEX `routetcp_org_id_id` ON `route_tcp` (`org_id`, `id`);
-- Create index "routetcp_route_id" to table: "route_tcp"
CREATE UNIQUE INDEX `routetcp_route_id` ON `route_tcp` (`route_id`);
-- Create index "routetcp_port_allocation_id" to table: "route_tcp"
CREATE UNIQUE INDEX `routetcp_port_allocation_id` ON `route_tcp` (`port_allocation_id`);
-- Create "route_targets" table
CREATE TABLE `route_targets` (`id` text NOT NULL, `org_id` text NOT NULL, `version` integer NOT NULL DEFAULT (1), `kind` text NOT NULL, `host` text NOT NULL DEFAULT (''), `port` integer NOT NULL DEFAULT (0), `unix_path` text NOT NULL DEFAULT (''), `upstream_protocol` text NOT NULL DEFAULT ('tcp'), `tls_server_name` text NOT NULL DEFAULT (''), `tls_spki_sha256` text NOT NULL DEFAULT (''), `proxy_protocol` text NOT NULL DEFAULT ('none'), `weight` integer NOT NULL DEFAULT (1), `priority` integer NOT NULL DEFAULT (0), `enabled` bool NOT NULL DEFAULT (true), `route_id` text NOT NULL, `connector_id` text NOT NULL, `tls_ca_bundle_id` text NULL, PRIMARY KEY (`id`), CONSTRAINT `route_targets_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_connectors_connector` FOREIGN KEY (`org_id`, `connector_id`) REFERENCES `connectors` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_ca_bundles_ca_bundle` FOREIGN KEY (`org_id`, `tls_ca_bundle_id`) REFERENCES `ca_bundles` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_targets_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetarget_org_id_id" to table: "route_targets"
CREATE UNIQUE INDEX `routetarget_org_id_id` ON `route_targets` (`org_id`, `id`);
-- Create index "routetarget_route_id" to table: "route_targets"
CREATE INDEX `routetarget_route_id` ON `route_targets` (`route_id`);
-- Create index "routetarget_connector_id" to table: "route_targets"
CREATE INDEX `routetarget_connector_id` ON `route_targets` (`connector_id`);
-- Create index "routetarget_tls_ca_bundle_id" to table: "route_targets"
CREATE INDEX `routetarget_tls_ca_bundle_id` ON `route_targets` (`tls_ca_bundle_id`);
-- Create "route_traffic_daily" table
CREATE TABLE `route_traffic_daily` (`id` text NOT NULL, `org_id` text NOT NULL, `route_id` text NOT NULL, `bucket` datetime NOT NULL, `bytes_in` integer NOT NULL, `bytes_out` integer NOT NULL, `connections` integer NOT NULL, `errors` integer NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `route_traffic_daily_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetrafficdaily_org_id_id" to table: "route_traffic_daily"
CREATE UNIQUE INDEX `routetrafficdaily_org_id_id` ON `route_traffic_daily` (`org_id`, `id`);
-- Create index "routetrafficdaily_route_id_bucket" to table: "route_traffic_daily"
CREATE UNIQUE INDEX `routetrafficdaily_route_id_bucket` ON `route_traffic_daily` (`route_id`, `bucket`);
-- Create index "routetrafficdaily_bucket" to table: "route_traffic_daily"
CREATE INDEX `routetrafficdaily_bucket` ON `route_traffic_daily` (`bucket`);
-- Create "route_traffic_hourly" table
CREATE TABLE `route_traffic_hourly` (`id` text NOT NULL, `org_id` text NOT NULL, `route_id` text NOT NULL, `bucket` datetime NOT NULL, `bytes_in` integer NOT NULL, `bytes_out` integer NOT NULL, `connections` integer NOT NULL, `errors` integer NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `route_traffic_hourly_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routetraffichourly_org_id_id" to table: "route_traffic_hourly"
CREATE UNIQUE INDEX `routetraffichourly_org_id_id` ON `route_traffic_hourly` (`org_id`, `id`);
-- Create index "routetraffichourly_route_id_bucket" to table: "route_traffic_hourly"
CREATE UNIQUE INDEX `routetraffichourly_route_id_bucket` ON `route_traffic_hourly` (`route_id`, `bucket`);
-- Create index "routetraffichourly_bucket" to table: "route_traffic_hourly"
CREATE INDEX `routetraffichourly_bucket` ON `route_traffic_hourly` (`bucket`);
-- Create "route_udp" table
CREATE TABLE `route_udp` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `org_id` text NOT NULL, `flow_idle_timeout_seconds` integer NOT NULL DEFAULT (60), `route_id` text NOT NULL, `port_allocation_id` text NOT NULL, CONSTRAINT `route_udp_routes_route` FOREIGN KEY (`org_id`, `route_id`) REFERENCES `routes` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_udp_port_allocations_port` FOREIGN KEY (`org_id`, `port_allocation_id`) REFERENCES `port_allocations` (`org_id`, `id`) ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT `route_udp_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "routeudp_org_id_id" to table: "route_udp"
CREATE UNIQUE INDEX `routeudp_org_id_id` ON `route_udp` (`org_id`, `id`);
-- Create index "routeudp_route_id" to table: "route_udp"
CREATE UNIQUE INDEX `routeudp_route_id` ON `route_udp` (`route_id`);
-- Create index "routeudp_port_allocation_id" to table: "route_udp"
CREATE UNIQUE INDEX `routeudp_port_allocation_id` ON `route_udp` (`port_allocation_id`);
-- Create "secrets_meta" table
CREATE TABLE `secrets_meta` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `table_name` text NOT NULL, `row_id` text NOT NULL, `column_name` text NOT NULL, `kek_version` text NOT NULL, `created_at` datetime NOT NULL);
-- Create index "secretmeta_table_name_row_id_column_name" to table: "secrets_meta"
CREATE UNIQUE INDEX `secretmeta_table_name_row_id_column_name` ON `secrets_meta` (`table_name`, `row_id`, `column_name`);
-- Create "sessions" table
CREATE TABLE `sessions` (`id` text NOT NULL, `token_hash` blob NOT NULL, `created_at` datetime NOT NULL, `last_seen_at` datetime NOT NULL, `idle_expires_at` datetime NOT NULL, `absolute_expires_at` datetime NOT NULL, `elevated_until` datetime NULL, `amr` json NOT NULL, `ip` text NOT NULL, `user_agent` text NOT NULL, `revoked_at` datetime NULL, `user_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `sessions_users_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE);
-- Create index "session_token_hash" to table: "sessions"
CREATE UNIQUE INDEX `session_token_hash` ON `sessions` (`token_hash`);
-- Create index "session_user_id" to table: "sessions"
CREATE INDEX `session_user_id` ON `sessions` (`user_id`);
-- Create "totp_credentials" table
CREATE TABLE `totp_credentials` (`id` text NOT NULL, `seed_enc` blob NOT NULL, `created_at` datetime NOT NULL, `confirmed_at` datetime NULL, `last_step` integer NOT NULL DEFAULT (0), `user_id` text NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `totp_credentials_users_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE);
-- Create index "totpcredential_user_id" to table: "totp_credentials"
CREATE UNIQUE INDEX `totpcredential_user_id` ON `totp_credentials` (`user_id`);
-- Create "traffic_baselines" table
CREATE TABLE `traffic_baselines` (`id` text NOT NULL, `org_id` text NOT NULL, `gateway_id` text NOT NULL, `route_id` text NOT NULL, `boot_id` text NOT NULL DEFAULT (''), `bytes_in` integer NOT NULL, `bytes_out` integer NOT NULL, `connections` integer NOT NULL, `errors` integer NOT NULL, `reported_at` datetime NOT NULL, PRIMARY KEY (`id`), CONSTRAINT `traffic_baselines_orgs` FOREIGN KEY (`org_id`) REFERENCES `orgs` (`id`) ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "trafficbaseline_org_id_id" to table: "traffic_baselines"
CREATE UNIQUE INDEX `trafficbaseline_org_id_id` ON `traffic_baselines` (`org_id`, `id`);
-- Create index "trafficbaseline_gateway_id_route_id" to table: "traffic_baselines"
CREATE UNIQUE INDEX `trafficbaseline_gateway_id_route_id` ON `traffic_baselines` (`gateway_id`, `route_id`);
-- Create "users" table
CREATE TABLE `users` (`id` text NOT NULL, `email` text NOT NULL, `display_name` text NOT NULL, `password_hash` text NULL, `status` text NOT NULL DEFAULT ('active'), `instance_admin` bool NOT NULL DEFAULT (false), `created_at` datetime NOT NULL, `last_login_at` datetime NULL, `theme` text NOT NULL DEFAULT ('system'), PRIMARY KEY (`id`));
-- Create index "user_email" to table: "users"
CREATE UNIQUE INDEX `user_email` ON `users` (`email`);
