// SPDX-License-Identifier: Apache-2.0

// The permissions an API token can carry, as scopes (docs/04-security.md, "Roles" and "API
// tokens"): the org permissions of the role table, and the Instance Admin's. A unit test checks
// them against the permissions the API's methods name. The server decides which of them the user
// may grant.
export const orgPermissions = [
  "org.read",
  "routes.write",
  "connectors.write",
  "infrastructure.write",
  "members.write",
  "audit.read",
  "org.write",
] as const;

export const instancePermission = "instance.admin";
