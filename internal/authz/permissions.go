// SPDX-License-Identifier: Apache-2.0

package authz

import "slices"

// The roles of an org membership (docs/04-security.md, "Roles").
const (
	RoleOwner    = "owner"
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// The permissions of the public API. The org permissions are the rows of the role table in
// docs/04-security.md, "Roles"; three more are granted by no org role.
const (
	// PermPublic needs no authentication: logging in, completing a password reset.
	PermPublic = "public"
	// PermAuthenticated needs any signed-in caller, acting on their own account.
	PermAuthenticated = "authenticated"
	// PermInstanceAdmin needs the Instance Admin role: CA, KEK, system gateways, instance settings.
	PermInstanceAdmin = "instance.admin"

	// PermOrgRead: view resources, status and metrics.
	PermOrgRead = "org.read"
	// PermRoutesWrite: routes, targets, health checks, access policies.
	PermRoutesWrite = "routes.write"
	// PermConnectorsWrite: enroll and revoke connectors; Operators only where the org allows it.
	PermConnectorsWrite = "connectors.write"
	// PermInfrastructureWrite: gateways, gateway groups, port pools, domains, certificates.
	PermInfrastructureWrite = "infrastructure.write"
	// PermMembersWrite: members and invitations; Admins cannot change Owners.
	PermMembersWrite = "members.write"
	// PermAuditRead: read and export the audit log.
	PermAuditRead = "audit.read"
	// PermOrgWrite: SSO, the MFA policy and the org's settings.
	PermOrgWrite = "org.write"
)

// grants lists the roles that hold each org permission.
var grants = map[string][]string{
	PermOrgRead:             {RoleOwner, RoleAdmin, RoleOperator, RoleViewer},
	PermRoutesWrite:         {RoleOwner, RoleAdmin, RoleOperator},
	PermConnectorsWrite:     {RoleOwner, RoleAdmin, RoleOperator},
	PermInfrastructureWrite: {RoleOwner, RoleAdmin},
	PermMembersWrite:        {RoleOwner, RoleAdmin},
	PermAuditRead:           {RoleOwner, RoleAdmin},
	PermOrgWrite:            {RoleOwner},
}

// OrgPermission reports whether p is a permission that org roles grant.
func OrgPermission(p string) bool {
	_, ok := grants[p]
	return ok
}

// KnownPermission reports whether p is any permission of the public API.
func KnownPermission(p string) bool {
	return p == PermPublic || p == PermAuthenticated || p == PermInstanceAdmin || OrgPermission(p)
}

// Grants reports whether role holds the org permission p; operatorsMayEnroll is the org's setting
// that gives Operators PermConnectorsWrite.
func Grants(role, p string, operatorsMayEnroll bool) bool {
	if p == PermConnectorsWrite && role == RoleOperator && !operatorsMayEnroll {
		return false
	}
	return slices.Contains(grants[p], role)
}
