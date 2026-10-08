// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"testing"

	"github.com/felix-homelab/rpmgr/internal/authz"
)

// TestGrants: the role table of docs/04-security.md, "Roles", cell by cell; Operators enroll
// connectors only where the org allows it; unknown roles and permissions grant nothing.
func TestGrants(t *testing.T) {
	roles := []string{authz.RoleOwner, authz.RoleAdmin, authz.RoleOperator, authz.RoleViewer}
	for p, want := range map[string][4]bool{
		authz.PermOrgRead:             {true, true, true, true},
		authz.PermRoutesWrite:         {true, true, true, false},
		authz.PermConnectorsWrite:     {true, true, false, false},
		authz.PermInfrastructureWrite: {true, true, false, false},
		authz.PermMembersWrite:        {true, true, false, false},
		authz.PermAuditRead:           {true, true, false, false},
		authz.PermOrgWrite:            {true, false, false, false},
	} {
		if !authz.OrgPermission(p) || !authz.KnownPermission(p) {
			t.Errorf("%s is not an org permission", p)
		}
		for i, role := range roles {
			if got := authz.Grants(role, p, false); got != want[i] {
				t.Errorf("%s %s: %v", role, p, got)
			}
		}
	}
	if !authz.Grants(authz.RoleOperator, authz.PermConnectorsWrite, true) || authz.Grants(authz.RoleViewer, authz.PermConnectorsWrite, true) {
		t.Error("the org setting for Operators")
	}
	for _, p := range []string{authz.PermPublic, authz.PermAuthenticated, authz.PermInstanceAdmin} {
		if authz.OrgPermission(p) || !authz.KnownPermission(p) {
			t.Errorf("%s", p)
		}
		for _, role := range roles {
			if authz.Grants(role, p, true) {
				t.Errorf("an org role grants %s", p)
			}
		}
	}
	if authz.Grants("superuser", authz.PermOrgRead, true) || authz.Grants(authz.RoleOwner, "route.update", true) ||
		authz.KnownPermission("route.update") || authz.KnownPermission("") {
		t.Error("an unknown role or permission")
	}
}
