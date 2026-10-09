// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// ReasonDependantsExist is the reason of a delete refused because other resources need the one
// to delete (docs/07-api.md, "Errors").
const ReasonDependantsExist = "DEPENDANTS_EXIST"

// storeError gives the store's errors their API codes: a resource not found (or in another org)
// is NOT_FOUND, a name taken ALREADY_EXISTS, a value the schema refuses INVALID_ARGUMENT, a
// reference that would dangle FAILED_PRECONDITION. Other errors pass on, and the interceptor
// hides their text.
func storeError(err error) error {
	var cerr *connect.Error
	switch {
	case err == nil, errors.As(err, &cerr):
		return err
	case ent.IsNotFound(err):
		return connect.NewError(connect.CodeNotFound, errors.New("apisvc: not found"))
	case store.IsUniqueViolation(err):
		return connect.NewError(connect.CodeAlreadyExists, errors.New("apisvc: the name is taken"))
	case ent.IsValidationError(err):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case store.IsForeignKeyViolation(err):
		return dependants("a resource it names does not exist, or others still need it")
	}
	return err
}

// dependants is FAILED_PRECONDITION with reason DEPENDANTS_EXIST.
func dependants(what string) error {
	return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("apisvc: %s", what)), ReasonDependantsExist)
}

func revisionOf(r store.Revision) *rpmgrv1.Revision {
	return &rpmgrv1.Revision{DbEpoch: r.DBEpoch, Seq: r.Seq}
}

// etagOf is a version as an etag.
func etagOf(version int64) string { return api.Etag(version) }

func errIf(cond bool, err error) error {
	if cond {
		return err
	}
	return nil
}
