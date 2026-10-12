// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/settings"
)

// SetACME sets the instance's ACME directory and account e-mail address on the controller host,
// beside or before a running controller (`rpmgr setup`, docs/16-cli.md). An empty value keeps the
// setting as it is. The controller reads them for its own certificate when it starts, and for route
// certificates at their next order.
func SetACME(ctx context.Context, path, directory, email string) error {
	upd := &rpmgrv1.InstanceSettings{}
	var paths []string
	if directory != "" {
		upd.AcmeDirectoryUrl, paths = proto.String(directory), append(paths, "acme_directory_url")
	}
	if email != "" {
		upd.AcmeEmail, paths = proto.String(email), append(paths, "acme_email")
	}
	if len(paths) == 0 {
		return nil
	}
	if err := protovalidate.Validate(upd); err != nil {
		return fmt.Errorf("controller: ACME settings: %w", err)
	}
	_, db, sys, err := openLocal(ctx, path, "rpmgr setup: ACME settings")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := settings.UpdateInstance(sys, db, upd, &fieldmaskpb.FieldMask{Paths: paths}, 0); err != nil {
		return err
	}
	_, err = audit.Record(sys, db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "instance.settings_update",
		TargetType: "instance", Result: audit.Success, Reason: "ACME directory and e-mail set by rpmgr setup"})
	return err
}
