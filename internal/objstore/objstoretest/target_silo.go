// SPDX-License-Identifier: Apache-2.0

//go:build objstoreit

package objstoretest

import (
	"testing"

	"github.com/felix-homelab/rpmgr/internal/objstore"
)

// With objstoreit, NewTarget starts SILO in a container (test/objstore) with one bucket.
func init() {
	startReal = func(t testing.TB) Target {
		endpoint := objstore.StartSilo(t)
		objstore.MakeBucket(t, endpoint, Bucket, false)
		return Target{Endpoint: endpoint, Region: "us-east-1", Bucket: Bucket, AccessKeyID: objstore.SiloUser, SecretKey: objstore.SiloPassword}
	}
}
