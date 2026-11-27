// SPDX-License-Identifier: Apache-2.0

package objstoretest

import (
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/objstore"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// Target is the store a test runs against and how to reach it. A test that needs a switch or a
// fault uses New; a test of behaviour that every S3-compatible store must show uses NewTarget, so
// that the check against a real store (build tag objstoreit, SILO in a container) runs the same
// test as the everyday run against the in-process Server.
type Target struct {
	Endpoint string
	Region   string
	Bucket   string
	// AccessKeyID and SecretKey are the access key: test values of low entropy.
	AccessKeyID string
	SecretKey   string
}

// Client returns a client of the target with the given request timeout; zero means the default.
func (g Target) Client(t testing.TB, timeout time.Duration) *objstore.Client {
	t.Helper()
	c, err := objstore.New(objstore.Config{Endpoint: g.Endpoint, Region: g.Region, Bucket: g.Bucket,
		Credentials: objstore.Credentials{AccessKeyID: g.AccessKeyID, SecretAccessKey: secret.New(g.SecretKey)}, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// startReal starts a real store; the file that holds objstoreit sets it.
var startReal func(testing.TB) Target

// NewTarget is the in-process Server, or a real store when the tests are built with objstoreit.
func NewTarget(t testing.TB) Target {
	t.Helper()
	if startReal != nil {
		return startReal(t)
	}
	return New(t).Target()
}

// Target describes the Server as a Target.
func (s *Server) Target() Target {
	return Target{Endpoint: s.URL, Region: Region, Bucket: Bucket, AccessKeyID: AccessKeyID, SecretKey: "fake-secret-key-0000"}
}
