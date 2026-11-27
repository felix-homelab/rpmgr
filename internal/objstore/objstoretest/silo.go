// SPDX-License-Identifier: Apache-2.0

//go:build objstoreit

package objstoretest

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/objstore"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// The access key of the store the tests start. Test values, low entropy on purpose.
const (
	siloUser     = "itadmin"
	siloPassword = "it-password-1234" //nolint:gosec // G101: a test value
)

var siloCount atomic.Int32

// With objstoreit, NewTarget starts SILO, the maintained fork of MinIO, in a container built from
// test/objstore, with one bucket.
func init() {
	startReal = func(t testing.TB) Target {
		endpoint := startSilo(t)
		makeBucket(t, endpoint, Bucket)
		return Target{Endpoint: endpoint, Region: "us-east-1", Bucket: Bucket, AccessKeyID: siloUser, SecretKey: siloPassword}
	}
}

// startSilo runs the store on a loopback port and returns its endpoint. The container is named by
// RPMGR_TEST_OBJSTORE_NAME when that is set, with the process and a number, so that parallel runs
// on one host do not meet. It is stopped with the test.
func startSilo(t testing.TB) string {
	t.Helper()
	dir, err := filepath.Abs("../../test/objstore") // the tests run in internal/<package>
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "build", "-q", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	image := strings.TrimSpace(string(out))
	args := []string{"run", "-d", "--rm", "-p", "127.0.0.1::9000"}
	if name := os.Getenv("RPMGR_TEST_OBJSTORE_NAME"); name != "" {
		args = append(args, "--name", fmt.Sprintf("%s-%d-%d", name, os.Getpid(), siloCount.Add(1)))
	}
	args = append(args, "-e", "MINIO_ROOT_USER="+siloUser, "-e", "MINIO_ROOT_PASSWORD="+siloPassword, image, "server", "/data")
	out, err = exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "stop", "-t", "1", id).Run() })
	out, err = exec.Command("docker", "port", id, "9000/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + strings.Fields(string(out))[0]
	for i := 0; i < 60; i++ {
		if resp, err := http.Get(endpoint + "/minio/health/live"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return endpoint
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("the store did not become ready")
	return ""
}

// makeBucket creates a bucket. A store that has just come up answers 503 for a while, so it asks
// again then.
func makeBucket(t testing.TB, endpoint, name string) {
	t.Helper()
	creds := objstore.Credentials{AccessKeyID: siloUser, SecretAccessKey: secret.New(siloPassword)}
	var status string
	for i := 0; i < 60; i++ {
		req, _ := http.NewRequest(http.MethodPut, endpoint+"/"+name, nil)
		objstore.SignBucketRequest(req, creds, "us-east-1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return
		}
		status = resp.Status
		if resp.StatusCode != http.StatusServiceUnavailable {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("create bucket %s: %s", name, status)
}
