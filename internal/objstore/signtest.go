// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest || objstoreit

package objstore

import (
	"net/http"
	"time"
)

// SignBucketRequest signs a request without a body, such as the creation of a bucket, for the
// tests that start a real store. It is compiled only under the test build tags (D60).
func SignBucketRequest(req *http.Request, c Credentials, region string) {
	sign(req, emptyHash, c, region, time.Now())
}
