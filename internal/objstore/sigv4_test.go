// SPDX-License-Identifier: Apache-2.0

package objstore

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// The published examples of AWS Signature Version 4: the signature test suite's get-vanilla
// (https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html) and the four
// worked examples of the S3 documentation, "Examples: Signature Calculations"
// (https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html).

func creds(id, key string) Credentials {
	return Credentials{AccessKeyID: id, SecretAccessKey: secret.New(key)}
}

func authSig(t *testing.T, r *http.Request) string {
	t.Helper()
	a := r.Header.Get("Authorization")
	i := strings.Index(a, "Signature=")
	if i < 0 {
		t.Fatalf("no signature in %q", a)
	}
	return a[i+len("Signature="):]
}

func TestSigV4SuiteGetVanilla(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	r.Header.Set("X-Amz-Date", "20150830T123600Z")
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	authorize(r, emptyHash, creds("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"), "us-east-1", "service", now)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := r.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization\n got %s\nwant %s", got, want)
	}
}

func TestSigV4S3Examples(t *testing.T) {
	c := creds("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	const putBody = "Welcome to Amazon S3."
	tests := []struct {
		name, method, url, payload, sig string
		headers                         map[string]string
	}{
		{"get object", "GET", "https://examplebucket.s3.amazonaws.com/test.txt", emptyHash,
			"f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
			map[string]string{"Range": "bytes=0-9"}},
		{"put object", "PUT", "https://examplebucket.s3.amazonaws.com/test$file.text", hexSHA256([]byte(putBody)),
			"98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
			map[string]string{"Date": "Fri, 24 May 2013 00:00:00 GMT", "X-Amz-Storage-Class": "REDUCED_REDUNDANCY"}},
		{"get bucket lifecycle", "GET", "https://examplebucket.s3.amazonaws.com/?lifecycle", emptyHash,
			"fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", nil},
		{"list objects", "GET", "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", emptyHash,
			"34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(tc.method, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.URL.RawPath = "" // sign escapes the decoded path itself
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			sign(r, tc.payload, c, "us-east-1", now)
			if got := authSig(t, r); got != tc.sig {
				t.Errorf("signature %s, want %s\n%s", got, tc.sig, r.Header.Get("Authorization"))
			}
		})
	}
}

func TestCanonicalQueryOrdersByNameThenValue(t *testing.T) {
	// "a" sorts before "a-b" although "a=" sorts after "a-b=" as text.
	q := url.Values{"a-b": {"1"}, "a": {"2", "1"}, "z": {""}, "k y": {"é/"}}
	want := "a=1&a=2&a-b=1&k%20y=%C3%A9%2F&z="
	if got := canonicalQuery(q); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEscape(t *testing.T) {
	if got := escape("a b/c$d~e.f_g-h/é", false); got != "a%20b/c%24d~e.f_g-h/%C3%A9" {
		t.Errorf("path: %q", got)
	}
	if got := escape("a/b", true); got != "a%2Fb" {
		t.Errorf("query: %q", got)
	}
}
