// SPDX-License-Identifier: Apache-2.0

package objstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4 in the Authorization header, with the payload's SHA-256 in
// x-amz-content-sha256, as S3 defines it for a payload sent in one piece.
const (
	algorithm  = "AWS4-HMAC-SHA256"
	s3         = "s3"
	amzDate    = "20060102T150405Z"
	scopeDate  = "20060102"
	emptyHash  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hdrDate    = "X-Amz-Date"
	hdrPayload = "X-Amz-Content-Sha256"
)

// unsigned are the headers a request may carry that are not signed: a proxy or the transport
// may change them on the way.
var unsigned = map[string]bool{"authorization": true, "user-agent": true, "content-length": true,
	"accept-encoding": true, "expect": true, "connection": true, "x-amzn-trace-id": true}

// sign adds X-Amz-Date, X-Amz-Content-Sha256 and the Authorization header to r, signing its
// method, its path and query as sent, the host and every other header it carries.
func sign(r *http.Request, payloadHash string, c Credentials, region string, now time.Time) {
	now = now.UTC()
	r.Header.Set(hdrDate, now.Format(amzDate))
	r.Header.Set(hdrPayload, payloadHash)
	authorize(r, payloadHash, c, region, s3, now)
}

// authorize signs the headers r carries now and sets Authorization. It is split from sign so that
// the AWS test suite, which names its own service and signs no X-Amz-Content-Sha256, can drive it.
func authorize(r *http.Request, payloadHash string, c Credentials, region, service string, now time.Time) {

	names := []string{"host"}
	values := map[string]string{"host": r.URL.Host}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if unsigned[lk] {
			continue
		}
		vs := make([]string, len(v))
		for i, s := range v {
			vs[i] = strings.Join(strings.Fields(s), " ")
		}
		names = append(names, lk)
		values[lk] = strings.Join(vs, ",")
	}
	sort.Strings(names)
	var headers strings.Builder
	for _, n := range names {
		headers.WriteString(n + ":" + values[n] + "\n")
	}
	signed := strings.Join(names, ";")

	canonical := strings.Join([]string{
		r.Method,
		escape(r.URL.Path, false),
		canonicalQuery(r.URL.Query()),
		headers.String(),
		signed,
		payloadHash,
	}, "\n")
	scope := now.Format(scopeDate) + "/" + region + "/" + service + "/aws4_request"
	toSign := algorithm + "\n" + now.Format(amzDate) + "\n" + scope + "\n" + hexSHA256([]byte(canonical))

	key := hmacSHA256([]byte("AWS4"+c.SecretAccessKey.Reveal()), now.Format(scopeDate))
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))

	r.Header.Set("Authorization", algorithm+" Credential="+c.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

// canonicalQuery sorts the parameters by name, then value, each encoded as S3 does.
func canonicalQuery(q url.Values) string {
	type pair struct{ k, v string }
	var pairs []pair
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, pair{escape(k, true), escape(v, true)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

// escape percent-encodes every byte but the unreserved characters of RFC 3986, and, unless all is
// set, the slash between a path's segments.
func escape(s string, all bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == '/' && !all:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
