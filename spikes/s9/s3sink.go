// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// s3Endpoint is the MinIO the spike uses; README starts it.
func s3Endpoint() string {
	if v := os.Getenv("S9_S3"); v != "" {
		return v
	}
	return "http://127.0.0.1:19000"
}

func s3Client() *s3.Client {
	return s3.New(s3.Options{
		BaseEndpoint: aws.String(s3Endpoint()),
		Region:       "us-east-1",
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("s9admin", "s9-spike-password", ""),
	})
}

func ensureBucket(ctx context.Context, c *s3.Client, bucket string) error {
	_, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	var owned interface{ ErrorCode() string }
	if errors.As(err, &owned) && (owned.ErrorCode() == "BucketAlreadyOwnedByYou" || owned.ErrorCode() == "BucketAlreadyExists") {
		return nil
	}
	return err
}

// s3Sink is the revocation-log sink on S3-compatible storage, with the filesystem sink's
// algorithm (internal/revlog/sink.go): the object named by a sequence number is created with
// If-None-Match: *, so allocating the number and writing the entry are one step.
type s3Sink struct {
	c             *s3.Client
	bucket        string
	prefix        string
	unconditional bool // negative control: plain PUTs, which overwrite
	cache         []revlog.SinkEntry
	Taken         int // numbers another shipper took first
	Conflicts     int // 409 ConditionalRequestConflict, retried
}

func (s *s3Sink) key(seq uint64) string { return fmt.Sprintf("%s%020d", s.prefix, seq) }

func sinkHash(e revlog.SinkEntry) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// read lists the objects after the cached ones and verifies the chain: numbers without a gap,
// each entry's hash and each link.
func (s *s3Sink) read(ctx context.Context) ([]revlog.SinkEntry, error) {
	after := ""
	if n := len(s.cache); n > 0 {
		after = s.key(uint64(n))
	}
	var keys []string
	p := s3.NewListObjectsV2Paginator(s.c, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(s.prefix),
		StartAfter: aws.String(after)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, o := range page.Contents {
			keys = append(keys, aws.ToString(o.Key))
		}
	}
	for _, k := range keys {
		n, err := strconv.ParseUint(strings.TrimPrefix(k, s.prefix), 10, 64)
		if err != nil {
			continue
		}
		if n != uint64(len(s.cache))+1 {
			return nil, fmt.Errorf("the sink has no entry %d", len(s.cache)+1)
		}
		obj, err := s.c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(k)})
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(obj.Body)
		_ = obj.Body.Close()
		if err != nil {
			return nil, err
		}
		var e revlog.SinkEntry
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("sink entry %d: %w", n, err)
		}
		h, err := sinkHash(e)
		if err != nil {
			return nil, err
		}
		prev := ""
		if len(s.cache) > 0 {
			prev = s.cache[len(s.cache)-1].Hash
		}
		if e.Seq != n || e.Prev != prev || e.Hash != h {
			return nil, fmt.Errorf("sink entry %d does not verify", n)
		}
		s.cache = append(s.cache, e)
	}
	return s.cache, nil
}

// ship copies the local log's entries the sink does not hold yet for replica.
func (s *s3Sink) ship(ctx context.Context, path, replica string) error {
	local, err := revlog.Read(path)
	if err != nil {
		return err
	}
	sink, err := s.read(ctx)
	if err != nil {
		return err
	}
	shipped := map[string]bool{}
	for _, e := range sink {
		if e.Replica == replica {
			shipped[e.Entry.Hash] = true
		}
	}
	var todo []revlog.Entry
	for _, e := range local {
		if !shipped[e.Hash] {
			todo = append(todo, e)
		}
	}
	for len(todo) > 0 {
		next, prev := uint64(len(s.cache))+1, ""
		if len(s.cache) > 0 {
			prev = s.cache[len(s.cache)-1].Hash
		}
		e := revlog.SinkEntry{Seq: next, Replica: replica, Entry: todo[0], Prev: prev}
		if e.Hash, err = sinkHash(e); err != nil {
			return err
		}
		taken, err := s.publish(ctx, e)
		if err != nil {
			return err
		}
		if taken {
			if _, err := s.read(ctx); err != nil {
				return err
			}
			continue
		}
		s.cache, todo = append(s.cache, e), todo[1:]
	}
	return nil
}

func (s *s3Sink) publish(ctx context.Context, e revlog.SinkEntry) (taken bool, err error) {
	b, err := json.Marshal(e)
	if err != nil {
		return false, err
	}
	in := &s3.PutObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(s.key(e.Seq)), Body: bytes.NewReader(append(b, '\n'))}
	if !s.unconditional {
		in.IfNoneMatch = aws.String("*")
	}
	_, err = s.c.PutObject(ctx, in)
	switch code := statusOf(err); {
	case err == nil:
		return false, nil
	case code == http.StatusPreconditionFailed:
		s.Taken++
		return true, nil
	case code == http.StatusConflict: // a conditional write of the same key in flight
		s.Conflicts++
		return true, nil
	default:
		return false, err
	}
}

func statusOf(err error) int {
	var re interface{ HTTPStatusCode() int }
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	var ae smithy.APIError
	if errors.As(err, &ae) && ae.ErrorCode() == "PreconditionFailed" {
		return http.StatusPreconditionFailed
	}
	return 0
}
