// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/objstore"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// openS3Sink returns the backend of an s3://<bucket>/<prefix> sink, with the credentials from the
// file of the boot file. Neither the key file's content nor the secret key is in an error.
func openS3Sink(ctx context.Context, rl config.RevocationLog, sink string) (*revlog.S3Backend, error) {
	bucket, prefix, ok, err := config.RevocationLog{Sink: sink}.S3Sink()
	if !ok || err != nil {
		return nil, fmt.Errorf("revocation log sink %q is not an s3:// sink: %w", sink, err)
	}
	if rl.S3.Endpoint == "" {
		return nil, errors.New("revocation_log.s3 is not set in the boot file")
	}
	creds, err := objstore.LoadKeyFile(rl.S3.CredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("revocation_log.s3.credentials_file: %w", err)
	}
	c, err := objstore.New(objstore.Config{Endpoint: rl.S3.Endpoint, Region: rl.S3.Region, Bucket: bucket,
		Credentials: creds, Timeout: revlog.S3RequestTimeout})
	if err != nil {
		return nil, fmt.Errorf("revocation_log.s3: %w", err)
	}
	b := revlog.NewS3Backend(ctx, c, prefix)
	b.LockDays = rl.S3.LockDays
	return b, nil
}

// OpenRevocationSink returns the backend of the revocation-log sink of the boot file; nil for a
// directory, which the shipper opens itself, and for no sink. An S3 sink is probed first: a store
// that does not refuse a second conditional create is an error that keeps the controller from
// starting. A store that cannot be reached is not: revocations are enforced without the sink, and
// the shipper probes again before the first entry goes out.
func OpenRevocationSink(ctx context.Context, rl config.RevocationLog, log *slog.Logger) (revlog.Backend, error) {
	if _, _, isS3, _ := rl.S3Sink(); !isS3 {
		return nil, nil
	}
	b, err := openS3Sink(ctx, rl, rl.Sink)
	if err != nil {
		return nil, err
	}
	switch err := b.Probe(ctx); {
	case errors.Is(err, revlog.ErrNoConditionalCreate):
		return nil, fmt.Errorf("revocation_log.sink %s: %w; a sink on it would overwrite entries and leave gaps, use another store", rl.Sink, err)
	case err != nil:
		log.Warn("revocation log: the sink could not be probed; it is tried again before shipping", "sink", rl.Sink, "error", err)
	}
	return b, nil
}
