// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Page sizes of List methods (docs/07-api.md, "Resource design").
const (
	DefaultPageSize = 50
	MaxPageSize     = 500
)

// ReasonEtagMismatch is the reason of an update or delete whose etag is not the stored one.
const ReasonEtagMismatch = "ETAG_MISMATCH"

// pageTag is the length of a page token's MAC.
const pageTag = 16

// PageSize returns the page size of a List request: the default for 0, at most MaxPageSize.
func PageSize(requested int32) (int, error) {
	switch {
	case requested < 0:
		return 0, connect.NewError(connect.CodeInvalidArgument, errors.New("api: page_size must not be negative"))
	case requested == 0:
		return DefaultPageSize, nil
	case requested > MaxPageSize:
		return MaxPageSize, nil
	}
	return int(requested), nil
}

// PageToken returns the opaque token of the page after the item with key after, for the List
// request req; the token is bound to req's other fields, so it cannot continue another query.
func (s *Server) PageToken(after string, req proto.Message) string {
	b := binary.AppendUvarint(nil, uint64(len(after)))
	b = append(b, after...)
	return base64.RawURLEncoding.EncodeToString(append(b, s.pageMAC(after, req)...))
}

// AfterPage returns the key a page token continues after; "" for no token. A token that was not
// made by PageToken for the same query is INVALID_ARGUMENT.
func (s *Server) AfterPage(token string, req proto.Message) (string, error) {
	if token == "" {
		return "", nil
	}
	bad := connect.NewError(connect.CodeInvalidArgument, errors.New("api: the page_token is not valid for this request"))
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", bad
	}
	n, k := binary.Uvarint(b)
	m := len(b) - k - pageTag // the key's length, if the token is whole
	if k <= 0 || m < 0 || n != uint64(m) {
		return "", bad
	}
	after := string(b[k : k+m])
	if !hmac.Equal(b[k+m:], s.pageMAC(after, req)) {
		return "", bad
	}
	return after, nil
}

// pageMAC authenticates a position for a query: the request without its page_token and
// page_size.
func (s *Server) pageMAC(after string, req proto.Message) []byte {
	q := proto.Clone(req).ProtoReflect()
	for _, name := range []protoreflect.Name{"page_token", "page_size"} {
		if fd := q.Descriptor().Fields().ByName(name); fd != nil {
			q.Clear(fd)
		}
	}
	query, _ := proto.MarshalOptions{Deterministic: true}.Marshal(q.Interface())
	mac := hmac.New(sha256.New, s.pageKey)
	_, _ = fmt.Fprintf(mac, "%s\x00%d\x00", q.Descriptor().FullName(), len(after))
	_, _ = mac.Write([]byte(after))
	_, _ = mac.Write(query)
	return mac.Sum(nil)[:pageTag]
}

// Etag is the etag of a resource at a version.
func Etag(version int64) string { return strconv.FormatInt(version, 10) }

// CheckEtag compares a request's etag with the stored version; an empty etag skips the check, as
// the CLI's --force does. A mismatch is FAILED_PRECONDITION with reason ETAG_MISMATCH and the
// current resource, redacted, as a detail, so a client can show what changed.
func CheckEtag(etag string, version int64, current proto.Message) error {
	if etag == "" || etag == Etag(version) {
		return nil
	}
	err := connect.NewError(connect.CodeFailedPrecondition, errors.New("api: the resource changed since it was read"))
	if current != nil {
		if d, derr := connect.NewErrorDetail(Redact(current)); derr == nil {
			err.AddDetail(d)
		}
	}
	return withInfo(err, ReasonEtagMismatch, nil)
}

// ApplyMask sets in dst every field that mask names to its value in src, clearing it where src
// leaves it unset; nothing else in dst changes. Paths name fields by their proto names, through
// singular messages with dots, and must start with one of allowed, the fields a client may
// change. An empty mask, a path not in the message or not allowed is INVALID_ARGUMENT.
func ApplyMask(dst, src proto.Message, mask *fieldmaskpb.FieldMask, allowed ...string) error {
	invalid := func(format string, args ...any) error {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("api: update_mask: "+format, args...))
	}
	if len(mask.GetPaths()) == 0 {
		return invalid("names no field")
	}
	d, sr := dst.ProtoReflect(), src.ProtoReflect()
	if d.Descriptor().FullName() != sr.Descriptor().FullName() {
		return invalid("%s and %s differ", d.Descriptor().FullName(), sr.Descriptor().FullName())
	}
	for _, path := range mask.GetPaths() {
		if !permitted(path, allowed) {
			return invalid("%q cannot be changed", path)
		}
		names := strings.Split(path, ".")
		dm, sm := d, sr
		for i, name := range names {
			fd := dm.Descriptor().Fields().ByName(protoreflect.Name(name))
			if fd == nil {
				return invalid("%q is not a field", path)
			}
			if i == len(names)-1 {
				if sm != nil && sm.Has(fd) {
					dm.Set(fd, sm.Get(fd))
				} else {
					dm.Clear(fd)
				}
				break
			}
			if fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
				return invalid("%q goes through a field that is not a message", path)
			}
			dm = dm.Mutable(fd).Message()
			if sm != nil && sm.Has(fd) {
				sm = sm.Get(fd).Message()
			} else {
				sm = nil
			}
		}
	}
	return nil
}

// permitted reports whether path is one of allowed or below one.
func permitted(path string, allowed []string) bool {
	for _, a := range allowed {
		if path == a || strings.HasPrefix(path, a+".") {
			return true
		}
	}
	return false
}
