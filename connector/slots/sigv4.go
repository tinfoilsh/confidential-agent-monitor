package slots

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/encoding/httpbinding"
)

const (
	sigV4Credential = "AWS4-HMAC-SHA256 Credential="
	unsignedTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

type SigV4 struct {
	Service string `json:"service"`
	Region  string `json:"region"`
	Secret  string `json:"secret"`
	Session string `json:"session,omitempty"`
}

var (
	sigV4Signer = v4.NewSigner()
	sigV4Scope  = regexp.MustCompile(`\A[0-9]{8}/([a-z0-9-]+)/([a-z0-9-]+)/aws4_request\z`)
)

func streaming(header http.Header) error {
	if header.Get("X-Amz-Content-Sha256") != unsignedTrailer && (strings.Contains(strings.ToLower(strings.Join(header.Values("Content-Encoding"), ",")), "aws-chunked") ||
		strings.HasPrefix(header.Get("X-Amz-Content-Sha256"), "STREAMING-") || header.Get("X-Amz-Decoded-Content-Length") != "" || header.Get("X-Amz-Trailer") != "") {
		return errors.New("streaming S3 uploads with signed chunks are refused")
	}
	return nil
}

func presigned(query url.Values) bool {
	for key := range query {
		key = strings.ToLower(key)
		if strings.HasPrefix(key, "x-amz-") || key == "awsaccesskeyid" || key == "signature" || key == "expires" {
			return true
		}
	}
	return false
}

func sign(r *http.Request, keys aws.Credentials, s *SigV4, now time.Time, limit int64) error {
	hash := r.Header.Get("X-Amz-Content-Sha256")
	if hash != unsignedTrailer {
		var body []byte
		if r.Body != nil {
			var err error
			body, err = io.ReadAll(io.LimitReader(r.Body, limit+1))
			r.Body.Close()
			if err != nil {
				return err
			}
			if int64(len(body)) > limit {
				return errors.New("the request body is too large to sign")
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		r.ContentLength, r.TransferEncoding = int64(len(body)), nil
		sum := sha256.Sum256(body)
		hash = hex.EncodeToString(sum[:])
	}
	for _, name := range []string{authorization, "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Content-Sha256"} {
		r.Header.Del(name)
	}
	if s.Service == "s3" || hash == unsignedTrailer {
		r.Header.Set("X-Amz-Content-Sha256", hash)
	}
	r.URL.RawPath = httpbinding.EscapePath(r.URL.Path, false)
	return sigV4Signer.SignHTTP(r.Context(), keys, r, hash, s.Service, s.Region, now, func(o *v4.SignerOptions) { o.DisableURIPathEscaping = s.Service == "s3" })
}
