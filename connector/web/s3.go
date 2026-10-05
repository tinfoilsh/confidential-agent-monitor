package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/encoding/httpbinding"
)

const (
	maxSignedBodyBytes = 16 << 20
	sigV4Credential    = "AWS4-HMAC-SHA256 Credential="
)

// S3 signs for service s3 with the slot's value as access key ID; Secret and Session name the other values.
type S3 struct {
	Region  string `json:"region"`
	Secret  string `json:"secret"`
	Session string `json:"session,omitempty"`
}

var s3Signer = v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })

// streaming refuses aws-chunked uploads, whose framing a whole-body hash cannot describe.
func streaming(header http.Header) error {
	if strings.Contains(strings.ToLower(strings.Join(header.Values("Content-Encoding"), ",")), "aws-chunked") ||
		strings.HasPrefix(header.Get("X-Amz-Content-Sha256"), "STREAMING-") || header.Get("X-Amz-Decoded-Content-Length") != "" || header.Get("X-Amz-Trailer") != "" {
		return errors.New("streaming S3 uploads are refused")
	}
	return nil
}

// presigned reports SigV4 or SigV2 query authentication, which would bypass the monitor's signature.
func presigned(query url.Values) bool {
	for key := range query {
		key = strings.ToLower(key)
		if strings.HasPrefix(key, "x-amz-") || key == "awsaccesskeyid" || key == "signature" || key == "expires" {
			return true
		}
	}
	return false
}

// signS3 signs the request exactly as it will be sent, hashing a body of at most maxSignedBodyBytes.
func signS3(r *http.Request, keys aws.Credentials, region string, now time.Time) error {
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxSignedBodyBytes+1))
		r.Body.Close()
		if err != nil {
			return err
		}
		if len(body) > maxSignedBodyBytes {
			return errors.New("the S3 request body is too large to sign")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	r.ContentLength, r.TransferEncoding = int64(len(body)), nil
	for _, name := range []string{authorization, "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Content-Sha256"} {
		r.Header.Del(name)
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	r.Header.Set("X-Amz-Content-Sha256", hash)
	r.URL.RawPath = httpbinding.EscapePath(r.URL.Path, false)
	return s3Signer.SignHTTP(r.Context(), keys, r, hash, "s3", region, now)
}
