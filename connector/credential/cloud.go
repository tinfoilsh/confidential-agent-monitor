package credential

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	awsDefaultRegion   = "us-east-1"
	awsRoleSessionName = "perimeter"
	awsExpiryWindow    = time.Minute
	googleScope        = "https://www.googleapis.com/auth/cloud-platform"
)

var (
	errAWS        = errors.New("aws credentials need an access key ID, a secret access key and, if set, a valid role ARN and region")
	errAssumeRole = errors.New("aws assume role failed")
	errGoogle     = errors.New("google credentials must be a service_account or authorized_user JSON file for Google's token endpoint")
	googleTypes   = []google.CredentialsType{google.ServiceAccount, google.AuthorizedUser}
	awsRegion     = regexp.MustCompile(`\A[a-z0-9-]+\z`)
)

type awsKeys struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	RoleARN         string `json:"role_arn"`
	ExternalID      string `json:"external_id"`
	Region          string `json:"region"`
}

type googleFile struct {
	Type        google.CredentialsType `json:"type"`
	ClientEmail string                 `json:"client_email"`
	TokenURI    string                 `json:"token_uri"`
	Audience    string                 `json:"audience"`
	Web         any                    `json:"web"`
	Installed   any                    `json:"installed"`
}

func parseAWS(k awsKeys, o Options) (*Value, error) {
	if k.AccessKeyID == "" || k.SecretAccessKey == "" || k.RoleARN != "" && !arn.IsARN(k.RoleARN) || k.Region != "" && !awsRegion.MatchString(k.Region) {
		return nil, errAWS
	}
	var provider aws.CredentialsProvider = credentials.NewStaticCredentialsProvider(k.AccessKeyID, k.SecretAccessKey, k.SessionToken)
	if k.RoleARN != "" {
		// CredentialsCache refreshes under a context that ignores cancellation, so only the client bounds each STS call.
		client := *o.Client
		client.Timeout = o.Timeout
		source := sts.New(sts.Options{Region: cmp.Or(k.Region, awsDefaultRegion), HTTPClient: &client, Credentials: provider})
		provider = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(source, k.RoleARN, func(a *stscreds.AssumeRoleOptions) {
			a.RoleSessionName = awsRoleSessionName
			if k.ExternalID != "" {
				a.ExternalID = &k.ExternalID
			}
		}), func(c *aws.CredentialsCacheOptions) { c.ExpiryWindow = awsExpiryWindow })
	}
	return &Value{configured: true, resolve: func(ctx context.Context) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, o.Timeout)
		defer cancel()
		creds, err := provider.Retrieve(ctx)
		var api smithy.APIError
		switch {
		case ctx.Err() != nil:
			return "", ctx.Err()
		case errors.As(err, &api):
			return "", fmt.Errorf("%w: %s", errAssumeRole, api.ErrorCode())
		case err != nil:
			return "", errAssumeRole
		}
		raw, err := json.Marshal(creds)
		return string(raw), err
	}}, nil
}

func parseGoogle(file string, o Options) (*Value, error) {
	var f googleFile
	// CredentialsFromJSONWithType checks only the type and still prefers a web or installed client, which needs an interactive sign-in.
	if json.Unmarshal([]byte(file), &f) != nil || !slices.Contains(googleTypes, f.Type) || f.Web != nil || f.Installed != nil ||
		f.TokenURI != "" && f.TokenURI != google.Endpoint.TokenURL || f.Audience != "" {
		return nil, errGoogle
	}
	client := *o.Client
	client.Timeout = o.Timeout
	creds, err := google.CredentialsFromJSONWithType(context.WithValue(context.Background(), oauth2.HTTPClient, &client), []byte(file), f.Type, googleScope)
	if err != nil {
		return nil, errGoogle
	}
	return &Value{configured: true, resolve: func(ctx context.Context) (string, error) {
		t, err := creds.TokenSource.Token()
		if err != nil {
			return "", Scrub(ctx, "refresh", err)
		}
		return t.AccessToken, nil
	}}, nil
}
