package format

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"

	"github.com/tinfoilsh/confidential-agent-monitor/core/sealedlog"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
)

const StateVersion = 4

const documentObject = "monitor.enc"

type Keys struct {
	HostKey string `json:"host_key"`
	CACert  string `json:"ca_cert"`
	CAKey   string `json:"ca_key"`
}

type Label struct {
	Audience string            `json:"audience"`
	Trust    string            `json:"trust"`
	Because  map[string]string `json:"because,omitempty"`
}

type Catalog struct {
	URL string `json:"url"`
	Pin string `json:"pin"`
}

type Document struct {
	Version     int                        `json:"version"`
	Generation  uint64                     `json:"generation"`
	Revision    uint64                     `json:"revision"`
	Keys        Keys                       `json:"keys"`
	Labels      map[string]Label           `json:"labels"`
	Policy      string                     `json:"policy"`
	Credentials Secrets                    `json:"credentials,omitempty"`
	Enrolled    map[string]bool            `json:"enrolled,omitempty"`
	Pending     map[string]json.RawMessage `json:"pending,omitempty"`
	Catalogs    map[string]Catalog         `json:"catalogs,omitempty"`
}

func DecodeDocument(plain []byte) (Document, error) {
	plain, err := upgradeV2(plain)
	if err == nil {
		plain, err = upgradeV3(plain)
	}
	if err != nil {
		return Document{}, fmt.Errorf("stored state: %w", err)
	}
	var d Document
	if err := json.Unmarshal(plain, &d); err != nil {
		return Document{}, fmt.Errorf("stored state: %w", err)
	}
	if d.Version != StateVersion {
		return Document{}, fmt.Errorf("unsupported stored state version %d (latest supported: %d)", d.Version, StateVersion)
	}
	return d, nil
}

func Load(ctx context.Context, bucket *blob.Bucket, key []byte, minimum uint64) (Document, sealedlog.Sealer, bool, error) {
	var doc Document
	if len(key) < sealedlog.MinKeyBytes || len(key) > sealedlog.MaxKeyBytes {
		return doc, sealedlog.Sealer{}, false, sealedlog.ErrKey
	}
	raw, err := bucket.ReadAll(ctx, documentObject)
	missing := false
	if err != nil {
		if missing, err = documentMissing(ctx, bucket, err); err != nil {
			return doc, sealedlog.Sealer{}, false, err
		}
	}
	if missing && minimum != 0 {
		return doc, sealedlog.Sealer{}, false, fmt.Errorf("the Perimeter has no saved state, but generation %d was saved", minimum)
	}
	var sealer sealedlog.Sealer
	if missing {
		sealer, err = sealedlog.NewSealer(key)
		doc = Document{Version: StateVersion, Labels: map[string]Label{}}
	} else {
		var plain []byte
		if sealer, plain, err = sealedlog.OpenState(key, raw); err == nil {
			doc, err = DecodeDocument(plain)
		}
	}
	if err == nil && doc.Generation < minimum {
		err = fmt.Errorf("stored generation %d is older than %d", doc.Generation, minimum)
	}
	return doc, sealer, missing, err
}

func Save(ctx context.Context, bucket *blob.Bucket, sealer sealedlog.Sealer, d Document) error {
	d.Version = StateVersion
	plain, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return bucket.WriteAll(ctx, documentObject, sealer.SealState(plain), nil)
}

func documentMissing(ctx context.Context, bucket *blob.Bucket, err error) (bool, error) {
	switch gcerrors.Code(err) {
	case gcerrors.NotFound:
		return true, nil
	case gcerrors.PermissionDenied:
		items := bucket.List(&blob.ListOptions{Prefix: documentObject})
		for {
			item, listErr := items.Next(ctx)
			if errors.Is(listErr, io.EOF) {
				return true, nil
			}
			if listErr != nil {
				return false, errors.Join(err, listErr)
			}
			if item.Key == documentObject {
				return false, err
			}
		}
	}
	return false, err
}

func Exists(ctx context.Context, bucket *blob.Bucket) (bool, error) {
	_, err := bucket.Attributes(ctx, documentObject)
	if err == nil {
		return true, nil
	}
	missing, err := documentMissing(ctx, bucket, err)
	return !missing, err
}

func Storage(bucket *blob.Bucket) sealedlog.Storage {
	return sealedlog.Storage{Read: bucket.ReadAll,
		Write: func(ctx context.Context, key string, data []byte) error { return bucket.WriteAll(ctx, key, data, nil) },
		List: func(ctx context.Context, prefix, delimiter string) ([]string, error) {
			keys := []string{}
			items := bucket.List(&blob.ListOptions{Prefix: prefix, Delimiter: delimiter})
			for {
				item, err := items.Next(ctx)
				if errors.Is(err, io.EOF) {
					return keys, nil
				}
				if err != nil {
					return nil, err
				}
				keys = append(keys, item.Key)
			}
		}}
}

type SecretID struct{ Connection, Name string }

type Secrets map[string]map[string]json.RawMessage

func (s Secrets) Get(id SecretID) json.RawMessage { return s[id.Connection][id.Name] }

func (s Secrets) Set(id SecretID, raw json.RawMessage) {
	if raw != nil {
		if s[id.Connection] == nil {
			s[id.Connection] = map[string]json.RawMessage{}
		}
		s[id.Connection][id.Name] = raw
		return
	}
	delete(s[id.Connection], id.Name)
	if len(s[id.Connection]) == 0 {
		delete(s, id.Connection)
	}
}

func (s Secrets) Clone() Secrets {
	out := Secrets{}
	for connection, values := range s {
		out[connection] = maps.Clone(values)
	}
	return out
}
