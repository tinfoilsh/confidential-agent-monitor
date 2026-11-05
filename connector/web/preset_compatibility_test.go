package web

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/presets"
)

func shippedSetup(t *testing.T, name string) *Setup {
	t.Helper()
	all, err := presets.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	p := all[name]
	var kinds map[string]json.RawMessage
	if err := json.Unmarshal(p.Catalog.Connections[""], &kinds); err != nil {
		t.Fatal(err)
	}
	config := kinds["http"]
	var options json.RawMessage
	if name == "grafana" {
		config = json.RawMessage(`{"slots":[{"value":"api_key","origin":"https://example.invalid","path":"/","header":"Authorization","prefix":"Bearer "}]}`)
		options = json.RawMessage(`{"origin":"https://example.invalid"}`)
	}
	prepared, err := Parse(connector.Setup{Config: config, Definition: p.Source, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	return prepared.Value.(*Setup)
}

func describeHTTP(t *testing.T, setup *Setup, method, target, body, contentType string) (facts.Facts, error) {
	t.Helper()
	r, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	request := newRequest(r)
	if err := request.capture(setup, r); err != nil {
		return facts.Facts{}, err
	}
	return request.Describe(setup)
}

func TestShippedHTTPPresetsCompile(t *testing.T) {
	all, err := presets.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range all {
		t.Run(name, func(t *testing.T) {
			var root map[string]json.RawMessage
			if err := json.Unmarshal(p.Source, &root); err != nil {
				t.Fatal(err)
			}
			if raw := root["http"]; len(raw) > 0 {
				var compiled Preset
				if err := json.Unmarshal(raw, &compiled); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSlackSDKReadVariants(t *testing.T) {
	h := shippedSetup(t, "slack")
	for _, method := range []string{"history", "replies"} {
		for _, verb := range []string{"GET", "POST"} {
			t.Run(method+verb, func(t *testing.T) {
				body := "channel=C_SYNTHETIC&ts=1.0&cursor=synthetic&limit=10"
				target := "https://slack.com/api/conversations." + method
				contentType := "application/x-www-form-urlencoded"
				if verb == "GET" {
					target += "?" + body
					body, contentType = "", ""
					if method == "history" {
						target = strings.Replace(target, "&ts=1.0", "", 1)
					}
				}
				f, err := describeHTTP(t, h, verb, target, body, contentType)
				if err != nil || f.Operation == nil || f.Operation.Action != "conversations."+method+".read" || !slices.Equal(f.Operation.Effects, []string{"read"}) || f.Parameters["channel"] != "C_SYNTHETIC" {
					t.Fatalf("read variant: %+v, %v", f, err)
				}
				if verb == "POST" && f.Parameters["request"] == nil {
					t.Fatal("full form must be available for approval binding")
				}
			})
		}
	}
}

func TestSlackViewsAreChangesNotReads(t *testing.T) {
	h := shippedSetup(t, "slack")
	for _, tc := range []struct{ method, identity string }{
		{"open", `"trigger_id":"T_SYNTHETIC"`}, {"update", `"view_id":"V_SYNTHETIC"`},
		{"push", `"trigger_id":"T_SYNTHETIC"`}, {"publish", `"user_id":"U_SYNTHETIC"`},
	} {
		t.Run(tc.method, func(t *testing.T) {
			target := "https://slack.com/api/views." + tc.method
			body := `{` + tc.identity + `,"view":{"type":"modal","blocks":[],"private_metadata":"SYNTHETIC"}}`
			f, err := describeHTTP(t, h, "POST", target, body, "application/json")
			if err != nil || f.Operation == nil || !slices.Contains(f.Operation.Effects, "write") || !slices.Contains(f.Operation.Effects, "send") || slices.Contains(f.Operation.Effects, "read") || !strings.HasSuffix(f.Operation.Action, ".write") {
				t.Fatalf("view is not a read: %+v, %v", f.Operation, err)
			}
			if f.Parameters["request"] == nil || f.Parameters["view"] == nil {
				t.Fatal("complete view and request must be extracted")
			}
			f, err = describeHTTP(t, h, "GET", target, "", "")
			if err == nil && f.Operation != nil {
				t.Fatal("stale GET view descriptor remains")
			}
		})
	}
}

func TestSlackVariantsRejectWrongShapes(t *testing.T) {
	h := shippedSetup(t, "slack")
	for _, tc := range []struct{ path, body, contentType string }{
		{"conversations.history", "channel=A&channel=B", "application/x-www-form-urlencoded"},
		{"conversations.history", "limit=1", "application/x-www-form-urlencoded"},
		{"conversations.replies", "channel=A", "application/x-www-form-urlencoded"},
		{"conversations.history", `{"channel":"A"}`, "application/json"},
		{"views.open", `{"trigger_id":"T","view":"not-an-object"}`, "application/json"},
		{"views.open", `{"view":{}}`, "application/json"},
		{"views.update", `{"view_id":42,"view":{}}`, "application/json"},
		{"views.open", "trigger_id=T&view=%7B%7D", "application/x-www-form-urlencoded"},
	} {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			f, err := describeHTTP(t, h, "POST", "https://slack.com/api/"+tc.path, tc.body, tc.contentType)
			if err == nil && f.Operation != nil {
				t.Fatal("unsupported shape accepted")
			}
		})
	}
}

func TestGitHubReleaseRoutes(t *testing.T) {
	h := shippedSetup(t, "github")
	for _, tc := range []struct{ suffix, id string }{
		{"latest", "repos/get-latest-release"}, {"123", "repos/get-release"},
		{"tags/v1.0", "repos/get-release-by-tag"}, {"not-an-id", ""}, {"123latest", ""},
	} {
		t.Run(tc.suffix, func(t *testing.T) {
			f, err := describeHTTP(t, h, "GET", "https://api.github.com/repos/synthetic/example/releases/"+tc.suffix, "", "")
			if err != nil {
				t.Fatal(err)
			}
			if tc.id == "" {
				if f.Operation != nil {
					t.Fatal("non-numeric release ID accepted")
				}
			} else if f.Operation == nil || f.Operation.ID != tc.id {
				t.Fatalf("wanted %s, got %+v", tc.id, f.Operation)
			}
		})
	}
}

func TestGrafanaNestedReads(t *testing.T) {
	h := shippedSetup(t, "grafana")
	for _, tc := range []struct{ verb, path, body, id string }{
		{"GET", "/api/frontend/settings", "", "getFrontendSettings"},
		{"GET", "/apis/dashboard.grafana.app", "", "getDashboardAPIGroup"},
		{"GET", "/api/datasources/proxy/uid/ds-a/loki/api/v1/labels?start=1&end=2", "", "datasourceLokiLabels"},
		{"GET", "/api/datasources/proxy/uid/ds-a/loki/api/v1/label/job/values?start=1", "", "datasourceLokiLabelValues"},
		{"GET", "/api/datasources/proxy/uid/ds-a/loki/api/v1/index/stats?query=%7Bjob%3D%22x%22%7D", "", "datasourceLokiIndexStats"},
		{"GET", "/api/datasources/proxy/uid/ds-a/loki/api/v1/patterns?query=x&step=1", "", "datasourceLokiPatterns"},
		{"GET", "/api/datasources/uid/ds-a/resources/api/v1/labels?match[]=up&match[]=down", "", "datasourcePrometheusLabels"},
		{"POST", "/api/datasources/uid/ds-a/resources/api/v1/labels", "start=1&end=2&match[]=up", "datasourcePrometheusLabels.form"},
		{"GET", "/api/datasources/uid/ds-a/resources/api/v1/label/__name__/values?limit=10", "", "datasourcePrometheusLabelValues"},
		{"GET", "/api/datasources/uid/ds-a/resources/api/v1/metadata?metric=up&limit=10", "", "datasourcePrometheusMetadata"},
		{"GET", "/api/health", "", "getHealth"},
		{"GET", "/api/datasources/uid/ds-a/resources/legacy", "", "callDatasourceResourceWithUID"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			contentType := ""
			if tc.verb == "POST" {
				contentType = "application/x-www-form-urlencoded"
			}
			f, err := describeHTTP(t, h, tc.verb, "https://example.invalid"+tc.path, tc.body, contentType)
			if err != nil || f.Operation == nil || f.Operation.ID != tc.id || !slices.Equal(f.Operation.Effects, []string{"read"}) {
				t.Fatalf("wanted %s, got %+v: %v", tc.id, f.Operation, err)
			}
			if strings.Contains(tc.path, "ds-a") && f.Parameters["uid"] != "ds-a" {
				t.Fatal("datasource scope was lost")
			}
			if strings.Contains(tc.path, "?") && f.Parameters["query"] == nil {
				t.Fatal("query parameters were not extracted")
			}
		})
	}
}

func TestGrafanaNestedRoutesStayBounded(t *testing.T) {
	h := shippedSetup(t, "grafana")
	for _, tc := range []struct{ verb, origin, path, body, contentType string }{
		{"GET", "https://example.invalid", "/api/datasources/proxy/uid/a/arbitrary/nested/path", "", ""},
		{"GET", "https://example.invalid", "/api/datasources/uid/a/resources/api/v1/admin/delete_series", "", ""},
		{"POST", "https://example.invalid", "/api/datasources/proxy/uid/a/loki/api/v1/push", "{}", "application/json"},
		{"DELETE", "https://example.invalid", "/api/datasources/proxy/uid/a/loki/api/v1/labels", "", ""},
		{"GET", "https://example.invalid", "/api/datasources/uid/a/resources/api/v1/metadata?unreviewed=x", "", ""},
		{"POST", "https://example.invalid", "/api/datasources/uid/a/resources/api/v1/labels", "{}", "application/json"},
		{"GET", "https://other.invalid", "/api/frontend/settings", "", ""},
		{"GET", "https://example.invalid", "/apis/dashboard.grafana.app/v1/arbitrary", "", ""},
		{"GET", "https://example.invalid", "/api/datasources/proxy/uid/a/loki/api/v1/label/x%2fy/values", "", ""},
	} {
		t.Run(tc.verb+tc.origin+tc.path, func(t *testing.T) {
			f, err := describeHTTP(t, h, tc.verb, tc.origin+tc.path, tc.body, tc.contentType)
			if err == nil && f.Operation != nil {
				t.Fatalf("unreviewed route accepted: %+v", f.Operation)
			}
		})
	}
}
