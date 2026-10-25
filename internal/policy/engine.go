package policy

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/facts"
)

//go:embed lib.rego
var library string

// Lattice switches control enforcement. Labels keep recording both axes.
type Lattices struct {
	Confidentiality bool `json:"confidentiality"`
	Integrity       bool `json:"integrity"`
}

// IDs bind approval waivers; messages explain them without granting authority.
type Requirement struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type Decision struct {
	Deny         []string      `json:"deny"`
	Requirements []Requirement `json:"requirements"`
	Sends        string        `json:"sends"`
	Next         facts.Label   `json:"next"`
}

// Engine is a prepared policy. Program hashes everything the policy's meaning depends on.
type Engine struct {
	Program string
	query   rego.PreparedEvalQuery
}

func prepare(ctx context.Context, data map[string]any, policies map[string]string, lattices Lattices) (*Engine, error) {
	reserved := []string{"monitor", "lattices", "levels"}
	for _, name := range reserved {
		if _, ok := data[name]; ok {
			return nil, fmt.Errorf("data.%s is reserved for the monitor", name)
		}
	}
	store := maps.Clone(data)
	if store == nil {
		store = map[string]any{}
	}
	store["levels"] = map[string]any{"audiences": facts.Audiences, "trusts": facts.Trusts, "effects": facts.Effects}
	store["lattices"] = map[string]any{"confidentiality": lattices.Confidentiality, "integrity": lattices.Integrity}
	opts := []func(*rego.Rego){rego.Query("data.monitor.decision"), rego.Module("monitor/lib.rego", library),
		rego.Store(inmem.NewFromObjectWithOpts(store, inmem.OptReturnASTValuesOnRead(true))), rego.StrictBuiltinErrors(true)}
	h := sha256.New()
	fmt.Fprintf(h, "facts-v%d%q%q", facts.Version, "monitor/lib.rego", library)
	for _, name := range slices.Sorted(maps.Keys(policies)) {
		filename := "policies/" + name
		module, err := ast.ParseModule(filename, policies[name])
		if err != nil {
			return nil, err
		}
		for _, r := range reserved {
			if module.Package.Path.HasPrefix(ast.MustParseRef("data." + r)) {
				return nil, fmt.Errorf("policy %s: data.%s is reserved for the monitor", name, r)
			}
		}
		fmt.Fprintf(h, "%q%q", filename, policies[name])
		opts = append(opts, rego.ParsedModule(module))
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	h.Write(raw)
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	return &Engine{Program: hex.EncodeToString(h.Sum(nil)), query: query}, nil
}

func (e *Engine) Decide(ctx context.Context, input map[string]any) (Decision, error) {
	// Each evaluation owns its lazy objects: OPA caches fields as it reads them.
	results, err := e.query.Eval(ctx, rego.EvalParsedInput(ast.LazyObject(input)))
	if err != nil {
		return Decision{}, fmt.Errorf("policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return Decision{}, errors.New("policy returned no decision")
	}
	d, err := facts.JSON[Decision](results[0].Expressions[0].Value)
	if err != nil {
		return Decision{}, fmt.Errorf("policy returned an invalid decision: %w", err)
	}
	return d, nil
}
