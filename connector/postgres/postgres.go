package postgres

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	sslAccepted       = 'S'
	encryptionRefused = 'N'
)

type Postgres struct {
	RawURL string `json:"url"`
	User   string `json:"user"`
	url    *url.URL
}

func Parse(config json.RawMessage) (*Postgres, error) {
	r := new(Postgres)
	if err := facts.DecodeNumbers(config, r); err != nil {
		return nil, err
	}
	u, err := url.Parse(r.RawURL)
	switch {
	case err != nil:
		return nil, err
	case u.Scheme == "" || u.Host == "":
		return nil, errors.New("destination requires a URL with a scheme and host")
	}
	if _, set := u.User.Password(); set || u.Query().Has("password") {
		return nil, errors.New("put the password in the service's password credential, not the URL")
	}
	if r.User != "" {
		u.User = url.User(r.User)
	}
	r.url = u
	return r, nil
}

func (r *Postgres) Hosts() []string { return []string{r.url.Hostname()} }

func (r *Postgres) Handler(dial func(ctx context.Context, network, address string) (net.Conn, error), password func(context.Context) (string, error), serverTLS func(ctx context.Context, host string) *tls.Config, timeout time.Duration) connector.Serve {
	return func(ctx context.Context, s net.Conn, _ string, target connector.Target, gate connector.Gate) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		backend, startup, err := startup(s, serverTLS(ctx, target.Host))
		if err != nil {
			log.Printf("postgres startup: %v", err)
			return
		}
		up, err := r.connect(ctx, dial, password, timeout, startup)
		if err != nil {
			log.Printf("postgres: %v", err)
			backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "08006", Message: err.Error()})
			backend.Flush()
			return
		}
		stop := context.AfterFunc(ctx, func() { up.Conn.Close() })
		defer func() { stop(); up.Conn.Close() }()
		backend.Send(&pgproto3.AuthenticationOk{})
		for name, value := range up.ParameterStatuses {
			backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
		}
		backend.Send(&pgproto3.BackendKeyData{ProcessID: up.PID, SecretKey: up.SecretKey})
		backend.Send(&pgproto3.ReadyForQuery{TxStatus: up.TxStatus})
		if err := backend.Flush(); err != nil {
			return
		}
		relayQueries(ctx, func() { cancel(); s.Close() }, gate, backend, up)
	}
}

func startup(s net.Conn, config *tls.Config) (*pgproto3.Backend, *pgproto3.StartupMessage, error) {
	conn := s
	for {
		backend := pgproto3.NewBackend(conn, conn)
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, err
		}
		switch msg := msg.(type) {
		case *pgproto3.StartupMessage:
			return backend, msg, nil
		case *pgproto3.SSLRequest:
			if config == nil {
				_, err = conn.Write([]byte{encryptionRefused})
			} else if _, err = conn.Write([]byte{sslAccepted}); err == nil {
				conn = tls.Server(conn, config)
			}
			if err != nil {
				return nil, nil, err
			}
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{encryptionRefused}); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("unsupported startup message %T", msg)
		}
	}
}

func (r *Postgres) connect(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), password func(context.Context) (string, error), timeout time.Duration, startup *pgproto3.StartupMessage) (*pgconn.HijackedConn, error) {
	config, err := pgconn.ParseConfig(r.url.String())
	if err != nil {
		return nil, err
	}
	config.Password, err = password(ctx)
	if err != nil {
		return nil, err
	}
	config.DialFunc = dial
	config.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	for name, value := range startup.Parameters {
		if slices.ContainsFunc(sqlGuards, func(guard string) bool {
			return strings.EqualFold(name, guard) || name == "options" && strings.Contains(strings.ToLower(value), guard)
		}) {
			return nil, fmt.Errorf("startup parameter %s is not supported", name)
		}
		if name != "user" && name != "database" {
			config.RuntimeParams[name] = value
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pg, err := pgconn.ConnectConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return pg.Hijack()
}

func relayQueries(ctx context.Context, end func(), gate connector.Gate, backend *pgproto3.Backend, up *pgconn.HijackedConn) {
	var status atomic.Uint32
	status.Store(uint32(up.TxStatus))
	pumped := make(chan struct{})
	defer func() { end(); <-pumped }()
	go func() {
		defer close(pumped)
		defer end()
		for {
			msg, err := up.Frontend.Receive()
			if err != nil {
				return
			}
			if ready, ok := msg.(*pgproto3.ReadyForQuery); ok {
				status.Store(uint32(ready.TxStatus))
			}
			backend.Send(msg)
			if err := backend.Flush(); err != nil {
				return
			}
		}
	}()
	for {
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		sql := ""
		switch msg := msg.(type) {
		case *pgproto3.Query:
			sql = msg.String
		case *pgproto3.Parse:
			sql = msg.Query
		case *pgproto3.FunctionCall:
			err = errors.New("fast-path function calls are not supported")
		}
		if sql != "" {
			err = gate(ctx, facts.Capture((&PostgresFacts{SQL: sql}).Describe(), nil))
		}
		if err != nil {
			backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: err.Error()})
			if _, extended := msg.(*pgproto3.Parse); !extended {
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: byte(status.Load())})
			}
			if err := backend.Flush(); err != nil {
				return
			}
			continue
		}
		up.Frontend.Send(msg)
		if err := up.Frontend.Flush(); err != nil {
			return
		}
	}
}

func (v *PostgresFacts) Describe() facts.Observation {
	details := Details{Postgres: v}
	action := "write"
	if plainRead(v.SQL) {
		action = "read"
	}
	return facts.Observation{Operation: &facts.Operation{Action: action}, Title: "Run " + v.SQL, Parameters: map[string]any{"sql": v.SQL}, Details: details}
}

var (
	sqlWord   = regexp.MustCompile(`^(?:[0-9]+|(?:[A-Za-z_]|[^\x00-\x7f])(?:[A-Za-z0-9_$]|[^\x00-\x7f])*)`)
	sqlDollar = regexp.MustCompile(`^\$(?:(?:[A-Za-z_]|[^\x00-\x7f])(?:[A-Za-z0-9_]|[^\x00-\x7f])*)?\$`)
	sqlWrites = strings.Fields("into insert update delete merge")
	sqlGuards = strings.Fields("role authorization session_authorization session_replication_role default_transaction_read_only transaction_read_only")
	sqlNames  = strings.Fields("as with recursive")
	sqlCalls  = strings.Fields(`
		all and any array as between by case cast cube distinct else except exists explain filter for from group having
		ilike in intersect join lateral like limit materialized not offset on only or over overlaps repeatable rollup row
		select sets some then to union using values when where zone bernoulli system
		coalesce nullif greatest least extract position substring overlay trim normalize grouping
		current_time current_timestamp localtime localtimestamp
		count sum avg min max array_agg string_agg json_agg jsonb_agg json_object_agg jsonb_object_agg bool_and bool_or
		stddev variance percentile_cont percentile_disc mode row_number rank dense_rank ntile lag lead first_value last_value
		lower upper length char_length octet_length substr strpos left right lpad rpad ltrim rtrim btrim replace concat
		concat_ws format split_part initcap repeat reverse translate starts_with regexp_match regexp_matches
		regexp_replace regexp_split_to_array string_to_array array_to_string quote_ident quote_literal md5 encode decode
		abs ceil ceiling floor round trunc mod power sqrt random gen_random_uuid
		now clock_timestamp age date_trunc date_part date_bin make_date make_interval to_char to_date to_number
		to_timestamp to_json to_jsonb row_to_json json_build_object jsonb_build_object json_build_array
		jsonb_build_array json_array_elements jsonb_array_elements jsonb_array_elements_text json_each jsonb_each
		jsonb_each_text jsonb_object_keys jsonb_array_length jsonb_typeof jsonb_pretty jsonb_extract_path_text
		array_length cardinality unnest generate_series
		version current_database current_schema current_schemas current_setting pg_backend_pid has_table_privilege
		pg_typeof format_type obj_description col_description pg_get_userbyid pg_get_expr pg_get_constraintdef
		pg_get_indexdef pg_get_viewdef pg_get_functiondef pg_table_is_visible pg_relation_size pg_table_size
		pg_indexes_size pg_total_relation_size pg_database_size pg_size_pretty to_regclass
	`)
)

func plainRead(sql string) bool {
	tokens, ok := sqlTokens(sql)
	for ok && len(tokens) > 0 {
		end := slices.Index(tokens, ";")
		if end < 0 {
			end = len(tokens)
		}
		ok = readStatement(tokens[:end])
		tokens = tokens[min(end+1, len(tokens)):]
	}
	return ok
}

func sqlTokens(sql string) ([]string, bool) {
	var tokens []string
	for rest := sql; rest != ""; {
		n := 1
		word, tag := sqlWord.FindString(rest), sqlDollar.FindString(rest)
		switch {
		case strings.IndexByte(" \t\n\r\f\v", rest[0]) >= 0:
		case strings.HasPrefix(rest, "--"):
			if n = strings.IndexAny(rest, "\r\n"); n < 0 {
				return tokens, true
			}
		case strings.HasPrefix(rest, "/*"):
			n = 2
			for depth := 1; depth > 0; {
				switch {
				case n >= len(rest):
					return nil, false
				case strings.HasPrefix(rest[n:], "/*"):
					depth, n = depth+1, n+2
				case strings.HasPrefix(rest[n:], "*/"):
					depth, n = depth-1, n+2
				default:
					n++
				}
			}
		case rest[0] == '\'' || rest[0] == '"':
			for {
				end := strings.IndexByte(rest[n:], rest[0])
				if end < 0 {
					return nil, false
				}
				n += end + 1
				if n == len(rest) || rest[n] != rest[0] {
					break
				}
				n++
			}
			// E'' strings and standard_conforming_strings=off let a backslash escape the closing quote.
			if rest[0] == '\'' && strings.Contains(rest[1:n], `\'`) {
				return nil, false
			}
			tokens = append(tokens, rest[:n])
		case rest[0] == '$' && len(rest) > 1 && '0' <= rest[1] && rest[1] <= '9':
			tokens = append(tokens, "$")
		case rest[0] == '$':
			end := strings.Index(rest[len(tag):], tag)
			if tag == "" || end < 0 {
				return nil, false
			}
			n = 2*len(tag) + end
			tokens = append(tokens, "''")
		case word != "":
			n = len(word)
			if !strings.ContainsFunc(word, func(r rune) bool { return r > unicode.MaxASCII }) {
				word = strings.ToLower(word)
			}
			tokens = append(tokens, word)
		default:
			tokens = append(tokens, rest[:1])
		}
		rest = rest[n:]
	}
	return tokens, true
}

func readStatement(ts []string) bool {
	if len(ts) == 0 {
		return true
	}
	switch ts[0] {
	case "select", "values", "table", "with", "(":
		for i, t := range ts {
			if slices.Contains(sqlWrites, t) || t == "for" && i+1 < len(ts) && (ts[i+1] == "share" || ts[i+1] == "key") {
				return false
			}
		}
		return readCalls(ts)
	case "explain":
		options := ts[:0]
		if slices.Index(ts, "(") == 1 {
			options = ts[:max(slices.Index(ts, ")"), 0)]
		}
		return !slices.Contains(ts, "analyze") && !slices.Contains(ts, "analyse") && !slices.ContainsFunc(options, quoted) && readCalls(ts)
	case "declare":
		i := slices.Index(ts, "for")
		return i > 0 && slices.Contains(ts[:i], "cursor") && readStatement(ts[i+1:])
	case "copy":
		depth := 0
		for i, t := range ts {
			switch {
			case t == "(":
				depth++
			case t == ")":
				depth--
			case depth == 0 && (t == "to" || t == "from"):
				return t == "to" && i+1 < len(ts) && ts[i+1] == "stdout" && (ts[1] != "(" || ts[i-1] == ")" && readStatement(ts[2:i-1]))
			}
		}
		return false
	case "set", "reset":
		name := ts[1:]
		if i := slices.IndexFunc(name, func(t string) bool { return t == "=" || t == "to" }); i >= 0 {
			name = name[:i]
		}
		return !slices.ContainsFunc(name, func(t string) bool { return quoted(t) || t == "write" || slices.Contains(sqlGuards, t) })
	case "begin", "start":
		return !slices.Contains(ts, "write")
	case "commit", "rollback":
		return !slices.Contains(ts, "prepared")
	case "end", "abort", "savepoint", "release", "fetch", "move", "close", "show", "listen", "unlisten":
		return true
	}
	return false
}

func readCalls(ts []string) bool {
	for i := 1; i < len(ts); i++ {
		name := ts[i-1]
		switch {
		case ts[i] != "(" || !quoted(name) && (!sqlWord.MatchString(name) || unicode.IsDigit(rune(name[0]))):
		// Type modifiers and alias or CTE column lists.
		case i > 2 && ts[i-2] == ":" && ts[i-3] == ":", i > 1 && slices.Contains(sqlNames, ts[i-2]):
		case i > 2 && ts[i-2] == "." && ts[i-3] != "pg_catalog", !slices.Contains(sqlCalls, name):
			return false
		}
	}
	return true
}

func quoted(token string) bool { return strings.HasPrefix(token, `"`) }
