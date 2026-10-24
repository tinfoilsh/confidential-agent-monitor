# Monitor performance investigation

Measured on October 14, 2026 against upstream
`82d2482b5a831d46c86934d0223bd9e319ed304e`. The physical checkout was
`features/muse-at-home/monitor`, initially clean and equal to fetched
`origin/main`. Work is on `perf/monitor-latency`. The separate local `main`
checkout was not the baseline. This change adds a harness and measurements,
fixes the Anthropic hello preset, and reduces UI polling work and traffic.
The fixes have not been deployed; no deployed policy was edited.

## Fixes and before/after results

Production changes:

- Added `hello.get` for exact `GET /api/hello`, with the existing `hello.read`
  action and read effect. The HEAD operation retains its ID and definition.
  Account permissions still apply; unrelated methods remain unknown.
- Activity uses `GET /requests?summary`: bounded titles and request metadata,
  without bodies, parameters, grants, or policy diffs. Opening a request loads
  its full audit record through authenticated `GET /requests/{id}`. Existing
  consumers of `GET /requests` and the default SDK `read()` keep the full format.
- Snapshot, compact-history, and individual-record reads support authenticated
  conditional GETs. Unchanged responses return 304 with no JSON body. The owner
  client keeps at most four parsed responses in memory, scoped to its credential,
  and clears them on writes. Validation still occurs after authentication and
  the owner SSH generation acknowledgement. Large JSON responses support gzip.
- The UI shares outstanding refreshes, skips cloning and rendering unchanged
  state, and clones only when applying optimistic edits. Pending requests still
  update their countdowns. Full audit payloads are loaded only for the selected
  request; rule-saving and operation drafting continue using the full record.

The same 66-scenario matrix was run sequentially against a detached upstream
checkout and the working tree, on two CPUs with a 1536 MiB Go soft limit. Each
synthetic request contains 256 KiB of message text. The new summary query is
ignored by upstream, so the comparison measures the old UI's full-history
response against the new compact representation.

| Case | Before | After |
| --- | ---: | ---: |
| Activity, 25 records | 13.1 MB / 10.4 ms | 10.4 KB / 0.067 ms |
| Activity, 100 records | 52.6 MB / 35.4 ms | 41.5 KB / 0.233 ms |
| Activity, 1,000 records | 525.5 MB / 1,445 ms | 414.9 KB / 2.93 ms |
| Unchanged activity, 1,000 records | 525.5 MB / 1,453 ms | 0 B / 2.87 ms |
| Allocated per 1,000-record activity poll | 2.74 GB | 0.61 MB |
| Unchanged snapshot with 600 KB connector details | 602.3 KB | 0 B |
| Changed snapshot with those details, gzip requested* | 602.3 KB | 2.44 KB |

Sizes are response-body bytes, excluding HTTP/SSH headers. Times are local
handler p50, not deployed network latency. Compact history sizes above are
uncompressed; browsers also request compression. The full legacy history
export deliberately avoids hashing hundreds of MB for validators.

\* The connector fixture contains repetitive synthetic data, so its compression
ratio is not a prediction for production MCP schemas/icons. Compression adds
about 3 ms to this local response; conditional snapshot encoding/hashing costs
about 2 ms. The initial/changed data trades a little CPU for much less traffic.

Tests and evidence:

- All 66 performance scenarios passed, including the real bubblewrap worker.
  [Before](network-before.json) and [after](network-after.json) contain complete
  results, metadata, allocation counts and recognition outcomes. The final
  harness hash differs because additional hello-forwarding checks were added;
  the measured scenario definitions and settings are unchanged.
- `TestOwnerPolling`, `TestHelloRecognition`, and `TestHelloForwarding` passed
  with the parent race detector. GET and HEAD hello reached a local HTTPS
  provider through real SSH/TLS in both in-process and isolated-worker modes,
  with a two-second client deadline and no owner approval.
- `node dev/owner-checks.mjs` verifies both owner transports, conditional reads,
  mutation invalidation, credential errors, generation rollback rejection,
  individual record lookup, and operation against an older server without ETags.
- The [browser checks](ui-network.json) passed visibility, coalescing, decisions
  during delayed reads, error recovery, on-demand full request facts, and empty
  unchanged responses. Go compilation/vet, JS syntax and patch checks passed.

The retained audit facts themselves are unchanged. Large histories can still
consume substantial server memory, and explicitly exporting full history is
still expensive. Snapshots are still encoded to compute their validator. The
new response sizes and hello behavior have not yet been measured on deployed
`sb2`/`m2`; the deployment measurements below describe the original version.

## Baseline findings

### The reproduced Claude connection timeout is an approval wait

The deployed path is `sb2` → sing-box TUN/fake DNS → an SSH SOCKS tunnel →
`10.254.0.1:22` → Monitor `m2` → isolated HTTP worker → broker → Anthropic.
`m2` was verified through the owner CLI and provisioned with 2 CPUs / 2048 MiB.
Its deployed v0.1.8 configuration explicitly enables `-connector-workers`;
the image digest and CVM version are in the deployed measurements artifact.
The intercepted certificate issuer was `monitor dev CA`; this is the certificate
name in the deployed implementation, not evidence that the connection was local.

| Credential-free request from sb2 | TLS complete | Response / total time |
| --- | ---: | --- |
| `HEAD /api/hello` | 130–132 ms | 200 in 227–230 ms |
| `GET /api/hello` | 130–135 ms | No response; both probes timed out at 11 seconds |
| `GET /v1/models`, correct Anthropic-Version | 130–132 ms | Expected 401 in 244–259 ms |

The owner audit contained Claude's unrecognized `GET /api/hello` calls with
`requirements: [ask]`, including pending, expired, and manually approved calls.
The original preset recognized only **HEAD** at that path. The policy evaluation takes
less than a millisecond locally, then `monitor.await` permits a **120 second**
approval wait. Claude reports its own 10 second connection timeout first.
Unrecognized telemetry (`POST /api/event_logging/v2/batch`) was also waiting.

Requests without the required version header can similarly become unknown;
probing `/v1/models` without it is not a useful upstream availability check.
The probe harness sends the header and does not send an API key.

The fix adds the exact GET hello operation alongside the existing HEAD
operation. Telemetry remains subject to policy; unknown requests are not
broadly allowed. Keep approval latency distinct from transport latency.
The local inference fixture explicitly allows
`messages.generate`, since its `pay` effect otherwise requests approval even
at account level `allow`.

Relevant sources: [Anthropic preset](../../presets/anthropic.json),
[request matching](../../connector/web/preset.go), [gate](../../internal/monitor/monitor.go)/[await](../../internal/approval/approval.go).

### The original owner UI repeatedly transferred large unchanged payloads

| Deployed owner request | Response size | Headers received | Fully received |
| --- | ---: | ---: | ---: |
| Health | 16 B | 296 ms | 296 ms |
| First snapshot | 957,521 B | 304 ms | 5.39 s |
| Snapshot with catalog cache | 592,933 B | 310 ms | 3.84 s |
| Request history (80 records) | 387,498 B | 295 ms | 2.57 s |

589,409 bytes of the cached snapshot were connection status. GitHub MCP's
blocked-tool details contain both a textual diff and the full current pin,
including schemas and icons. Those details do not benefit from the preset
catalog cache. The shared owner client requests a snapshot and full history
on every read; the UI starts a read every five seconds.

Most elapsed time in these deployed samples was after headers, during payload
transfer. This does not establish whether a particular host/network component
limits throughput. It does establish that the current response size is expensive
on the actual owner connection, even with fewer than 100 small records.

Conditional reads now avoid transferring unchanged connector data. Activity
uses compact summaries and loads full audit details on demand. The existing
catalog negotiation remains in place.

Relevant sources: [MCP details](../../connector/mcp/mcp.go),
[owner snapshots/history](../../internal/monitor/owner.go), [owner client](../../app/owner.js),
[poll loop](../../app/monitor.js).

### Slow polls can hide approvals indefinitely

The CLI window's deployed `app/monitor.js` was retrieved read-only from `m2`
and matched upstream `82d2482` byte for byte. Its `refresh()` incremented
`pollVersion` when a read **started**, then discarded a response if a newer
read had started. With a five-second interval and consistently slower reads,
every response was discarded. The browser could keep showing zero approvals
while the server repeatedly returned pending requests.

Three concurrent snapshot/history reads through the deployed CLI connection
took 2.73, **7.18**, and **6.30 seconds**. The two cached-catalog reads transferred
592,933 snapshot bytes plus 442,963 history bytes each. The condition needed
to trigger the UI bug therefore exists on the actual owner connection. This
does not reconstruct the user's earlier browser state.

The browser harness serves the real app against a local synthetic owner API.
It loads an empty activity page, inserts a pending `GET /api/hello`, then adds
6.5 seconds to every API response. Before the fix the server completes pending
responses but the approval never appears during the observation window. With
the fix it appears after the first delayed read. Only one snapshot/history
pair runs at a time, including when Refresh is clicked repeatedly.

| Browser case | Approval visible | Peak concurrent API GETs |
| --- | ---: | ---: |
| Upstream, 6.5 s responses | Still hidden after 26.1 s | 6 |
| Fixed, 6.5 s responses | 11.1 s | 2 |
| Fixed, 12 s responses | 16.6 s | 2 |

Visibility time includes the wait for the next scheduled poll. The upstream
case completed 14 delayed API responses (snapshot and history combined) while
the page continued to report zero pending requests.

Production change: `refresh()` now shares its outstanding promise. A completed
read is applied unless an edit or credential change invalidates it; completed
edits trigger a fresh read, and failures release the promise for retry. The
browser checks also approve a synthetic request while an older snapshot is
in flight, verify the decision survives, and exercise recovery from HTTP 503.

The initial polling fix addressed lost UI updates. The subsequent compact
reads, compression and preset fix are measured above. Waiting for an approval
can still exceed a caller's deadline when policy requires one.
The original user's browser session was not instrumented, and the UI fix has
not been deployed. Numerical evidence is in [UI results](ui.json).

### Full request history creates substantial memory and CPU pressure

Local synthetic requests used 256 KiB message text, the shipped Anthropic
operation, and real authorization/audit encoding. Each request body appears in
both facts parameters and HTTP details. The immutable encoding is also retained.
The 1,000-record limit is a count limit, not a byte limit.

| Records | History response | Poll p50 | Poll p95 | Parent live heap after GC* |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 2 B | 0.003 ms | 0.030 ms | 75 MB |
| 25 | 13.1 MB | 8.2 ms | 19.1 ms | 102 MB |
| 100 | 52.6 MB | 37.0 ms | 75.7 ms | 182 MB |
| 500 | 262.8 MB | 201 ms | 570 ms | 606 MB |
| 1,000 | 525.5 MB | 1,423 ms | 1,538 ms | 1,136 MB |

\* Heap values are the subsequent admission scenario, after temporary encoding
buffers have been collected. This includes the fixture and the parent Go
runtime, not an isolated audit allocation estimate. MB here is decimal.

At 1,000 records the poll allocated **3.29 GB per operation** in the recorded
run. During concurrent polling an admission evaluation reached **179 ms**;
without polling its p95 was **0.30 ms**. CPU profiles are dominated by memory
copying, JSON processing, and GC. Large response allocations can exceed the
soft Go memory limit; the deployment's hard 2 GiB limit is a separate risk.

This is a reproduced scaling failure, not evidence that m2 was holding 1,000
large requests during the observed Claude timeout. Its live history was small.

Fix targets: bound retained audit bytes while preserving pending approvals,
avoid duplicate retained body representations, and stop serializing the entire
history every poll. Keep full facts available for authorization and approval
rechecks; optimizing the audit display must not weaken policy inputs.

Relevant sources: [record retention/evaluation](../../internal/approval/approval.go),
[frozen facts](../../facts/json.go), [owner response encoding](../../internal/monitor/owner.go).

### Worker overhead is measurable, but did not explain the 10 second wait

Local p50 milliseconds, sharing two CPU affinity slots across parent and worker:

| Message text / connection | Direct HTTPS fixture | In-process Monitor | Isolated worker |
| --- | ---: | ---: | ---: |
| Empty / fresh | 0.95 | 2.74 | 3.51 |
| Empty / reused | 0.06 | 0.45 | 0.72 |
| 64 KiB / fresh | 0.98 | 3.47 | 5.01 |
| 64 KiB / reused | 0.11 | 1.02 | 2.01 |
| 512 KiB / fresh | 1.20 | 7.77 | 12.28 |
| 512 KiB / reused | 0.45 | 5.09 | 8.73 |

Fixture initialization through connector readiness took 7.3 ms in-process and
14.7 ms with a worker. These are single startup observations, not startup
percentile estimates. Worker RPC copies parsed requests to the parent; the
additional cost grows with body size. HTTP transports are currently per stream,
so fresh streams also repeat upstream connection/TLS work. In-process policy
evaluation alone grew from 0.23 ms to 2.52 ms at 512 KiB.

Keep sandbox isolation while addressing the confirmed approval and payload
issues first. If transport reuse is subsequently changed, preserve connector
lifetime, destination checks, cancellation, and policy revocation semantics.

Relevant sources: [HTTP serving](../../connector/web/http.go),
[worker RPC](../../internal/worker/protocol.go), [worker launcher](../../internal/worker/local.go).

## Reproduce and compare

Requirements: the repository's Go version, Python 3, and Linux/bubblewrap for
the worker cases. The harness uses temporary synthetic keys, an in-memory blob
store, a local HTTPS provider, actual SSH/TLS verification, the real policy,
credential substitution, and the production bubblewrap launcher. It does not
invoke Claude or bill a model API. No extra Go dependencies are needed.

From the repository root:

```sh
# Small routine run (default history sizes 0,25,100).
dev/perf --output .dev/perf/before

# Make a change, then run the identical scenario matrix.
dev/perf --output .dev/perf/after --compare .dev/perf/before/results.json

# Full growth experiment used for the checked-in baseline.
dev/perf --output .dev/perf/growth --samples 30 --histories 0,25,100,500,1000

# CI can opt into a p95 growth budget (exit 2 for a regression).
dev/perf --output .dev/perf/candidate --compare .dev/perf/before/results.json --fail-regression 50

# Limit work while developing, or when bubblewrap is unavailable.
dev/perf --output .dev/perf/quick --samples 3 --sizes 0,65536 --histories 0,25
dev/perf --output .dev/perf/policy --modes inprocess --scenario 'TestPerformance/(recognition|policy)$'

# Match the new 66-scenario checked-in comparison (15 samples, five histories).
dev/perf --output .dev/perf/network --samples 15 --histories 0,25,100,500,1000 --compare dev/performance/network-after.json

# Verify owner reads and hello forwarding using that run's worker fixture.
MONITOR_PERF_CONFIG="$PWD/.dev/perf/network/config.json" go test -race -tags performance -run 'Test(OwnerPolling|HelloRecognition|HelloForwarding)$' ./internal/monitor
node dev/owner-checks.mjs
```

Output directories must be new. The script writes `results.json`, `metadata.json`,
raw test output, the exact binaries, and CPU/heap/mutex/block profiles. JSON
contains sample counts, p50/p95/max, parent allocations, retained heap, response
bytes, recognition/approval information, and cumulative client trace milestones.
`tls_start` through `tls_done` measures the intercepted TLS handshake;
`connection_ready` includes SSH channel admission. Reused connections are warmed
before sampling. Failures retain partial results without marking them complete.

```sh
go tool pprof -top .dev/perf/growth/harness .dev/perf/growth/cpu.pprof
go tool pprof -top -alloc_space .dev/perf/growth/harness .dev/perf/growth/heap.pprof
go tool pprof -top .dev/perf/growth/harness .dev/perf/growth/mutex.pprof
go tool pprof -http=127.0.0.1:0 .dev/perf/growth/harness .dev/perf/growth/cpu.pprof
```

The Go harness is opt-in with the `performance` build tag. Ordinary production
builds do not include it. It rejects failed requests and verifies that only the
fixture credential reaches the provider. The recognition case cancels an
approval wait after 25 ms so the suite can diagnose the 120 second wait without
actually waiting two minutes. History polling uses a counting writer, exercising
real server JSON allocation without retaining another response copy in the test.

For the deployed path:

```sh
dev/perf-probe --ssh sb2 --output .dev/perf/sb2.json

# Optional owner timings: in another terminal, keep an owner panel running.
# Treat this log as a secret while the panel is open.
umask 077
tinfoil monitor open m2 > .dev/perf/panel.log
# Then include its local session in the probe, without printing/storing the token:
dev/perf-probe --ssh sb2 --owner-panel-log .dev/perf/panel.log --output .dev/perf/sb2-owner.json
```

The deployed probe needs an already configured/pinned SSH alias and `curl` and
Python in the sandbox. It sends credential-free requests and makes no policy
edits. Unknown requests can appear as pending/expired approvals, which is the
behavior being measured. A captured curl timeout is a result, not a harness
failure; inspect `exit_code` and HTTP status. Interrupted runs are incomplete.
Owner artifacts contain timing, sizes, state counts, and recognition booleans;
they exclude session tokens, prompts, schemas, and request bodies.

For approval visibility in the actual browser UI (requires Python 3, PinchTab,
and its configured Chromium browser):

```sh
# Reproduce on the original source; exits 2 for hidden approvals/overlap.
dev/perf-ui --ref 82d2482b5a831d46c86934d0223bd9e319ed304e --output .dev/perf/ui-before.json

# Check the working tree: visibility, overlapping reads, decisions and retries.
dev/perf-ui --output .dev/perf/ui-after.json

# The response delay is configurable; defaults to 6.5 seconds (> poll interval).
dev/perf-ui --delay 12 --output .dev/perf/ui-slower.json
```

Each run creates and closes a dedicated PinchTab session/tab and a loopback
fixture server. The fake session string and all data are synthetic; it does not
open a deployed Monitor, collect browser credentials, or change a real policy.
`--ref` serves all app assets from that exact commit. Results include source
hashes, delay, time until the pending approval is visible, completed responses,
peak simultaneous API requests (two per read), and correctness checks. An
incomplete run is not a passing result. This is an end-to-end regression check,
not a frontend CPU/render profiler; timing includes the next scheduled poll.

## Measurement limits and verification

The two complete 52-scenario runs passed, including real bubblewrap workers;
the repeat used the comparison command. A smaller matrix also passed with
`go test -race -tags performance` (the parent harness was instrumented; the
isolated production worker binary was not). Go vet and Python compilation
passed. The browser regression failed as expected on upstream and passed all
five checks with the fix at both 6.5- and 12-second response delays. JavaScript
syntax and patch whitespace checks passed. Single-run p95 values vary, especially
for startup and the five-sample history measurements. Use repeated runs on a
quiet machine and sufficiently many samples before enforcing a regression
budget. Compare the same settings and scenario sets. Keep failed runs out of
comparisons. The checked-in [baseline](baseline.json) and
[deployed measurements](deployed.json) preserve the numerical evidence.

Linux CPU affinity constrains the harness and its descendants together to
`--cpus` (default 2). `--memory` is the parent's **soft** Go limit (default
1536 MiB); workers keep their production 256 MiB soft limit. No hard memory
cgroup is installed. The in-process fixture includes both client and provider
in the parent, so its CPU/memory figures are not a standalone Monitor service
measurement. Parent profiles and allocations exclude worker runtime allocation;
compare allocations within a mode, not across modes. Metadata records the
checkout SHA, dirty status, diff and harness hashes, runtime, affinity and limits.

Not measured here: paid model inference/streaming, a hard-limit OOM experiment,
S3 label/credential writes, worker CPU profiles, isolated frontend render time, or the
individual CVM/kernel/physical-network hops. Public curl DNS timings on sb2
measure its fake DNS; Monitor's upstream DNS is inside the tunnel. Controlplane
resource metrics returned zero utilization/placeholder totals, so they could
not establish the Monitor VM's CPU or memory usage. The deployed config identity
was recorded separately from the local source SHA; this does not claim the
running image was rebuilt from this checkout.
