# Manual connector tests

Run these from the repository root. They use the real connector and shipped JSON,
not a full Monitor policy engine or sandbox. They are manually invoked development
tests, not CI or automatic upstream monitoring. Go is required; Slack additionally
needs a Python venv with `slack_sdk==3.38.0`.

```sh
# Public Grafana health read; no credentials required if the endpoint permits it.
python dev/manual_tests/test.py grafana --url https://grafana.example.com
# Also verify authenticated search using a read-only service-account API key.
python dev/manual_tests/test.py grafana --env-file /private/path/to/.env
# Receive/acknowledge Slack events and verify delivery on a fresh session.
python dev/manual_tests/test.py slack --env-file /private/path/to/.env --duration 180 --reconnect-after 60
```

The explicitly supplied private `0600` file accepts these literal settings:

- Slack: `SLACK_BOT_TOKEN` for Web API calls and `SLACK_APP_TOKEN` for Socket Mode,
  from the same dedicated test app. Enable Socket Mode and give the app-level
  `xapp-` token `connections:write`; do not reuse the bot token for that connection.
- Grafana: `GRAFANA_URL` (HTTPS origin, no `/api` suffix), optional `GRAFANA_API_KEY`.

Without a Grafana key, search is skipped: health success alone does not establish
access to dashboards. With a key, only health and a search limited to one result
are tested; no records are printed or changed. Use a read-only service account.

For Slack, mention the app before and after reconnect. `--post-test --channel ID`
explicitly permits one labelled post. Otherwise the HTTP side permits only exact
`auth.test` operations. Concurrent Socket Mode clients can take events from each
other, so do not use a production bot. `slack-fixture.json` contains synthetic SDK
examples; `python dev/manual_tests/test.py slack --capture` inspects them offline.
See [Slack's protocol](https://docs.slack.dev/apis/events-api/using-socket-mode)
for app setup and session/reconnection behavior.

Receiving a test mention does not prove channel filtering: incoming events are
opaque to Monitor, which neither filters them by channel nor correlates acknowledgement
IDs with received envelopes. In Monitor policy, acknowledgements count as sends
because they can contain interactive responses; read-only access cannot acknowledge.
These tests do not verify the full event schema or deployed policy. Supported hosts,
paths, encodings and approval selectors are defined in
[`slack_socket_mode.json`](../../presets/slack_socket_mode.json), not enumerated here.

`slack.py` and `grafana.py` contain the service scenarios. `test.py` owns the
shared CLI and process lifecycle; `common.py` handles private settings and safe
errors. The shared `main.go` supplies authenticated loopback proxies, temporary
TLS and credential injection. Tokens pass privately to it over stdin; client subprocesses
receive placeholders only. No full URLs, token values or event contents are
printed. Never commit credential files. See `--help` for options.
