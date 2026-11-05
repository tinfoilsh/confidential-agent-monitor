# Manual Slack connector test

This tool runs the Slack SDK through the real connector and shipped presets. It
is for manual development tests, not CI or automatic upstream monitoring. It does
not run the full Monitor policy engine or sandbox enrollment.

From the repository root, with Go and a Python venv containing `slack_sdk==3.38.0`:

```sh
python dev/slack/test.py --env-file /private/path/to/.env --duration 180 --reconnect-after 60
```

The private `0600` file supplies `SLACK_BOT_TOKEN` and `SLACK_APP_TOKEN` from the
same dedicated test app. Without `--env-file`, use the hidden terminal prompts.
Default behavior authenticates, receives events and acknowledges them. Mention
the app before and after reconnection; an event from the original session does
not satisfy the fresh-session delivery check. `--post-test --channel CHANNEL_ID`
explicitly permits one labelled test post. Only the exact `auth.test` operations
are otherwise allowed on the HTTP connection. See `--help` for options.

`main.go` is the local connector helper. `fixture.json` records synthetic SDK wire
shapes; inspect changes manually with `python dev/slack/test.py --capture`. No
credentials or network are needed for capture mode. Neither mode records message
contents or real connection URLs; never commit credential files.
