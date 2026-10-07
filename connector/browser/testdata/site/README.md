# Browser test pages

Local pages for the browser connector's tests and for trying a takeover by hand. They need no accounts, and the credentials are fake.

- `index.html`: a counter, a popup, a link that opens a new tab, a late redirect, a reload, a dialog, and a form.
- `login.html` → `code.html` → `account.html`: a simulated sign-in. User: anything. Password: `fixture`. Code: `123456`.
- `/slow`: answers after 10 seconds, so you can pause during a load.

Serve them:

```sh
go run ./connector/browser/testdata/site -listen 127.0.0.1:8765
```

The monitor's browser reaches only allowed networks. For a dev monitor, add `127.0.0.1/32` under Settings → Networks for as long as you test, then remove it.

The tests start their own copy of these pages, and need Chromium and the english-only extension (`ENGLISH_ONLY`, default `../english-only` next to this repository):

```sh
go test ./connector/browser -race -timeout 300s
```
