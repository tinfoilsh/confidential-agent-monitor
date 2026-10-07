# Browser control

A browser connection runs one Chromium browser with the english-only extension. The agent drives it through the monitor. The owner can watch it in the app, pause the agent, use the browser, and return control. The browser keeps the same session, tabs and pages through the handoff.

## Setup

1. Start the monitor with `-extension <path to english-only>`. Without this flag, the monitor has no `browser` kind. `dev/setup` passes `../english-only` by default.
2. In the app, open **Add account → Protocol → Browser**, then name the account.
3. Give the agent access to the account on its agent page.
4. The browser reaches only the networks the monitor allows. Public sites need no change. For a local page, add its address under **Settings → Networks**.

Each browser connection has its own temporary Chromium profile. Cookies and local storage are not shared between connections. The profile is lost when the connection stops or restarts, for example after a change to its settings.

## Take over and return control

Open the account's page. The **Browser** card shows the active tab and polls about once a second.

1. Select **Pause and take control**.
   - The agent's command in progress ends, and a page load that the agent started stops.
   - The status changes to "You have control. The agent is paused."
2. Use the browser:
   - click, scroll and type in the page;
   - type text in the box under the page, or use the key buttons;
   - type a URL in the address field, or select **Back**;
   - select a tab button to change tabs.

   A popup that you open appears as a tab, but the card does not switch to it until you select it.
3. If the page opens a dialog, the card cannot show the page. Select **Accept** or **Dismiss** under **Page dialog**.
4. Select **Return to agent**. The agent must take a new snapshot before it can click or type again.

Each click or key that you send applies only to the page that the card showed when you sent it. If the page changed first, for example after a reload, a redirect or a return of control, the monitor refuses the input. The card then shows the new page.

To try a sign-in handoff, use the local test pages. See [connector/browser/testdata/site/README.md](../connector/browser/testdata/site/README.md). The test pages are dev and test data only, and they are not part of the monitor binary.

## Agent API

The agent reaches the connection as `<account>.monitor`, for example `http://browser.monitor/snapshot`. The policy checks each command, as before.

| Command | JSON request fields | Notes |
|---|---|---|
| `POST /navigate` | `url` | `http` or `https` only. |
| `GET /snapshot` | | One line for each element, such as `e42.3 button "Sign in"`. |
| `GET /text`, `GET /screenshot` | | Censored page content. These do not authorize input. |
| `POST /click` | `ref` | |
| `POST /type` | `ref`, `text` | Focuses the ref, then presses the keys. The `ref` is now required. |
| `POST /fill` | `ref`, `text` | Replaces the field's text. A credential placeholder is allowed only in its form slot. |

A ref names a node and a generation: `e42.3` is node 42 of generation 3. A generation is one document in one tab within one period of control. A ref is valid only while that same document shows in the active tab, and only if control has not passed since the snapshot.

### 409 Conflict

The monitor answers 409 in these cases:

- The owner has paused the agent. Every agent command is refused until the owner returns control.
- The owner took control after the request arrived, even if the request was waiting for an approval. The request does not run after control returns.
- The ref is from another document. This happens after a reload, a navigation, a late redirect, a switch to another tab at the same URL, or a popup that became active.
- A pause interrupted the command. The command may have reached the page.

After a 409, take a new snapshot and decide again. The monitor does not repeat any command.

A click or key that starts a navigation, closes its tab or opens a dialog counts as delivered and returns 200. The monitor does not close the dialog; the owner accepts or dismisses it.

When the page opens a popup or a new tab, that tab becomes active at the agent's next command. When the active tab closes, the most recently used open tab becomes active.

## Owner API

The owner API is `GET` or `POST /connections/{name}/browser` on the owner address, with `Authorization: Bearer <owner key>`. The agent's connection does not serve it. `GET` returns the current view. `POST` takes one action.

The view has these fields:

- `owner` (bool): reports who holds control after the capture attempt, including when capture fails.
- `tabs`: a list of `{id, url, title, active}`.
- `frame`: a token for the document that the screenshot shows.
- `url` and `screenshot` (base64 JPEG).
- `error`: set instead of `frame`, `url` and `screenshot` when the capture failed.

The actions:

- `pause` and `resume`.
- `tab` with `tab`, and `dialog` with `accept`. These need the owner to have control.
- `click` with `x` and `y`, `scroll` with `x`, `y` and `dy`, `type` with `text`, `key` with a DOM key name, `navigate` with `url`, and `back`. Each needs the owner to have control and the `frame` token of the view that the input is aimed at. A token from another document, tab or period of control is refused with 409.

## Limits

- The owner sees the censored page. Hover-to-reveal is not forwarded.
- The agent can read fields that the owner filled after the owner returns control. A private login handoff is not built yet.
- Sessions exist only while the connection runs. Nothing is saved when it stops.
- There is no support for file pickers, uploads or downloads.
- Only the local test pages are tested. External sites, accounts and CAPTCHA are not validated.
- A pause cannot undo a request that the browser already sent.
