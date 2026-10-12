# Monitor interfaces

Monitor serves one app with two views:

- `/app/` uses the Tinfoil dashboard layout.
- `/app/fun_ui.html` keeps the original UI.

Both load `app/monitor.js`, use `app/owner.js` for owner actions, and share the
owner login, either an owner key/passphrase or a CLI SSH session. The sidebar
links switch views in the same tab. No dashboard
server, Node runtime, CDN, or frontend build is needed to run Monitor.

`app/dashboard.js` renders the management navigation, collection pages, and
activity filters. Detailed controls use the same renderers and event handlers
in both views. Add owner behavior to `owner.js`, and wire the controls in
`monitor.js` so both views receive it.

## Dashboard design source

The CSS and assets follow the adjacent `websites-monorepo` checkout:

- `packages/tailwind-preset/src/index.ts`: colors and Aeonik Fono typography.
- `apps/dashboard/src/styles/theme-colors.ts` and `tailwind.config.ts`: dark
  colors and application corner radii.
- `packages/ui/src/sidebar.tsx` and `sidebar-nav.tsx`: 224px dark sidebar,
  navigation spacing, and active states.
- `packages/ui/src/button.tsx`: button dimensions, colors, and corner radius.
- `packages/ui/src/textures/`: grid and paper grain.
- `apps/dashboard/src/components/dashboard-{page,header,content}.tsx`: page
  padding, sticky header, and scroll container.
- `apps/dashboard/src/app/components/monitor/`: activity summaries, request
  rows, status badges, filters, and collection pages.
- `apps/dashboard/src/app/fonts/` and `public/brand-assets/`: bundled fonts and
  Tinfoil logo.

The management UI supports system, light, and dark themes. Its theme preference
is local to the browser. The original UI still follows the system color scheme.

## Checks

```sh
node --test app_test.mjs approval_ui_test.mjs dashboard_test.mjs owner_test.mjs
go test ./...
```

With `dev/setup`, open `http://127.0.0.1:8080/app/` and enter `.dev/owner.key`.
UI edits appear on reload. Production and owner SSH sessions use the embedded
assets and require a rebuild after editing them.
