// Package ui embeds the built Monitor UI.
package ui

import "embed"

//go:generate bun install --frozen-lockfile
//go:generate bun run build

// Files holds only the built UI, which also serves the attested SSH panel.
//
//go:embed dist
var Files embed.FS
