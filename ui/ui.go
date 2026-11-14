// Package ui embeds the built Monitor UI.
package ui

import (
	"embed"
	"io/fs"
)

//go:generate bun install --frozen-lockfile
//go:generate bun run build

//go:embed dist
var dist embed.FS

// Files holds only the built UI, which also serves the attested SSH panel.
var Files, _ = fs.Sub(dist, "dist")
