package ui

import (
	"embed"
	"io/fs"
)

//go:generate bun install --frozen-lockfile
//go:generate bun run build

//go:embed dist
var dist embed.FS

var Files, _ = fs.Sub(dist, "dist")
