#!/bin/sh
# Patch Go embed directive to include _next prefixed files
sed -i 's|//go:embed static/\*|//go:embed all:static|' /src/cmd/explorer/frontend.go
