package main

// Version is the release version reported in logs and /api/status.
// Overridden at build time via:
//
//	go build -ldflags="-X main.Version=vX.Y.Z" .
//
// The default matches the latest git tag.
var Version = "v1.0.0-beta.1"
