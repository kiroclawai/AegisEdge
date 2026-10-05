package main

import (
	"regexp"
	"testing"
)

var semverRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
	if !semverRe.MatchString(Version) {
		t.Errorf("Version %q is not semver-shaped", Version)
	}
}
