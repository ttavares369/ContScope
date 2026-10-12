package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestServerTagsValidationAndStorage(t *testing.T) {
	old := storePath
	storePath = filepath.Join(t.TempDir(), "servers.json")
	defer func() { storePath = old }()
	tags := []ServerTag{{ID: "company-a", Name: "Company A", Color: "blue"}, {ID: "aws", Name: "AWS", Color: "orange"}}
	if err := saveTags(tags); err != nil {
		t.Fatal(err)
	}
	got, err := readTags()
	if err != nil || len(got) != 2 {
		t.Fatalf("cannot load tags: %v", err)
	}
	if !validTag(ServerTag{Name: "Azure", Color: "teal"}) {
		t.Fatal("valid tag rejected")
	}
	for _, bad := range []ServerTag{{Name: "Bad", Color: "not-a-color"}, {Name: strings.Repeat("x", 49), Color: "blue"}, {Name: "new\nline", Color: "green"}} {
		if validTag(bad) {
			t.Fatalf("invalid tag accepted: %+v", bad)
		}
	}
	if uniqueTagName(tags, ServerTag{Name: "company a"}) {
		t.Fatal("case-insensitive duplicate accepted")
	}
	if !validTagIDs([]string{"company-a", "aws"}, tags) {
		t.Fatal("multiple tags should be valid")
	}
	if validTagIDs([]string{"aws", "aws"}, tags) || validTagIDs([]string{"missing"}, tags) {
		t.Fatal("invalid tag IDs accepted")
	}
}
