package main

import (
	"io/fs"
	"strings"
	"testing"
)

func TestBrandAssetsEmbedded(t *testing.T) {
	for _, name := range []string{"assets/contscope-mark.svg", "assets/contscope-logo.svg"} {
		data, err := fs.ReadFile(logoFiles, name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "ContScope") {
			t.Fatalf("missing product title in %s", name)
		}
	}
}
func TestDashboardAssetsAndVersionDefaults(t *testing.T) {
	for _, element := range []string{"openAbout", "/web/app.js", "/web/app.css", "/assets/contscope-mark.svg", "aria-label", "lang=\"en\""} {
		if !strings.Contains(htmlPage, element) {
			t.Fatalf("missing dashboard element: %s", element)
		}
	}
	js, err := fs.ReadFile(webFiles, "web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"/api/about", "/api/tags/assign", "/api/servers/quick", "/api/admin/password", "/api/telegram", "/api/diagnostics", "/api/logs", "/api/support/report"} {
		if !strings.Contains(string(js), endpoint) {
			t.Fatalf("missing API integration: %s", endpoint)
		}
	}
	if version == "" || commit == "" || buildDate == "" {
		t.Fatal("build metadata defaults must be explicit")
	}
}
