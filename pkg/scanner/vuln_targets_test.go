package scanner

import (
    "os"
    "path/filepath"
    "sort"
    "testing"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
)

func TestCollectTargetsMergesCrawledSurface(t *testing.T) {
    dir := t.TempDir()
    domain := "example.com"
    webDir := filepath.Join(dir, domain, "web")
    epDir := filepath.Join(dir, domain, "endpoints")
    os.MkdirAll(webDir, 0755)
    os.MkdirAll(epDir, 0755)

    // Root hosts from httpx.
    os.WriteFile(filepath.Join(webDir, "live_urls.txt"), []byte(
        "https://example.com\nhttps://app.example.com\n"), 0644)

    // Crawled deep surface from the endpoints module — including a deep path, a
    // parameterized URL, an out-of-scope CDN asset, and a duplicate of a root.
    os.WriteFile(filepath.Join(epDir, "all_endpoints.txt"), []byte(
        "https://example.com/admin/login\n"+
            "https://app.example.com/api/v1/users?id=1\n"+
            "https://cdn.thirdparty.net/lib.js\n"+
            "https://example.com/\n"), 0644)

    m := &VulnModule{cfg: &config.Config{OutputDir: dir}, log: logger.New(dir, false)}
    targets := m.collectTargets(domain)

    got := map[string]bool{}
    for _, tg := range targets {
        got[tg] = true
    }

    // Deep crawled path must be scanned now (the whole point of the fix).
    if !got["https://example.com/admin/login"] {
        t.Error("deep crawled endpoint was not fed into the scan surface")
    }
    // Parameterized URL retained.
    if !got["https://app.example.com/api/v1/users?id=1"] {
        t.Error("parameterized endpoint missing from scan surface")
    }
    // Out-of-scope third-party host dropped.
    if got["https://cdn.thirdparty.net/lib.js"] {
        t.Error("out-of-scope host leaked into scan surface")
    }
    // Root dedup: only one https://example.com entry.
    n := 0
    for _, tg := range targets {
        if tg == "https://example.com" {
            n++
        }
    }
    if n != 1 {
        t.Errorf("root host not deduplicated: appeared %d times", n)
    }

    // Origins collapse to the two in-scope hosts.
    origins := uniqueOrigins(targets)
    sort.Strings(origins)
    if len(origins) != 2 {
        t.Errorf("uniqueOrigins = %v, want 2 in-scope origins", origins)
    }

    // Only the parameterized URL is selected for DAST fuzzing.
    params := paramURLs(targets)
    if len(params) != 1 || params[0] != "https://app.example.com/api/v1/users?id=1" {
        t.Errorf("paramURLs = %v, want the single parameterized URL", params)
    }
}
