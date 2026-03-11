package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/H3llKa1ser/recon-storm/pkg/config"
	"github.com/H3llKa1ser/recon-storm/pkg/logger"
	"github.com/H3llKa1ser/recon-storm/pkg/state"
)

type WebModule struct {
	cfg   *config.Config
	state *state.Manager
	log   *logger.Logger
}

func NewWebModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *WebModule {
	return &WebModule{cfg: cfg, state: sm, log: log}
}

func (m *WebModule) Name() string { return "web" }

func (m *WebModule) Run(ctx context.Context, domain string) error {
	outDir := filepath.Join(m.cfg.OutputDir, domain, "web")
	os.MkdirAll(outDir, 0755)

	// Prefer host:port pairs from port scan, fall back to all_subdomains.
	// Check content, not just existence — upstream modules may create empty files.
	inputFile := filepath.Join(m.cfg.OutputDir, domain, "ports", "host_ports.txt")
	if lines := readLines(inputFile); len(lines) == 0 {
		inputFile = filepath.Join(m.cfg.OutputDir, domain, "subdomains", "all_subdomains.txt")
	}

	// Final check
	if _, ok := readLinesOrWarn(inputFile, m.log, "web"); !ok {
		return nil
	}

	// ── httpx — Web Server Probing & Tech Detection ──
	httpxPath, isGoHttpx := findGoHttpx()
	if isGoHttpx {
		m.log.Info("  Running httpx web probe...")

		httpxJSON := filepath.Join(outDir, "httpx_results.json")

		// Use JSON lines output mode (-j) with a single -o flag.
		// httpx does not support dual output (-o for text AND -output for JSON)
		// in the same invocation — this causes one to be empty.
		cmd := exec.CommandContext(ctx, httpxPath,
			"-l", inputFile,
			"-sc",
			"-cl",
			"-ct",
			"-title",
			"-server",
			"-td",
			"-cdn",
			"-wc",
			"-lc",
			"-rt",
			"-favicon",
			"-jarm",
			"-threads", fmt.Sprintf("%d", m.cfg.Threads),
			"-follow-redirects",
			"-silent",
			"-j",
			"-o", httpxJSON,
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			m.log.Warn("  httpx error: %v — %s", err, string(output))
		}

		// Parse JSON results and extract live URLs
		urls := m.parseHttpxResults(httpxJSON, domain)

		liveURLFile := filepath.Join(outDir, "live_urls.txt")
		writeLines(liveURLFile, urls)

		// Also write a human-readable text version
		httpxOut := filepath.Join(outDir, "httpx_results.txt")
		writeLines(httpxOut, urls)

		m.log.Success("  httpx found %d live web servers", len(urls))
	} else if httpxPath != "" {
		// httpx binary found but it's the Python version, not ProjectDiscovery's Go version
		m.log.Warn("  Found httpx at %s but it appears to be the Python version, not ProjectDiscovery's Go httpx", httpxPath)
		m.log.Warn("  Install the correct one: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
	} else {
		m.log.Warn("  httpx not found — install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
	}

	return nil
}

// findGoHttpx locates the httpx binary and verifies it's ProjectDiscovery's Go version
// (not Python's httpx package which also installs an `httpx` binary).
// Returns (path, true) if Go httpx found, (path, false) if wrong httpx, ("", false) if missing.
func findGoHttpx() (string, bool) {
	path, err := exec.LookPath("httpx")
	if err != nil {
		return "", false
	}

	// Run "httpx -version" and check the output
	out, err := exec.Command(path, "-version").CombinedOutput()
	if err != nil {
		// Some versions of Go httpx may return non-zero on -version but still print version info
		// Fall through and check the output anyway
	}

	outStr := strings.ToLower(string(out))
	// ProjectDiscovery's httpx contains "projectdiscovery" in its version output
	if strings.Contains(outStr, "projectdiscovery") || strings.Contains(outStr, "pd") {
		return path, true
	}

	// Also check for common Go httpx version patterns like "httpx v1.x.x"
	// Python httpx prints something different (typically "httpx, version 0.x.x")
	if strings.Contains(outStr, "current") || strings.Contains(outStr, "/cmd/httpx") {
		return path, true
	}

	return path, false
}

// parseHttpxResults parses the JSONL output from httpx and returns discovered URLs
func (m *WebModule) parseHttpxResults(jsonFile string, domain string) []string {
	lines := readLines(jsonFile)
	var urls []string

	for _, line := range lines {
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		url, _ := result["url"].(string)
		if url == "" {
			continue
		}
		urls = append(urls, url)

		statusCode := ""
		if sc, ok := result["status_code"].(float64); ok {
			statusCode = fmt.Sprintf("%.0f", sc)
		}
		title, _ := result["title"].(string)
		tech := ""
		if techs, ok := result["tech"].([]interface{}); ok {
			techStrs := make([]string, len(techs))
			for i, t := range techs {
				techStrs[i] = fmt.Sprintf("%v", t)
			}
			tech = fmt.Sprintf("%v", techStrs)
		}

		m.state.AddFinding(state.Finding{
			Type:     "web_server",
			Value:    url,
			Source:   "httpx",
			Domain:   domain,
			Severity: "info",
			Metadata: map[string]string{
				"status_code": statusCode,
				"title":       title,
				"tech":        tech,
			},
		})
	}

	return urls
}
