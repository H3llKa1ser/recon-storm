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

type VulnModule struct {
	cfg   *config.Config
	state *state.Manager
	log   *logger.Logger
}

func NewVulnModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *VulnModule {
	return &VulnModule{cfg: cfg, state: sm, log: log}
}

func (m *VulnModule) Name() string { return "vulns" }

func (m *VulnModule) Run(ctx context.Context, domain string) error {
	outDir := filepath.Join(m.cfg.OutputDir, domain, "vulns")
	os.MkdirAll(outDir, 0755)

	liveURLsFile := filepath.Join(m.cfg.OutputDir, domain, "web", "live_urls.txt")
	if _, err := os.Stat(liveURLsFile); os.IsNotExist(err) {
		return fmt.Errorf("no live URLs found — run web module first")
	}

	// Empty-input guard
	if _, ok := readLinesOrWarn(liveURLsFile, m.log, "vulns"); !ok {
		return nil
	}

	// ── Nuclei — Template-based Vulnerability Scanner ──
	if _, err := exec.LookPath("nuclei"); err == nil {
		m.log.Info("  Running Nuclei vulnerability scan...")

		nucleiJSON := filepath.Join(outDir, "nuclei_results.json")

		cmd := exec.CommandContext(ctx, "nuclei",
			"-l", liveURLsFile,
			"-severity", "info,low,medium,high,critical",
			"-c", fmt.Sprintf("%d", m.cfg.Threads),
			"-bs", "50",
			"-rl", "150",
			"-timeout", "10",
			"-retries", "2",
			"-j",
			"-o", nucleiJSON,
			"-silent",
			"-stats",
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			m.log.Warn("  Nuclei error: %v — %s", err, string(output))
		}

		m.parseNucleiResults(nucleiJSON, domain)

		results := readLines(nucleiJSON)
		m.log.Success("  Nuclei found %d potential vulnerabilities", len(results))
	} else {
		m.log.Warn("  Nuclei not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	}

	// ── Custom checks ──
	m.runCustomChecks(ctx, domain, outDir, liveURLsFile)

	return nil
}

func (m *VulnModule) parseNucleiResults(jsonFile string, domain string) {
	lines := readLines(jsonFile)
	vulnCount := 0

	for _, line := range lines {
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		templateID, _ := result["template-id"].(string)
		severity := ""
		name := ""
		if info, ok := result["info"].(map[string]interface{}); ok {
			severity, _ = info["severity"].(string)
			name, _ = info["name"].(string)
		}
		matchedAt, _ := result["matched-at"].(string)
		matcherName, _ := result["matcher-name"].(string)

		m.state.AddFinding(state.Finding{
			Type:     "vulnerability",
			Value:    fmt.Sprintf("[%s] %s — %s", severity, name, matchedAt),
			Source:   "nuclei",
			Domain:   domain,
			Severity: severity,
			Metadata: map[string]string{
				"template_id":  templateID,
				"name":         name,
				"matched_at":   matchedAt,
				"matcher_name": matcherName,
			},
		})
		vulnCount++
	}

	m.state.UpdateStats(func(s *state.ScanStats) {
		s.TotalVulns += vulnCount
	})
}

func (m *VulnModule) runCustomChecks(ctx context.Context, domain string, outDir string, urlsFile string) {
	m.log.Info("  Running custom security checks...")

	urls := readLines(urlsFile)
	if len(urls) == 0 {
		m.log.Info("  No URLs for custom checks, skipping")
		return
	}

	sensitivePaths := []string{
		"/.env",
		"/.git/config",
		"/.git/HEAD",
		"/robots.txt",
		"/sitemap.xml",
		"/.well-known/security.txt",
		"/server-status",
		"/server-info",
		"/.DS_Store",
		"/wp-config.php.bak",
		"/crossdomain.xml",
		"/clientaccesspolicy.xml",
		"/security.txt",
		"/.htaccess",
		"/.htpasswd",
		"/web.config",
		"/phpinfo.php",
		"/info.php",
		"/actuator",
		"/actuator/env",
		"/actuator/health",
		"/swagger-ui.html",
		"/swagger/v1/swagger.json",
		"/api-docs",
		"/graphql",
		"/graphiql",
	}

	var checkURLs []string
	for _, base := range urls {
		base = strings.TrimRight(base, "/")
		for _, path := range sensitivePaths {
			checkURLs = append(checkURLs, base+path)
		}
	}

	checkFile := filepath.Join(outDir, "custom_check_urls.txt")
	writeLines(checkFile, checkURLs)

	m.log.Info("  Checking %d sensitive paths across %d hosts...", len(sensitivePaths), len(urls))

	// Use findGoHttpx to ensure we have the right binary
	httpxPath, isGoHttpx := findGoHttpx()
	if isGoHttpx {
		resultFile := filepath.Join(outDir, "sensitive_files.txt")
		cmd := exec.CommandContext(ctx, httpxPath,
			"-l", checkFile,
			"-sc",
			"-cl",
			"-mc", "200,301,302,403",
			"-silent",
			"-threads", fmt.Sprintf("%d", m.cfg.Threads),
			"-o", resultFile,
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			m.log.Debug("  httpx custom checks stderr: %s", string(output))
		}

		results := readLines(resultFile)
		for _, r := range results {
			m.state.AddFinding(state.Finding{
				Type:     "sensitive_file",
				Value:    r,
				Source:   "custom_check",
				Domain:   domain,
				Severity: "medium",
			})
		}
		m.log.Info("  Custom checks found %d interesting responses", len(results))
	} else {
		m.log.Warn("  httpx (ProjectDiscovery) not available — skipping custom sensitive path checks")
	}
}
