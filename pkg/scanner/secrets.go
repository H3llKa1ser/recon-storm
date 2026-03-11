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

type SecretsModule struct {
	cfg   *config.Config
	state *state.Manager
	log   *logger.Logger
}

func NewSecretsModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *SecretsModule {
	return &SecretsModule{cfg: cfg, state: sm, log: log}
}

func (m *SecretsModule) Name() string { return "secrets" }

func (m *SecretsModule) Run(ctx context.Context, domain string) error {
	outDir := filepath.Join(m.cfg.OutputDir, domain, "secrets")
	os.MkdirAll(outDir, 0755)

	// ── ffuf — Directory/File Fuzzing ──
	liveURLsFile := filepath.Join(m.cfg.OutputDir, domain, "web", "live_urls.txt")
	if _, err := os.Stat(liveURLsFile); err == nil {
		if _, err := exec.LookPath("ffuf"); err == nil {
			m.runFfuf(ctx, domain, outDir, liveURLsFile)
		} else {
			m.log.Warn("  ffuf not found — install: go install github.com/ffuf/ffuf/v2@latest")
		}
	} else {
		m.log.Info("  No live URLs file found, skipping ffuf")
	}

	// ── Search JS files for secrets ──
	jsFile := filepath.Join(m.cfg.OutputDir, domain, "endpoints", "js_files.txt")
	if _, err := os.Stat(jsFile); err == nil {
		m.scanJSFiles(ctx, domain, outDir, jsFile)
	} else {
		m.log.Info("  No JS files list found, skipping JS secret scanning")
	}

	return nil
}

// ffufOutput represents the JSON structure ffuf produces
type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	Input      map[string]string `json:"input"`
	Position   int               `json:"position"`
	Status     int               `json:"status"`
	Length     int               `json:"length"`
	Words      int               `json:"words"`
	Lines      int               `json:"lines"`
	ResultFile string            `json:"resultfile"`
	URL        string            `json:"url"`
	Host       string            `json:"host"`
}

func (m *SecretsModule) runFfuf(ctx context.Context, domain string, outDir string, urlsFile string) {
	m.log.Info("  Running ffuf content discovery...")

	urls := readLines(urlsFile)
	if len(urls) == 0 {
		m.log.Warn("  No URLs for ffuf, skipping")
		return
	}

	wordlist := "/usr/share/seclists/Discovery/Web-Content/common.txt"

	fallbacks := []string{
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		for _, fb := range fallbacks {
			if _, err := os.Stat(fb); err == nil {
				wordlist = fb
				break
			}
		}
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		m.log.Warn("  No wordlist found, skipping ffuf. Install seclists: sudo apt-get install -y seclists")
		return
	}

	maxURLs := 20
	if len(urls) < maxURLs {
		maxURLs = len(urls)
	}

	m.log.Info("  Fuzzing %d target URLs with wordlist %s", maxURLs, filepath.Base(wordlist))

	totalFindings := 0
	for i, baseURL := range urls[:maxURLs] {
		m.log.Progress("ffuf", i+1, maxURLs)

		outFile := filepath.Join(outDir, fmt.Sprintf("ffuf_%d.json", i))
		cmd := exec.CommandContext(ctx, "ffuf",
			"-u", baseURL+"/FUZZ",
			"-w", wordlist,
			"-mc", "200,201,204,301,302,307,401,403,405",
			"-ac",
			"-sf",
			"-se",
			"-t", fmt.Sprintf("%d", m.cfg.Threads/2),
			"-rate", "100",
			"-o", outFile,
			"-of", "json",
			"-s",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			m.log.Debug("  ffuf error for %s: %v — %s", baseURL, err, string(output))
		}

		// Parse ffuf JSON output properly
		count := m.parseFfufResults(outFile, domain)
		totalFindings += count
		if count > 0 {
			m.log.Info("  ffuf found %d results for %s", count, baseURL)
		}
	}

	m.state.UpdateStats(func(s *state.ScanStats) {
		s.TotalSecrets += totalFindings
	})

	m.log.Success("  ffuf content discovery complete: %d findings across %d targets", totalFindings, maxURLs)
}

// parseFfufResults parses ffuf's JSON output file and returns the number of results
func (m *SecretsModule) parseFfufResults(jsonFile string, domain string) int {
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return 0
	}

	var output ffufOutput
	if err := json.Unmarshal(data, &output); err != nil {
		// ffuf output might be empty or malformed
		m.log.Debug("  Failed to parse ffuf output %s: %v", filepath.Base(jsonFile), err)
		return 0
	}

	for _, result := range output.Results {
		m.state.AddFinding(state.Finding{
			Type:     "content_discovery",
			Value:    result.URL,
			Source:   "ffuf",
			Domain:   domain,
			Severity: "info",
			Metadata: map[string]string{
				"status": fmt.Sprintf("%d", result.Status),
				"length": fmt.Sprintf("%d", result.Length),
				"words":  fmt.Sprintf("%d", result.Words),
				"lines":  fmt.Sprintf("%d", result.Lines),
			},
		})
	}

	return len(output.Results)
}

func (m *SecretsModule) scanJSFiles(ctx context.Context, domain string, outDir string, jsFile string) {
	m.log.Info("  Scanning JS files for secrets...")

	jsURLs := readLines(jsFile)
	if len(jsURLs) == 0 {
		m.log.Info("  No JS URLs to scan, skipping")
		return
	}

	secretsFile := filepath.Join(outDir, "js_secrets.txt")
	f, err := os.Create(secretsFile)
	if err != nil {
		return
	}
	defer f.Close()

	patterns := []string{
		`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"\x60]([^'"\x60\s]{16,})`,
		`(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*['"\x60]([^'"\x60\s]{16,})`,
		`(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['"\x60]([A-Z0-9]{20})`,
		`(?i)(secret[_-]?key|private[_-]?key)\s*[:=]\s*['"\x60]([^'"\x60\s]{16,})`,
		`(?i)(password|passwd|pwd)\s*[:=]\s*['"\x60]([^'"\x60\s]{6,})`,
		`(?i)(firebase|supabase|mongodb\+srv)://[^\s'"]+`,
		`(?i)(sk-[a-zA-Z0-9]{20,})`,
		`(?i)(ghp_[a-zA-Z0-9]{36})`,
		`(?i)(AIza[0-9A-Za-z\-_]{35})`,
		`(?i)(AKIA[0-9A-Z]{16})`,
		`(?i)(xox[baprs]-[0-9a-zA-Z]{10,})`,
	}

	m.log.Info("  Downloading and scanning %d JS files...", len(jsURLs))

	secretCount := 0
	for _, jsURL := range jsURLs {
		cmd := exec.CommandContext(ctx, "curl", "-s", "-L", "--max-time", "20", jsURL)
		content, err := cmd.Output()
		if err != nil {
			continue
		}

		for _, pattern := range patterns {
			grepCmd := exec.CommandContext(ctx, "grep", "-oP", pattern)
			grepCmd.Stdin = strings.NewReader(string(content))
			matches, err := grepCmd.Output()
			if err == nil && len(matches) > 0 {
				line := fmt.Sprintf("[%s] %s\n", jsURL, strings.TrimSpace(string(matches)))
				f.WriteString(line)

				m.state.AddFinding(state.Finding{
					Type:     "secret",
					Value:    strings.TrimSpace(string(matches)),
					Source:   "js_analysis",
					Domain:   domain,
					Severity: "high",
					Metadata: map[string]string{"file": jsURL},
				})
				secretCount++
			}
		}
	}

	m.state.UpdateStats(func(s *state.ScanStats) {
		s.TotalSecrets += secretCount
	})

	m.log.Success("  Found %d potential secrets in JS files", secretCount)
}
