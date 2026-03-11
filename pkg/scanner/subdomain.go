package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/H3llKa1ser/recon-storm/pkg/config"
	"github.com/H3llKa1ser/recon-storm/pkg/logger"
	"github.com/H3llKa1ser/recon-storm/pkg/state"
)

type SubdomainModule struct {
	cfg   *config.Config
	state *state.Manager
	log   *logger.Logger
}

func NewSubdomainModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *SubdomainModule {
	return &SubdomainModule{cfg: cfg, state: sm, log: log}
}

func (m *SubdomainModule) Name() string { return "subdomains" }

func (m *SubdomainModule) Run(ctx context.Context, domain string) error {
	outDir := filepath.Join(m.cfg.OutputDir, domain, "subdomains")
	os.MkdirAll(outDir, 0755)

	var mu sync.Mutex
	allSubs := make(map[string]string) // subdomain -> source

	type subTool struct {
		name    string
		binary  string
		args    []string
		outFile string
	}

	tools := []subTool{
		{
			name:    "subfinder",
			binary:  "subfinder",
			args:    []string{"-d", domain, "-all", "-silent", "-o", filepath.Join(outDir, "subfinder.txt")},
			outFile: filepath.Join(outDir, "subfinder.txt"),
		},
		{
			name:    "amass",
			binary:  "amass",
			args:    []string{"enum", "-passive", "-d", domain, "-o", filepath.Join(outDir, "amass.txt")},
			outFile: filepath.Join(outDir, "amass.txt"),
		},
		{
			name:    "assetfinder",
			binary:  "assetfinder",
			args:    []string{"--subs-only", domain},
			outFile: filepath.Join(outDir, "assetfinder.txt"),
		},
		{
			name:    "findomain",
			binary:  "findomain",
			args:    []string{"-t", domain, "-u", filepath.Join(outDir, "findomain.txt")},
			outFile: filepath.Join(outDir, "findomain.txt"),
		},
	}

	// Run all tools concurrently
	var wg sync.WaitGroup
	for _, tool := range tools {
		t := tool
		if _, err := exec.LookPath(t.binary); err != nil {
			m.log.Warn("  %s not found, skipping — install it for better coverage", t.name)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			m.log.Info("  Running %s...", t.name)

			cmd := exec.CommandContext(ctx, t.binary, t.args...)

			if t.name == "assetfinder" {
				output, err := cmd.Output()
				if err != nil {
					m.log.Warn("  %s error: %v", t.name, err)
					return
				}
				os.WriteFile(t.outFile, output, 0644)
			} else {
				if output, err := cmd.CombinedOutput(); err != nil {
					m.log.Debug("  %s stderr: %s", t.name, string(output))
				}
			}

			subs := readLines(t.outFile)
			mu.Lock()
			for _, sub := range subs {
				sub = strings.TrimSpace(strings.ToLower(sub))
				if sub != "" && strings.HasSuffix(sub, domain) {
					allSubs[sub] = t.name
				}
			}
			mu.Unlock()
			m.log.Info("  %s found %d subdomains", t.name, len(subs))
		}()
	}
	wg.Wait()

	// ── CRT.SH (passive, no tool needed) ──
	m.log.Info("  Querying crt.sh...")
	crtSubs := m.queryCrtSh(ctx, domain)
	for _, sub := range crtSubs {
		allSubs[sub] = "crt.sh"
	}

	// ── Aggregate & deduplicate ──
	uniqueSubs := make([]string, 0, len(allSubs))
	for sub := range allSubs {
		uniqueSubs = append(uniqueSubs, sub)
	}
	sort.Strings(uniqueSubs)

	finalFile := filepath.Join(outDir, "all_subdomains.txt")
	f, err := os.Create(finalFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	for _, sub := range uniqueSubs {
		fmt.Fprintln(f, sub)

		m.state.AddFinding(state.Finding{
			Type:     "subdomain",
			Value:    sub,
			Source:   allSubs[sub],
			Domain:   domain,
			Severity: "info",
			Metadata: map[string]string{
				"source": allSubs[sub],
			},
		})
	}

	m.state.UpdateStats(func(s *state.ScanStats) {
		s.TotalSubdomains += len(uniqueSubs)
	})

	m.log.Success("  Total unique subdomains: %d → %s", len(uniqueSubs), finalFile)
	return nil
}

// queryCrtSh queries the crt.sh Certificate Transparency log using proper JSON parsing
func (m *SubdomainModule) queryCrtSh(ctx context.Context, domain string) []string {
	cmd := exec.CommandContext(ctx, "curl", "-s", "--max-time", "30",
		fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))

	output, err := cmd.Output()
	if err != nil {
		m.log.Debug("  crt.sh query failed: %v", err)
		return nil
	}

	// Handle empty response
	if len(output) == 0 {
		m.log.Debug("  crt.sh returned empty response")
		return nil
	}

	// Parse JSON properly instead of string splitting
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(output, &entries); err != nil {
		m.log.Debug("  crt.sh JSON parse failed: %v", err)
		return nil
	}

	var subs []string
	seen := make(map[string]bool)
	for _, entry := range entries {
		// name_value can contain multiple names separated by newlines
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name != "" && !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	m.log.Info("  crt.sh found %d subdomains", len(subs))
	return subs
}

// readLines reads a file and returns non-empty lines
func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// readLinesOrWarn reads a file and returns its lines, logging a warning if empty.
// Returns nil, false if the file is missing or empty.
func readLinesOrWarn(path string, log *logger.Logger, moduleName string) ([]string, bool) {
	lines := readLines(path)
	if len(lines) == 0 {
		log.Warn("  %s: input file %s is empty or missing, skipping", moduleName, filepath.Base(path))
		return nil, false
	}
	return lines, true
}
