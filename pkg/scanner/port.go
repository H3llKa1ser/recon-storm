package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/H3llKa1ser/recon-storm/pkg/config"
	"github.com/H3llKa1ser/recon-storm/pkg/logger"
	"github.com/H3llKa1ser/recon-storm/pkg/state"
)

type PortModule struct {
	cfg   *config.Config
	state *state.Manager
	log   *logger.Logger
}

func NewPortModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *PortModule {
	return &PortModule{cfg: cfg, state: sm, log: log}
}

func (m *PortModule) Name() string { return "ports" }

func (m *PortModule) Run(ctx context.Context, domain string) error {
	outDir := filepath.Join(m.cfg.OutputDir, domain, "ports")
	os.MkdirAll(outDir, 0755)

	// Prefer live_hosts from DNS resolution, fall back to all_subdomains.
	// Check both existence AND content — dnsx may create an empty file.
	inputFile := filepath.Join(m.cfg.OutputDir, domain, "dns", "live_hosts.txt")
	if lines := readLines(inputFile); len(lines) == 0 {
		inputFile = filepath.Join(m.cfg.OutputDir, domain, "subdomains", "all_subdomains.txt")
	}

	// Final check: do we have any input at all?
	if _, ok := readLinesOrWarn(inputFile, m.log, "ports"); !ok {
		return nil
	}

	hasNaabu := false
	naabuOut := filepath.Join(outDir, "naabu_results.txt")

	// ── Naabu — Fast Port Scanner ──
	if _, err := exec.LookPath("naabu"); err == nil {
		hasNaabu = true
		m.log.Info("  Running Naabu port scan...")

		naabuJSON := filepath.Join(outDir, "naabu_results.json")

		cmd := exec.CommandContext(ctx, "naabu",
			"-list", inputFile,
			"-top-ports", "1000",
			"-c", fmt.Sprintf("%d", m.cfg.Threads),
			"-silent",
			"-o", naabuOut,
			"-json", "-output", naabuJSON,
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			m.log.Warn("  Naabu error: %v — %s", err, string(output))
		}

		results := readLines(naabuOut)
		for _, line := range results {
			parts := strings.SplitN(line, ":", 2)
			host := line
			port := ""
			if len(parts) == 2 {
				host = parts[0]
				port = parts[1]
			}

			m.state.AddFinding(state.Finding{
				Type:     "open_port",
				Value:    line,
				Source:   "naabu",
				Domain:   domain,
				Severity: "info",
				Metadata: map[string]string{
					"host": host,
					"port": port,
				},
			})
		}

		m.state.UpdateStats(func(s *state.ScanStats) {
			s.TotalOpenPorts += len(results)
		})

		m.log.Success("  Naabu found %d open ports", len(results))

		hostPortFile := filepath.Join(outDir, "host_ports.txt")
		writeLines(hostPortFile, results)
	} else {
		m.log.Warn("  Naabu not found — install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
	}

	// ── Nmap service detection ──
	if _, err := exec.LookPath("nmap"); err == nil {
		if hasNaabu {
			// Naabu ran — do targeted service detection on found ports
			if _, err := os.Stat(naabuOut); os.IsNotExist(err) {
				m.log.Debug("  No Naabu results to feed to Nmap")
				return nil
			}

			results := readLines(naabuOut)
			if len(results) == 0 {
				m.log.Info("  Naabu found 0 open ports, skipping Nmap")
				return nil
			}

			m.log.Info("  Running Nmap service detection on %d discovered host:port pairs...", len(results))

			hostPorts := make(map[string][]string)
			for _, line := range results {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					hostPorts[parts[0]] = append(hostPorts[parts[0]], parts[1])
				}
			}

			m.runNmapParallel(ctx, outDir, hostPorts)
		} else {
			// Naabu not available — fallback: run nmap top-1000 directly on subdomains
			m.log.Info("  Running Nmap top-1000 scan (Naabu fallback)...")

			nmapOut := filepath.Join(outDir, fmt.Sprintf("nmap_fallback_%s.xml", strings.ReplaceAll(domain, ".", "_")))
			cmd := exec.CommandContext(ctx, "nmap",
				"-sV", "-sC",
				"--top-ports", "1000",
				"-iL", inputFile,
				"-oX", nmapOut,
				"--open",
				"--min-rate", "300",
				"-T4",
			)
			output, err := cmd.CombinedOutput()
			if err != nil {
				m.log.Warn("  Nmap fallback error: %v — %s", err, string(output))
			} else {
				m.log.Success("  Nmap fallback scan complete → %s", nmapOut)
			}
		}
	} else {
		m.log.Warn("  Nmap not found — install: sudo apt-get install -y nmap")
	}

	return nil
}

// runNmapParallel runs nmap service detection across multiple hosts concurrently
// with a bounded worker pool to avoid overwhelming the system
func (m *PortModule) runNmapParallel(ctx context.Context, outDir string, hostPorts map[string][]string) {
	// Limit concurrent nmap instances (nmap is already heavy)
	maxWorkers := 5
	if len(hostPorts) < maxWorkers {
		maxWorkers = len(hostPorts)
	}

	type nmapJob struct {
		host  string
		ports string
	}

	jobs := make(chan nmapJob, len(hostPorts))
	for host, ports := range hostPorts {
		jobs <- nmapJob{host: host, ports: strings.Join(ports, ",")}
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				nmapOut := filepath.Join(outDir, fmt.Sprintf("nmap_%s.xml", strings.ReplaceAll(job.host, ".", "_")))
				cmd := exec.CommandContext(ctx, "nmap",
					"-sV", "-sC",
					"-p", job.ports,
					"-oX", nmapOut,
					"--open",
					job.host,
				)
				if output, err := cmd.CombinedOutput(); err != nil {
					m.log.Debug("  Nmap error for %s: %v — %s", job.host, err, string(output))
				}
			}
		}()
	}
	wg.Wait()

	m.log.Success("  Nmap service detection complete (%d hosts)", len(hostPorts))
}
