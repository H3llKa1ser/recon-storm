package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/H3llKa1ser/recon-storm/pkg/config"
	"github.com/H3llKa1ser/recon-storm/pkg/logger"
	"github.com/H3llKa1ser/recon-storm/pkg/state"
)

type DNSModule struct {
	cfg   *config.Config
	state *state.Manager
	log   *logger.Logger
}

func NewDNSModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *DNSModule {
	return &DNSModule{cfg: cfg, state: sm, log: log}
}

func (m *DNSModule) Name() string { return "dns" }

func (m *DNSModule) Run(ctx context.Context, domain string) error {
	outDir := filepath.Join(m.cfg.OutputDir, domain, "dns")
	os.MkdirAll(outDir, 0755)

	subsFile := filepath.Join(m.cfg.OutputDir, domain, "subdomains", "all_subdomains.txt")
	if _, err := os.Stat(subsFile); os.IsNotExist(err) {
		return fmt.Errorf("no subdomains file found — run subdomains module first")
	}

	// Check if input file has any content
	if lines, ok := readLinesOrWarn(subsFile, m.log, "dns"); !ok {
		return nil
	} else {
		m.log.Info("  DNS module processing %d subdomains", len(lines))
	}

	// ── dnsx resolution ──
	if _, err := exec.LookPath("dnsx"); err == nil {
		m.log.Info("  Running dnsx for DNS resolution...")

		dnsxOut := filepath.Join(outDir, "dnsx_resolved.txt")
		dnsxJSON := filepath.Join(outDir, "dnsx_full.json")

		cmd := exec.CommandContext(ctx, "dnsx",
			"-l", subsFile,
			"-resp",
			"-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
			"-retry", "3",
			"-t", fmt.Sprintf("%d", m.cfg.Threads),
			"-o", dnsxOut,
			"-json", "-jo", dnsxJSON,
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			m.log.Warn("  dnsx error: %v — %s", err, string(output))
		}

		resolved := readLines(dnsxOut)
		m.log.Success("  dnsx resolved %d hosts", len(resolved))

		liveFile := filepath.Join(outDir, "live_hosts.txt")
		var liveHosts []string
		for _, line := range resolved {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				host := strings.TrimSpace(parts[0])
				liveHosts = append(liveHosts, host)
				m.state.AddFinding(state.Finding{
					Type:     "dns_resolved",
					Value:    line,
					Source:   "dnsx",
					Domain:   domain,
					Severity: "info",
					Metadata: map[string]string{"raw": line},
				})
			}
		}
		writeLines(liveFile, liveHosts)

		m.state.UpdateStats(func(s *state.ScanStats) {
			s.TotalLiveHosts += len(liveHosts)
		})
	} else {
		m.log.Warn("  dnsx not found — skipping DNS resolution. Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
	}

	// ── Zone Transfer Attempt (active operation — skip in passive mode) ──
	if m.cfg.PassiveOnly {
		m.log.Info("  Skipping zone transfer (passive mode)")
	} else {
		m.log.Info("  Attempting zone transfer...")
		m.attemptZoneTransfer(ctx, domain, outDir)
	}

	return nil
}

func (m *DNSModule) attemptZoneTransfer(ctx context.Context, domain string, outDir string) {
	// Check if dig is available
	if _, err := exec.LookPath("dig"); err != nil {
		m.log.Warn("  dig not found — skipping zone transfer attempts")
		return
	}

	cmd := exec.CommandContext(ctx, "dig", "+short", "NS", domain)
	output, err := cmd.Output()
	if err != nil {
		m.log.Debug("  Could not get NS records: %v", err)
		return
	}

	nameservers := strings.Fields(string(output))
	if len(nameservers) == 0 {
		m.log.Debug("  No NS records found for %s", domain)
		return
	}

	for _, ns := range nameservers {
		ns = strings.TrimSuffix(strings.TrimSpace(ns), ".")
		if ns == "" {
			continue
		}

		m.log.Debug("  Trying zone transfer from %s...", ns)
		axfr := exec.CommandContext(ctx, "dig", "AXFR", domain, fmt.Sprintf("@%s", ns))
		axfrOut, err := axfr.Output()
		if err != nil {
			m.log.Debug("  Zone transfer from %s failed: %v", ns, err)
			continue
		}

		// Validate AXFR response: must contain actual records beyond just
		// SOA and transfer metadata. A failed AXFR often returns only a
		// single SOA or a short "Transfer failed" message.
		axfrStr := string(axfrOut)
		lines := strings.Split(axfrStr, "\n")
		recordCount := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Skip empty lines, comments, and the transfer stats footer
			if line == "" || strings.HasPrefix(line, ";") {
				continue
			}
			recordCount++
		}

		if recordCount > 2 {
			// More than just SOA records — this is a real zone transfer
			outFile := filepath.Join(outDir, fmt.Sprintf("zonetransfer_%s.txt", ns))
			os.WriteFile(outFile, axfrOut, 0644)
			m.log.Success("  ZONE TRANSFER SUCCESSFUL from %s! (%d records)", ns, recordCount)

			m.state.AddFinding(state.Finding{
				Type:     "vuln",
				Value:    fmt.Sprintf("Zone transfer possible from %s (%d records)", ns, recordCount),
				Source:   "dig",
				Domain:   domain,
				Severity: "high",
				Metadata: map[string]string{"nameserver": ns, "file": outFile, "records": fmt.Sprintf("%d", recordCount)},
			})
		} else {
			m.log.Debug("  Zone transfer from %s returned %d records (likely refused)", ns, recordCount)
		}
	}
}

// writeLines writes a slice of strings to a file
func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, line := range lines {
		fmt.Fprintln(f, line)
	}
	return nil
}
