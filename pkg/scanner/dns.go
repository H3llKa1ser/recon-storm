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
    if !fileExists(subsFile) {
        return fmt.Errorf("no subdomains file — run subdomains module first")
    }

    subCount := countFileLines(subsFile)
    m.log.Info("  DNS module processing %d subdomains", subCount)

    // dnsx resolution
    if toolExists("dnsx") {
        m.log.Info("  Running dnsx for DNS resolution...")
        dnsxOut := filepath.Join(outDir, "dnsx_resolved.txt")
        dnsxJSON := filepath.Join(outDir, "dnsx_full.jsonl")

        cmd := exec.CommandContext(ctx, "dnsx",
            "-l", subsFile,
            "-resp", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
            "-retry", "3",
            "-t", fmt.Sprintf("%d", m.cfg.Threads),
            "-o", dnsxOut,
            "-json", "-jo", dnsxJSON,
        )
        out, err := cmd.CombinedOutput()
        if err != nil {
            m.log.Warn("  dnsx error: %v — %s", err, strings.TrimSpace(string(out)))
        }

        resolved := readLines(dnsxOut)
        m.log.Success("  dnsx resolved %d hosts", len(resolved))

        liveFile := filepath.Join(outDir, "live_hosts.txt")
        var liveHosts []string
        for _, line := range resolved {
            parts := strings.Fields(line)
            if len(parts) > 0 {
                host := parts[0]
                liveHosts = append(liveHosts, host)
                m.state.AddFinding(state.Finding{
                    Type: "dns_resolved", Value: line, Source: "dnsx",
                    Domain: domain, Severity: "info",
                    Metadata: map[string]string{"raw": line},
                })
            }
        }
        writeLines(liveFile, liveHosts)

        m.state.UpdateStats(func(s *state.ScanStats) {
            s.TotalLiveHosts += len(liveHosts)
        })
    } else {
        m.log.Warn("  dnsx not found — skipping DNS resolution")
    }

    // Zone transfer — only in active mode
    if !m.cfg.PassiveOnly {
        m.log.Info("  Attempting zone transfer...")
        m.zoneTransfer(ctx, domain, outDir)
    } else {
        m.log.Info("  Skipping zone transfer (passive mode)")
    }

    return nil
}

func (m *DNSModule) zoneTransfer(ctx context.Context, domain string, outDir string) {
    if !toolExists("dig") {
        m.log.Warn("  dig not found, skipping zone transfer")
        return
    }

    cmd := exec.CommandContext(ctx, "dig", "+short", "NS", domain)
    out, err := cmd.Output()
    if err != nil {
        m.log.Debug("  NS lookup failed: %v", err)
        return
    }

    nameservers := strings.Fields(string(out))
    for _, ns := range nameservers {
        ns = strings.TrimSuffix(strings.TrimSpace(ns), ".")
        if ns == "" {
            continue
        }

        m.log.Debug("  Trying AXFR from %s...", ns)
        axfr := exec.CommandContext(ctx, "dig", "AXFR", domain, fmt.Sprintf("@%s", ns))
        axfrOut, err := axfr.Output()
        if err != nil {
            continue
        }

        // Validate: real zone transfer has multiple record types, not just SOA
        output := string(axfrOut)
        hasRecords := false
        recordTypes := []string{" A ", " AAAA ", " CNAME ", " MX ", " TXT ", " NS "}
        recordCount := 0

        for _, rt := range recordTypes {
            if strings.Contains(output, rt) {
                recordCount++
            }
        }
        // Real zone transfer has at least 3 different record types
        if recordCount >= 3 && strings.Count(output, "\n") > 10 {
            hasRecords = true
        }

        if hasRecords {
            outFile := filepath.Join(outDir, fmt.Sprintf("zonetransfer_%s.txt", ns))
            os.WriteFile(outFile, axfrOut, 0644)
            m.log.Success("  ZONE TRANSFER SUCCESSFUL from %s!", ns)

            m.state.AddFinding(state.Finding{
                Type: "vuln", Value: fmt.Sprintf("Zone transfer possible from %s", ns),
                Source: "dig", Domain: domain, Severity: "high",
                Metadata: map[string]string{"nameserver": ns, "file": outFile, "record_types": fmt.Sprintf("%d", recordCount)},
            })
        }
    }
}
