package scanner

import (
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
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

    if toolExists("dnsx") {
        m.log.Info("  Running dnsx for DNS resolution...")

        resolvedFile := filepath.Join(outDir, "dnsx_resolved.txt")
        cmd := exec.CommandContext(ctx, "dnsx",
            "-l", subsFile,
            "-resp",
            "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
            "-wd", domain, // wildcard filtering against the base domain
            "-retry", "3",
            "-t", fmt.Sprintf("%d", m.cfg.Threads),
            "-silent",
            "-o", resolvedFile,
        )
        out, err := cmd.CombinedOutput()
        if err != nil {
            m.log.Warn("  dnsx error: %v — %s", err, strings.TrimSpace(string(out)))
        }

        jsonFile := filepath.Join(outDir, "dnsx_full.jsonl")
        jsonCmd := exec.CommandContext(ctx, "dnsx",
            "-l", subsFile,
            "-resp",
            "-a", "-aaaa", "-cname",
            "-wd", domain,
            "-retry", "2",
            "-t", fmt.Sprintf("%d", m.cfg.Threads),
            "-silent",
            "-json",
            "-o", jsonFile,
        )
        jsonCmd.Run()

        resolved := readLines(resolvedFile)
        m.log.Success("  dnsx resolved %d hosts", len(resolved))

        liveFile := filepath.Join(outDir, "live_hosts.txt")
        var liveHosts []string
        seen := make(map[string]bool)

        for _, line := range resolved {
            parts := strings.Fields(line)
            if len(parts) == 0 {
                continue
            }
            host := strings.TrimSpace(parts[0])
            if seen[host] {
                continue
            }
            seen[host] = true
            liveHosts = append(liveHosts, host)
            m.state.AddFinding(state.Finding{
                Type: "dns_resolved", Value: host, Source: "dnsx",
                Domain: domain, Severity: "info",
                Metadata: map[string]string{"raw": line},
            })
        }

        writeLines(liveFile, liveHosts)
        m.log.Info("  %d unique live hosts written to %s", len(liveHosts), filepath.Base(liveFile))
    } else {
        m.log.Warn("  dnsx not found — skipping active DNS resolution")
        m.log.Warn("  Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")

        // Fallback: treat enumerated subdomains as live hosts AND record them as
        // findings so the recomputed live-host stat stays consistent.
        subsData := readLines(subsFile)
        if len(subsData) > 0 {
            liveFile := filepath.Join(outDir, "live_hosts.txt")
            writeLines(liveFile, subsData)
            for _, h := range subsData {
                m.state.AddFinding(state.Finding{
                    Type: "dns_resolved", Value: h, Source: "fallback",
                    Domain: domain, Severity: "info",
                    Metadata: map[string]string{"note": "unresolved fallback (dnsx missing)"},
                })
            }
            m.log.Info("  Fallback: using %d subdomains as live hosts", len(subsData))
        }
    }

    if !m.cfg.PassiveOnly {
        m.log.Info("  Attempting zone transfer...")
        m.zoneTransfer(ctx, domain, outDir)
    } else {
        m.log.Info("  Skipping zone transfer (passive mode)")
    }

    return nil
}

// soaLine matches a resource record whose type field is SOA, tolerating the
// variable whitespace dig emits.
var soaLine = regexp.MustCompile(`(?mi)^\S+\s+\d+\s+IN\s+SOA\s`)

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
    if len(nameservers) == 0 {
        m.log.Debug("  No nameservers found for %s", domain)
        return
    }

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
        output := string(axfrOut)

        // A successful AXFR is delimited by the SOA record: the transfer begins
        // and ends with SOA, so a genuine transfer contains at least two SOA
        // lines. This is the authoritative signal and avoids false positives
        // from large TXT records or chatty refusals.
        soaCount := len(soaLine.FindAllString(output, -1))
        refused := strings.Contains(output, "Transfer failed") ||
            strings.Contains(output, "; Transfer failed") ||
            strings.Contains(output, "connection timed out") ||
            strings.Contains(output, "communications error") ||
            strings.Contains(output, "REFUSED")

        if soaCount >= 2 && !refused {
            lineCount := strings.Count(output, "\n")
            outFile := filepath.Join(outDir, fmt.Sprintf("zonetransfer_%s.txt", ns))
            os.WriteFile(outFile, axfrOut, 0644)
            m.log.Success("  ZONE TRANSFER CONFIRMED from %s! (SOA envelope present, %d lines)", ns, lineCount)

            m.state.AddFinding(state.Finding{
                Type: "vuln", Value: fmt.Sprintf("Zone transfer possible from %s", ns),
                Source: "dig", Domain: domain, Severity: "high",
                Metadata: map[string]string{
                    "nameserver":  ns,
                    "file":        outFile,
                    "soa_records": fmt.Sprintf("%d", soaCount),
                    "line_count":  fmt.Sprintf("%d", lineCount),
                    "description": "Full DNS zone transfer permitted; discloses all records for the zone.",
                },
            })
        } else if soaCount == 1 {
            m.log.Debug("  Partial/refused AXFR from %s (single SOA) — not a transfer", ns)
        }
    }
}
