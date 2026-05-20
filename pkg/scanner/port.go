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

    inputFile := resolveInputFile(
        filepath.Join(m.cfg.OutputDir, domain, "dns", "live_hosts.txt"),
        filepath.Join(m.cfg.OutputDir, domain, "subdomains", "all_subdomains.txt"),
    )
    if inputFile == "" {
        return fmt.Errorf("no input hosts file found")
    }

    hostCount := countFileLines(inputFile)
    m.log.Info("  Scanning %d hosts from %s", hostCount, filepath.Base(inputFile))

    naabuDone := false

    // ── Naabu fast port scan ──
    if toolExists("naabu") {
        m.log.Info("  Running Naabu port scan...")
        naabuOut := filepath.Join(outDir, "naabu_results.txt")

        cmd := exec.CommandContext(ctx, "naabu",
            "-list", inputFile,
            "-top-ports", "1000",
            "-c", fmt.Sprintf("%d", m.cfg.Threads),
            "-silent",
            "-o", naabuOut,
        )
        out, err := cmd.CombinedOutput()
        if err != nil {
            m.log.Warn("  Naabu error: %v — %s", err, strings.TrimSpace(string(out)))
        }

        results := readLines(naabuOut)
        if len(results) > 0 {
            naabuDone = true
            for _, line := range results {
                parts := strings.SplitN(line, ":", 2)
                host, port := line, ""
                if len(parts) == 2 {
                    host, port = parts[0], parts[1]
                }
                m.state.AddFinding(state.Finding{
                    Type: "open_port", Value: line, Source: "naabu",
                    Domain: domain, Severity: "info",
                    Metadata: map[string]string{"host": host, "port": port},
                })
            }
            m.state.UpdateStats(func(s *state.ScanStats) { s.TotalOpenPorts += len(results) })
            m.log.Success("  Naabu found %d open ports", len(results))

            writeLines(filepath.Join(outDir, "host_ports.txt"), results)
        }
    } else {
        m.log.Warn("  Naabu not found — using Nmap fallback")
    }

    // ── Nmap fallback or service detection ──
    if toolExists("nmap") {
        if naabuDone {
            m.nmapServiceDetect(ctx, domain, outDir)
        } else {
            m.nmapFallback(ctx, domain, outDir, inputFile)
        }
    }

    return nil
}

func (m *PortModule) nmapFallback(ctx context.Context, domain, outDir, inputFile string) {
    m.log.Info("  Running Nmap top-1000 scan (Naabu fallback)...")

    hosts := readLines(inputFile)
    for _, host := range hosts {
        safeHost := strings.ReplaceAll(host, ".", "_")
        xmlOut := filepath.Join(outDir, fmt.Sprintf("nmap_fallback_%s.xml", safeHost))
        txtOut := filepath.Join(outDir, fmt.Sprintf("nmap_fallback_%s.txt", safeHost))

        cmd := exec.CommandContext(ctx, "nmap",
            "-sV", "--top-ports", "1000", "--open",
            "-oX", xmlOut, "-oN", txtOut,
            host,
        )
        cmd.Run()

        // Parse open ports from text output
        lines := readLines(txtOut)
        for _, line := range lines {
            if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
                fields := strings.Fields(line)
                if len(fields) >= 3 {
                    portProto := fields[0] // e.g., "80/tcp"
                    service := fields[2]
                    m.state.AddFinding(state.Finding{
                        Type: "open_port", Value: fmt.Sprintf("%s:%s", host, portProto),
                        Source: "nmap", Domain: domain, Severity: "info",
                        Metadata: map[string]string{"host": host, "port": portProto, "service": service},
                    })
                    m.state.UpdateStats(func(s *state.ScanStats) { s.TotalOpenPorts++ })
                }
            }
        }

        m.log.Success("  Nmap fallback scan complete → %s", xmlOut)
    }
}

func (m *PortModule) nmapServiceDetect(ctx context.Context, domain, outDir string) {
    m.log.Info("  Running Nmap service detection on Naabu results...")

    naabuOut := filepath.Join(outDir, "naabu_results.txt")
    if !fileExists(naabuOut) {
        return
    }

    results := readLines(naabuOut)
    hostPorts := make(map[string][]string)
    for _, line := range results {
        parts := strings.SplitN(line, ":", 2)
        if len(parts) == 2 {
            hostPorts[parts[0]] = append(hostPorts[parts[0]], parts[1])
        }
    }

    for host, ports := range hostPorts {
        safeHost := strings.ReplaceAll(host, ".", "_")
        xmlOut := filepath.Join(outDir, fmt.Sprintf("nmap_%s.xml", safeHost))

        cmd := exec.CommandContext(ctx, "nmap",
            "-sV", "-sC",
            "-p", strings.Join(ports, ","),
            "-oX", xmlOut, "--open",
            host,
        )
        cmd.Run()
    }

    m.log.Success("  Nmap service detection complete")
}
