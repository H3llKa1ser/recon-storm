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

    inputFile := filepath.Join(m.cfg.OutputDir, domain, "dns", "live_hosts.txt")
    if _, err := os.Stat(inputFile); os.IsNotExist(err) {
        inputFile = filepath.Join(m.cfg.OutputDir, domain, "subdomains", "all_subdomains.txt")
    }

    if _, err := os.Stat(inputFile); os.IsNotExist(err) {
        return fmt.Errorf("no input hosts file found")
    }

    // ── Naabu — Fast Port Scanner ──
    if _, err := exec.LookPath("naabu"); err == nil {
        m.log.Info("  Running Naabu port scan...")

        naabuOut := filepath.Join(outDir, "naabu_results.txt")
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
    }

    // ── Nmap service detection on found ports ──
    if _, err := exec.LookPath("nmap"); err == nil {
        m.log.Info("  Running Nmap service detection on discovered ports...")

        naabuOut := filepath.Join(outDir, "naabu_results.txt")
        if _, err := os.Stat(naabuOut); os.IsNotExist(err) {
            m.log.Debug("  No Naabu results to feed to Nmap")
            return nil
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
            portStr := strings.Join(ports, ",")
            nmapOut := filepath.Join(outDir, fmt.Sprintf("nmap_%s.xml", strings.ReplaceAll(host, ".", "_")))

            cmd := exec.CommandContext(ctx, "nmap",
                "-sV", "-sC",
                "-p", portStr,
                "-oX", nmapOut,
                "--open",
                host,
            )
            cmd.Run()
        }

        m.log.Success("  Nmap service detection complete")
    }

    return nil
}
