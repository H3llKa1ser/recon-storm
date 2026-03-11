package scanner

import (
    "bufio"
    "context"
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
            m.log.Debug("  %s not found, skipping", t.name)
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
                    m.log.Debug("  %s error: %v", t.name, err)
                    return
                }
                os.WriteFile(t.outFile, output, 0644)
            } else {
                cmd.Run()
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

func (m *SubdomainModule) queryCrtSh(ctx context.Context, domain string) []string {
    cmd := exec.CommandContext(ctx, "curl", "-s",
        fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))

    output, err := cmd.Output()
    if err != nil {
        m.log.Debug("  crt.sh query failed: %v", err)
        return nil
    }

    var subs []string
    seen := make(map[string]bool)
    lines := strings.Split(string(output), "\"name_value\":\"")
    for _, line := range lines[1:] {
        idx := strings.Index(line, "\"")
        if idx > 0 {
            names := strings.Split(line[:idx], "\\n")
            for _, name := range names {
                name = strings.TrimSpace(strings.ToLower(name))
                name = strings.TrimPrefix(name, "*.")
                if name != "" && !seen[name] {
                    seen[name] = true
                    subs = append(subs, name)
                }
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
