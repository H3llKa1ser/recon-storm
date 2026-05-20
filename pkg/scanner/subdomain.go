package scanner

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "sort"
    "strings"
    "sync"
    "time"

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
    allSubs := make(map[string]string)

    type subTool struct {
        name, binary string
        args         []string
        outFile      string
        captureStdout bool
    }

    tools := []subTool{
        {name: "subfinder", binary: "subfinder",
            args: []string{"-d", domain, "-all", "-silent", "-o", filepath.Join(outDir, "subfinder.txt")},
            outFile: filepath.Join(outDir, "subfinder.txt")},
        {name: "amass", binary: "amass",
            args: []string{"enum", "-passive", "-d", domain, "-o", filepath.Join(outDir, "amass.txt")},
            outFile: filepath.Join(outDir, "amass.txt")},
        {name: "assetfinder", binary: "assetfinder",
            args: []string{"--subs-only", domain},
            outFile: filepath.Join(outDir, "assetfinder.txt"), captureStdout: true},
        {name: "findomain", binary: "findomain",
            args: []string{"-t", domain, "-u", filepath.Join(outDir, "findomain.txt")},
            outFile: filepath.Join(outDir, "findomain.txt")},
    }

    var wg sync.WaitGroup
    for _, t := range tools {
        t := t
        if !toolExists(t.binary) {
            m.log.Warn("  %s not found, skipping — install it for better coverage", t.name)
            continue
        }

        wg.Add(1)
        go func() {
            defer wg.Done()
            m.log.Info("  Running %s...", t.name)

            cmd := exec.CommandContext(ctx, t.binary, t.args...)
            if t.captureStdout {
                out, err := cmd.Output()
                if err != nil {
                    m.log.Debug("  %s error: %v", t.name, err)
                    return
                }
                os.WriteFile(t.outFile, out, 0644)
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

    // crt.sh with proper JSON parsing
    m.log.Info("  Querying crt.sh...")
    crtSubs := m.queryCrtSh(ctx, domain)
    for _, sub := range crtSubs {
        allSubs[sub] = "crt.sh"
    }

    // Deduplicate and sort
    uniqueSubs := make([]string, 0, len(allSubs))
    for sub := range allSubs {
        uniqueSubs = append(uniqueSubs, sub)
    }
    sort.Strings(uniqueSubs)

    // Write output
    finalFile := filepath.Join(outDir, "all_subdomains.txt")
    f, err := os.Create(finalFile)
    if err != nil {
        return fmt.Errorf("create output: %w", err)
    }
    defer f.Close()

    for _, sub := range uniqueSubs {
        fmt.Fprintln(f, sub)
        m.state.AddFinding(state.Finding{
            Type: "subdomain", Value: sub, Source: allSubs[sub],
            Domain: domain, Severity: "info",
            Metadata: map[string]string{"source": allSubs[sub]},
        })
    }

    m.state.UpdateStats(func(s *state.ScanStats) {
        s.TotalSubdomains += len(uniqueSubs)
    })

    m.log.Success("  Total unique subdomains: %d → %s", len(uniqueSubs), finalFile)
    return nil
}

// queryCrtSh uses proper JSON parsing instead of string splitting
func (m *SubdomainModule) queryCrtSh(ctx context.Context, domain string) []string {
    url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

    client := &http.Client{Timeout: 30 * time.Second}
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        m.log.Debug("  crt.sh request error: %v", err)
        return nil
    }
    req.Header.Set("User-Agent", "ReconStorm/2.0")

    resp, err := client.Do(req)
    if err != nil {
        m.log.Debug("  crt.sh error: %v", err)
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        m.log.Debug("  crt.sh returned %d", resp.StatusCode)
        return nil
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        m.log.Debug("  crt.sh read error: %v", err)
        return nil
    }

    // Proper JSON parsing
    var entries []struct {
        NameValue string `json:"name_value"`
        CommonName string `json:"common_name"`
    }

    if err := json.Unmarshal(body, &entries); err != nil {
        m.log.Debug("  crt.sh JSON parse error: %v", err)
        return nil
    }

    seen := make(map[string]bool)
    var subs []string

    for _, entry := range entries {
        // name_value can contain multiple names separated by newlines
        names := strings.Split(entry.NameValue, "\n")
        for _, name := range names {
            name = strings.TrimSpace(strings.ToLower(name))
            name = strings.TrimPrefix(name, "*.")
            if name != "" && !seen[name] && strings.HasSuffix(name, domain) {
                seen[name] = true
                subs = append(subs, name)
            }
        }
        // Also check common_name
        cn := strings.TrimSpace(strings.ToLower(entry.CommonName))
        cn = strings.TrimPrefix(cn, "*.")
        if cn != "" && !seen[cn] && strings.HasSuffix(cn, domain) {
            seen[cn] = true
            subs = append(subs, cn)
        }
    }

    m.log.Info("  crt.sh found %d subdomains", len(subs))
    return subs
}
