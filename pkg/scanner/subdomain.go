package scanner

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net"
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

    // Detect a DNS wildcard up front so we can flag names that only exist
    // because the zone answers everything. This requires live DNS queries to the
    // target's authoritative servers, so it is skipped in passive mode.
    var wildcardIPs map[string]bool
    if m.cfg.PassiveOnly {
        m.log.Info("  Passive mode — skipping active wildcard DNS detection")
    } else {
        wildcardIPs = m.detectWildcard(domain)
        if len(wildcardIPs) > 0 {
            m.log.Warn("  Wildcard DNS detected for %s (%v) — flagging wildcard hits", domain, setKeys(wildcardIPs))
        }
    }

    var mu sync.Mutex
    allSubs := make(map[string]string)

    type subTool struct {
        name, binary  string
        args          []string
        outFile       string
        captureStdout bool
    }

    tools := []subTool{
        {name: "subfinder", binary: "subfinder",
            args:    []string{"-d", domain, "-all", "-silent", "-o", filepath.Join(outDir, "subfinder.txt")},
            outFile: filepath.Join(outDir, "subfinder.txt")},
        {name: "amass", binary: "amass",
            args:    []string{"enum", "-passive", "-d", domain, "-o", filepath.Join(outDir, "amass.txt")},
            outFile: filepath.Join(outDir, "amass.txt")},
        {name: "assetfinder", binary: "assetfinder",
            args:    []string{"--subs-only", domain},
            outFile: filepath.Join(outDir, "assetfinder.txt"), captureStdout: true},
        {name: "findomain", binary: "findomain",
            args:    []string{"-t", domain, "-u", filepath.Join(outDir, "findomain.txt")},
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
            added := 0
            mu.Lock()
            for _, sub := range subs {
                sub = strings.TrimSpace(strings.ToLower(sub))
                sub = strings.TrimPrefix(sub, "*.")
                if sub != "" && isInScope(sub, domain) {
                    if _, exists := allSubs[sub]; !exists {
                        allSubs[sub] = t.name
                        added++
                    }
                }
            }
            mu.Unlock()
            m.log.Info("  %s contributed %d in-scope subdomains", t.name, added)
        }()
    }
    wg.Wait()

    // crt.sh with proper JSON parsing
    m.log.Info("  Querying crt.sh...")
    crtSubs := m.queryCrtSh(ctx, domain)
    mu.Lock()
    for _, sub := range crtSubs {
        if _, exists := allSubs[sub]; !exists {
            allSubs[sub] = "crt.sh"
        }
    }
    mu.Unlock()

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

    wildcardCount := 0
    for _, sub := range uniqueSubs {
        fmt.Fprintln(f, sub)

        severity := "info"
        meta := map[string]string{"source": allSubs[sub]}

        // If this name resolves only to the wildcard address(es), mark it so the
        // report and downstream stats can treat it with suspicion.
        if len(wildcardIPs) > 0 && m.resolvesOnlyToWildcard(sub, wildcardIPs) {
            meta["wildcard"] = "true"
            wildcardCount++
        }

        m.state.AddFinding(state.Finding{
            Type: "subdomain", Value: sub, Source: allSubs[sub],
            Domain: domain, Severity: severity,
            Metadata: meta,
        })
    }

    if wildcardCount > 0 {
        m.log.Warn("  %d/%d subdomains resolve only to the wildcard address", wildcardCount, len(uniqueSubs))
    }

    // Stats are recomputed from findings at report time; no manual increment here
    // (prevents double-counting on resume and across sources).

    m.log.Success("  Total unique subdomains: %d → %s", len(uniqueSubs), finalFile)
    return nil
}

// detectWildcard resolves several random non-existent hostnames. If they answer,
// the zone is a wildcard and their answer set is the wildcard address pool.
func (m *SubdomainModule) detectWildcard(domain string) map[string]bool {
    ips := make(map[string]bool)
    resolver := &net.Resolver{}
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    for i := 0; i < 3; i++ {
        probe := fmt.Sprintf("reconstorm-wc-%s.%s", randHex(10), domain)
        addrs, err := resolver.LookupHost(ctx, probe)
        if err != nil {
            continue
        }
        for _, a := range addrs {
            ips[a] = true
        }
    }
    return ips
}

func (m *SubdomainModule) resolvesOnlyToWildcard(host string, wildcard map[string]bool) bool {
    resolver := &net.Resolver{}
    ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
    defer cancel()

    addrs, err := resolver.LookupHost(ctx, host)
    if err != nil || len(addrs) == 0 {
        return false // doesn't resolve at all -> not a wildcard artifact per se
    }
    for _, a := range addrs {
        if !wildcard[a] {
            return false // resolves to something real
        }
    }
    return true
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
    req.Header.Set("User-Agent", "ReconStorm/2.1")

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

    var entries []struct {
        NameValue  string `json:"name_value"`
        CommonName string `json:"common_name"`
    }

    if err := json.Unmarshal(body, &entries); err != nil {
        m.log.Debug("  crt.sh JSON parse error: %v", err)
        return nil
    }

    seen := make(map[string]bool)
    var subs []string

    add := func(name string) {
        name = strings.TrimSpace(strings.ToLower(name))
        name = strings.TrimPrefix(name, "*.")
        if name != "" && !seen[name] && isInScope(name, domain) {
            seen[name] = true
            subs = append(subs, name)
        }
    }

    for _, entry := range entries {
        for _, name := range strings.Split(entry.NameValue, "\n") {
            add(name)
        }
        add(entry.CommonName)
    }

    m.log.Info("  crt.sh found %d subdomains", len(subs))
    return subs
}

// isInScope guards against the HasSuffix bug where "notexample.com" matches
// "example.com". A name is in scope only if it equals the domain or ends with
// ".<domain>".
func isInScope(name, domain string) bool {
    return name == domain || strings.HasSuffix(name, "."+domain)
}

func randHex(n int) string {
    b := make([]byte, n/2+1)
    rand.Read(b)
    return hex.EncodeToString(b)[:n]
}

func setKeys(m map[string]bool) []string {
    out := make([]string, 0, len(m))
    for k := range m {
        out = append(out, k)
    }
    sort.Strings(out)
    return out
}
