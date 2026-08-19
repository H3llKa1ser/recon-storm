package scanner

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

type WebModule struct {
    cfg   *config.Config
    state *state.Manager
    log   *logger.Logger
}

func NewWebModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *WebModule {
    return &WebModule{cfg: cfg, state: sm, log: log}
}

func (m *WebModule) Name() string { return "web" }

func (m *WebModule) Run(ctx context.Context, domain string) error {
    outDir := filepath.Join(m.cfg.OutputDir, domain, "web")
    os.MkdirAll(outDir, 0755)

    inputFile := resolveInputFile(
        filepath.Join(m.cfg.OutputDir, domain, "ports", "host_ports.txt"),
        filepath.Join(m.cfg.OutputDir, domain, "dns", "live_hosts.txt"),
        filepath.Join(m.cfg.OutputDir, domain, "subdomains", "all_subdomains.txt"),
    )
    if inputFile == "" {
        return fmt.Errorf("no input file for web probing")
    }

    m.log.Info("  Input: %s (%d hosts)", filepath.Base(inputFile), countFileLines(inputFile))

    httpxBin, found := findHttpx(m.log)
    if !found {
        m.log.Warn("  ProjectDiscovery httpx not found — skipping web probe")
        return nil
    }

    m.log.Info("  Running httpx web probe...")

    httpxJSON := filepath.Join(outDir, "httpx_results.jsonl")
    liveURLFile := filepath.Join(outDir, "live_urls.txt")

    cmd := exec.CommandContext(ctx, httpxBin,
        "-l", inputFile,
        "-sc", "-cl", "-ct", "-title", "-server", "-td", "-cdn",
        "-wc", "-lc", "-rt", "-favicon", "-jarm",
        "-threads", fmt.Sprintf("%d", m.cfg.Threads),
        "-follow-redirects", "-silent",
        "-json", "-o", httpxJSON,
    )

    out, err := cmd.CombinedOutput()
    if err != nil {
        m.log.Warn("  httpx error: %v — %s", err, string(out))
    }

    lines := readLines(httpxJSON)
    var liveURLs []string

    for _, line := range lines {
        var result map[string]interface{}
        if err := json.Unmarshal([]byte(line), &result); err != nil {
            continue
        }

        url, _ := result["url"].(string)
        if url == "" {
            continue
        }
        liveURLs = append(liveURLs, url)

        sc := ""
        if v, ok := result["status_code"].(float64); ok {
            sc = fmt.Sprintf("%.0f", v)
        }
        title, _ := result["title"].(string)
        server, _ := result["webserver"].(string)

        // Join tech names into a readable comma-separated string instead of Go's
        // default slice formatting ("[nginx php]").
        tech := ""
        if techs, ok := result["tech"].([]interface{}); ok {
            strs := make([]string, 0, len(techs))
            for _, t := range techs {
                strs = append(strs, fmt.Sprintf("%v", t))
            }
            tech = strings.Join(strs, ", ")
        }

        m.state.AddFinding(state.Finding{
            Type: "web_server", Value: url, Source: "httpx",
            Domain: domain, Severity: "info",
            Metadata: map[string]string{
                "status_code": sc,
                "title":       title,
                "server":      server,
                "tech":        tech,
            },
        })
    }

    writeLines(liveURLFile, liveURLs)
    m.log.Success("  httpx found %d live web servers", len(liveURLs))
    return nil
}
