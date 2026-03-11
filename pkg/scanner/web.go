package scanner

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"

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

    inputFile := filepath.Join(m.cfg.OutputDir, domain, "ports", "host_ports.txt")
    if _, err := os.Stat(inputFile); os.IsNotExist(err) {
        inputFile = filepath.Join(m.cfg.OutputDir, domain, "subdomains", "all_subdomains.txt")
    }

    if _, err := os.Stat(inputFile); os.IsNotExist(err) {
        return fmt.Errorf("no input file found for web probing")
    }

    // ── httpx — Web Server Probing & Tech Detection ──
    if _, err := exec.LookPath("httpx"); err == nil {
        m.log.Info("  Running httpx web probe...")

        httpxOut := filepath.Join(outDir, "httpx_results.txt")
        httpxJSON := filepath.Join(outDir, "httpx_results.json")

        cmd := exec.CommandContext(ctx, "httpx",
            "-l", inputFile,
            "-sc",
            "-cl",
            "-ct",
            "-title",
            "-server",
            "-td",
            "-cdn",
            "-wc",
            "-lc",
            "-rt",
            "-favicon",
            "-jarm",
            "-threads", fmt.Sprintf("%d", m.cfg.Threads),
            "-follow-redirects",
            "-silent",
            "-o", httpxOut,
            "-json", "-output", httpxJSON,
        )

        output, err := cmd.CombinedOutput()
        if err != nil {
            m.log.Warn("  httpx error: %v — %s", err, string(output))
        }

        m.parseHttpxResults(httpxJSON, domain)

        lines := readLines(httpxOut)
        liveURLFile := filepath.Join(outDir, "live_urls.txt")
        var urls []string
        for _, line := range lines {
            if line != "" {
                urls = append(urls, line)
            }
        }
        writeLines(liveURLFile, urls)

        m.log.Success("  httpx found %d live web servers", len(urls))
    }

    return nil
}

func (m *WebModule) parseHttpxResults(jsonFile string, domain string) {
    lines := readLines(jsonFile)

    for _, line := range lines {
        var result map[string]interface{}
        if err := json.Unmarshal([]byte(line), &result); err != nil {
            continue
        }

        url, _ := result["url"].(string)
        statusCode := ""
        if sc, ok := result["status_code"].(float64); ok {
            statusCode = fmt.Sprintf("%.0f", sc)
        }
        title, _ := result["title"].(string)
        tech := ""
        if techs, ok := result["tech"].([]interface{}); ok {
            techStrs := make([]string, len(techs))
            for i, t := range techs {
                techStrs[i] = fmt.Sprintf("%v", t)
            }
            tech = fmt.Sprintf("%v", techStrs)
        }

        m.state.AddFinding(state.Finding{
            Type:     "web_server",
            Value:    url,
            Source:   "httpx",
            Domain:   domain,
            Severity: "info",
            Metadata: map[string]string{
                "status_code": statusCode,
                "title":       title,
                "tech":        tech,
            },
        })
    }
}
