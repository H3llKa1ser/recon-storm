package scanner

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
    "strings"
    "time"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

type VulnModule struct {
    cfg   *config.Config
    state *state.Manager
    log   *logger.Logger
}

func NewVulnModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *VulnModule {
    return &VulnModule{cfg: cfg, state: sm, log: log}
}

func (m *VulnModule) Name() string { return "vulns" }

func (m *VulnModule) Run(ctx context.Context, domain string) error {
    outDir := filepath.Join(m.cfg.OutputDir, domain, "vulns")
    os.MkdirAll(outDir, 0755)

    liveURLsFile := filepath.Join(m.cfg.OutputDir, domain, "web", "live_urls.txt")
    if !fileExists(liveURLsFile) {
        m.log.Warn("  No live URLs found — skipping vulnerability scan")
        return nil
    }

    urlCount := countFileLines(liveURLsFile)

    if toolExists("nuclei") {
        m.runNuclei(ctx, domain, outDir, liveURLsFile, urlCount)
    } else {
        m.log.Warn("  Nuclei not found — install for comprehensive vuln scanning")
    }

    m.customChecks(ctx, domain, outDir, liveURLsFile)

    return nil
}

// ── Nuclei ───────────────────────────────────────────────

func (m *VulnModule) runNuclei(ctx context.Context, domain, outDir, liveURLsFile string, urlCount int) {
    m.log.Info("  Running Nuclei on %d live URLs...", urlCount)

    nucleiOut := filepath.Join(outDir, "nuclei_results.txt")
    nucleiJSON := filepath.Join(outDir, "nuclei_results.jsonl")

    cmd := exec.CommandContext(ctx, "nuclei",
        "-l", liveURLsFile,
        "-severity", "low,medium,high,critical",
        "-c", fmt.Sprintf("%d", m.cfg.Threads),
        "-bs", "50",
        "-rl", "150",
        "-timeout", "10",
        "-retries", "2",
        "-o", nucleiOut,
        "-jsonl", nucleiJSON,
        "-silent",
        "-stats",
        "-etags", "ssl,dns",
    )

    out, err := cmd.CombinedOutput()
    if err != nil {
        m.log.Warn("  Nuclei error: %v — %s", err, strings.TrimSpace(string(out)))
    }

    m.parseNucleiResults(nucleiJSON, domain)

    results := readLines(nucleiOut)
    m.log.Success("  Nuclei found %d validated vulnerabilities", len(results))
}

func (m *VulnModule) parseNucleiResults(jsonFile string, domain string) {
    lines := readLines(jsonFile)

    for _, line := range lines {
        var result map[string]interface{}
        if err := json.Unmarshal([]byte(line), &result); err != nil {
            continue
        }

        templateID, _ := result["template-id"].(string)
        severity, name, description := "", "", ""
        if info, ok := result["info"].(map[string]interface{}); ok {
            severity, _ = info["severity"].(string)
            name, _ = info["name"].(string)
            description, _ = info["description"].(string)
        }
        matchedAt, _ := result["matched-at"].(string)
        matcherName, _ := result["matcher-name"].(string)

        if strings.ToLower(severity) == "info" {
            continue
        }

        m.state.AddFinding(state.Finding{
            Type:   "vulnerability",
            Value:  fmt.Sprintf("[%s] %s — %s", severity, name, matchedAt),
            Source: "nuclei", Domain: domain, Severity: severity,
            Metadata: map[string]string{
                "template_id": templateID, "name": name,
                "matched_at": matchedAt, "matcher_name": matcherName,
                "description": firstNonEmpty(description, name),
            },
        })
    }
}

// ── Custom Checks with False-Positive Reduction ─────────

type responseFingerprint struct {
    StatusCode    int
    ContentLength int
    RedirectTo    string
    BodyHash      string
    valid         bool
}

type sensitivePathCheck struct {
    Path          string
    Severity      string
    Description   string
    MinBodySize   int
    BodyValidator func(body []byte) bool
    SkipRedirects bool
}

func (m *VulnModule) customChecks(ctx context.Context, domain, outDir, urlsFile string) {
    urls := readLines(urlsFile)
    if len(urls) == 0 {
        return
    }

    m.log.Info("  Running validated sensitive path checks...")

    checks := m.defineChecks()
    m.log.Info("  Checking %d sensitive paths across %d hosts...", len(checks), len(urls))

    client := &http.Client{
        Timeout: 10 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    totalFindings := 0
    totalFPFiltered := 0

    for _, baseURL := range urls {
        baseURL = strings.TrimRight(baseURL, "/")

        // Multiple canaries with different path shapes fingerprint catch-all
        // behaviour more robustly than a single probe.
        baselines := m.getBaselines(ctx, client, baseURL)

        for _, check := range checks {
            targetURL := baseURL + check.Path

            resp, body, err := m.doRequest(ctx, client, targetURL)
            if err != nil {
                continue
            }

            if m.matchesAnyBaseline(resp, body, baselines) {
                totalFPFiltered++
                m.log.Debug("    FP filtered (baseline match): %s", check.Path)
                continue
            }

            if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308 {
                if check.SkipRedirects {
                    totalFPFiltered++
                    continue
                }
                location := strings.ToLower(resp.Header.Get("Location"))
                if m.isCatchAllRedirect(location) {
                    totalFPFiltered++
                    continue
                }
            }

            if resp.StatusCode == 404 || resp.StatusCode == 410 {
                continue
            }

            if check.MinBodySize > 0 && len(body) < check.MinBodySize {
                totalFPFiltered++
                continue
            }

            if check.BodyValidator != nil && !check.BodyValidator(body) {
                totalFPFiltered++
                continue
            }

            m.log.Success("  CONFIRMED: %s [%d] [%d bytes] — %s",
                check.Path, resp.StatusCode, len(body), check.Description)

            m.state.AddFinding(state.Finding{
                Type: "sensitive_file", Value: targetURL, Source: "custom_check",
                Domain: domain, Severity: check.Severity,
                Metadata: map[string]string{
                    "status_code":    fmt.Sprintf("%d", resp.StatusCode),
                    "content_length": fmt.Sprintf("%d", len(body)),
                    "description":    check.Description,
                },
            })
            totalFindings++
        }
    }

    m.log.Info("  Custom checks: %d confirmed, %d false positives filtered", totalFindings, totalFPFiltered)

    summaryFile := filepath.Join(outDir, "custom_checks_summary.txt")
    writeLines(summaryFile, []string{
        fmt.Sprintf("Confirmed findings: %d", totalFindings),
        fmt.Sprintf("False positives filtered: %d", totalFPFiltered),
        fmt.Sprintf("Hosts checked: %d", len(urls)),
        fmt.Sprintf("Paths per host: %d", len(checks)),
    })
}

// getBaselines probes several non-existent paths of different shapes so the
// catch-all fingerprint covers /foo, /foo.php and /.foo style handling.
func (m *VulnModule) getBaselines(ctx context.Context, client *http.Client, baseURL string) []responseFingerprint {
    shapes := []string{
        "/reconstorm_canary_%s",
        "/reconstorm_canary_%s.php",
        "/.reconstorm_canary_%s",
    }
    var fps []responseFingerprint
    for _, shape := range shapes {
        canaryURL := baseURL + fmt.Sprintf(shape, randomString(12))
        resp, body, err := m.doRequest(ctx, client, canaryURL)
        if err != nil {
            continue
        }
        fp := responseFingerprint{
            StatusCode:    resp.StatusCode,
            ContentLength: len(body),
            BodyHash:      hashBody(body),
            valid:         true,
        }
        if resp.StatusCode >= 300 && resp.StatusCode < 400 {
            fp.RedirectTo = strings.ToLower(resp.Header.Get("Location"))
        }
        fps = append(fps, fp)
    }
    return fps
}

func (m *VulnModule) matchesAnyBaseline(resp *http.Response, body []byte, baselines []responseFingerprint) bool {
    for _, b := range baselines {
        if m.matchesBaseline(resp, body, b) {
            return true
        }
    }
    return false
}

func (m *VulnModule) matchesBaseline(resp *http.Response, body []byte, baseline responseFingerprint) bool {
    if !baseline.valid {
        return false
    }
    if resp.StatusCode != baseline.StatusCode {
        return false
    }

    // Byte-identical catch-all page (common for SPA/error handlers).
    if baseline.BodyHash != "" && hashBody(body) == baseline.BodyHash {
        return true
    }

    // Same content length within a 10% band (dynamic pages vary a little).
    if baseline.ContentLength > 0 {
        diff := abs(len(body) - baseline.ContentLength)
        tolerance := baseline.ContentLength / 10
        if tolerance < 20 {
            tolerance = 20
        }
        if diff <= tolerance {
            return true
        }
    }

    if baseline.RedirectTo != "" {
        if strings.ToLower(resp.Header.Get("Location")) == baseline.RedirectTo {
            return true
        }
    }
    return false
}

func (m *VulnModule) isCatchAllRedirect(location string) bool {
    catchAllPatterns := []string{
        "/login", "/signin", "/sign-in", "/auth",
        "/", "/index", "/home", "/404", "/error",
        "/not-found", "/notfound", "/default",
        "/welcome", "/dashboard",
        "sso.", "accounts.", "auth.",
    }
    for _, pattern := range catchAllPatterns {
        if strings.HasSuffix(location, pattern) || strings.Contains(location, pattern) {
            return true
        }
    }
    ssoProviders := []string{"okta.", "auth0.", "onelogin.", "ping", "adfs.", "login.microsoftonline"}
    for _, sso := range ssoProviders {
        if strings.Contains(location, sso) {
            return true
        }
    }
    return false
}

func (m *VulnModule) defineChecks() []sensitivePathCheck {
    return []sensitivePathCheck{
        {
            Path: "/.env", Severity: "high", Description: "Environment file with credentials",
            SkipRedirects: true, MinBodySize: 10,
            BodyValidator: func(body []byte) bool {
                return regexp.MustCompile(`(?m)^[A-Z_]{2,}=.+`).Match(body)
            },
        },
        {
            Path: "/.git/config", Severity: "high", Description: "Git repository config exposed",
            SkipRedirects: true, MinBodySize: 30,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "[core]") || strings.Contains(s, "[remote")
            },
        },
        {
            Path: "/.git/HEAD", Severity: "high", Description: "Git HEAD reference exposed",
            SkipRedirects: true, MinBodySize: 10,
            BodyValidator: func(body []byte) bool {
                s := strings.TrimSpace(string(body))
                // SHA-1 (40 hex) or SHA-256 (64 hex) detached HEAD, or a symbolic ref.
                return strings.HasPrefix(s, "ref: refs/") ||
                    regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(s) ||
                    regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(s)
            },
        },
        {
            Path: "/phpinfo.php", Severity: "high", Description: "PHP info page exposed",
            SkipRedirects: true, MinBodySize: 500,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "PHP Version") || strings.Contains(s, "phpinfo()")
            },
        },
        {
            Path: "/info.php", Severity: "high", Description: "PHP info page exposed",
            SkipRedirects: true, MinBodySize: 500,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "PHP Version") || strings.Contains(s, "phpinfo()")
            },
        },
        {
            Path: "/wp-config.php.bak", Severity: "high", Description: "WordPress config backup",
            SkipRedirects: true, MinBodySize: 100,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "DB_NAME") || strings.Contains(s, "DB_PASSWORD") ||
                    strings.Contains(s, "table_prefix")
            },
        },
        {
            Path: "/actuator/env", Severity: "high", Description: "Spring Actuator environment variables",
            SkipRedirects: true, MinBodySize: 50,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "activeProfiles") || strings.Contains(s, "propertySources") ||
                    strings.Contains(s, "\"property\"")
            },
        },
        {
            Path: "/.svn/entries", Severity: "high", Description: "SVN repository exposed",
            SkipRedirects: true, MinBodySize: 10,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return regexp.MustCompile(`^\d+`).MatchString(strings.TrimSpace(s)) ||
                    (strings.Contains(s, "dir") && strings.Contains(s, "svn"))
            },
        },
        {
            Path: "/.htpasswd", Severity: "high", Description: "Apache password file exposed",
            SkipRedirects: true, MinBodySize: 10,
            BodyValidator: func(body []byte) bool {
                return regexp.MustCompile(`^[a-zA-Z0-9_-]+:\$`).Match(body) ||
                    regexp.MustCompile(`^[a-zA-Z0-9_-]+:\{`).Match(body)
            },
        },
        {
            Path: "/server-status", Severity: "medium", Description: "Apache server-status exposed",
            SkipRedirects: true, MinBodySize: 200,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "Apache Server Status") || strings.Contains(s, "Server uptime") ||
                    strings.Contains(s, "requests/sec")
            },
        },
        {
            Path: "/server-info", Severity: "medium", Description: "Apache server-info exposed",
            SkipRedirects: true, MinBodySize: 200,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "Apache Server Information") || strings.Contains(s, "Server Settings")
            },
        },
        {
            Path: "/actuator", Severity: "medium", Description: "Spring Actuator base endpoint",
            SkipRedirects: true, MinBodySize: 20,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "\"_links\"") || strings.Contains(s, "actuator")
            },
        },
        {
            Path: "/actuator/health", Severity: "medium", Description: "Spring Actuator health endpoint",
            SkipRedirects: true, MinBodySize: 10,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "\"status\"") && (strings.Contains(s, "UP") || strings.Contains(s, "DOWN"))
            },
        },
        {
            Path: "/swagger-ui.html", Severity: "medium", Description: "Swagger API documentation exposed",
            SkipRedirects: true, MinBodySize: 100,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "swagger") || strings.Contains(s, "Swagger") ||
                    strings.Contains(s, "api-docs")
            },
        },
        {
            Path: "/swagger/v1/swagger.json", Severity: "medium", Description: "Swagger JSON spec exposed",
            SkipRedirects: true, MinBodySize: 50,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "\"swagger\"") || strings.Contains(s, "\"openapi\"") ||
                    strings.Contains(s, "\"paths\"")
            },
        },
        {
            Path: "/api-docs", Severity: "medium", Description: "API documentation exposed",
            SkipRedirects: true, MinBodySize: 50,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "\"swagger\"") || strings.Contains(s, "\"openapi\"") ||
                    strings.Contains(s, "\"info\"")
            },
        },
        {
            Path: "/graphql", Severity: "medium", Description: "GraphQL endpoint exposed",
            SkipRedirects: true, MinBodySize: 20,
            BodyValidator: func(body []byte) bool {
                s := strings.ToLower(string(body))
                return strings.Contains(s, "graphql") || strings.Contains(s, "\"data\"") ||
                    strings.Contains(s, "\"errors\"") || strings.Contains(s, "query")
            },
        },
        {
            Path: "/graphiql", Severity: "medium", Description: "GraphiQL IDE exposed",
            SkipRedirects: true, MinBodySize: 100,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "graphiql") || strings.Contains(s, "GraphiQL")
            },
        },
        {
            Path: "/.htaccess", Severity: "medium", Description: "Apache config file exposed",
            SkipRedirects: true, MinBodySize: 10,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "RewriteRule") || strings.Contains(s, "Deny from") ||
                    strings.Contains(s, "Allow from") || strings.Contains(s, "AuthType") ||
                    strings.Contains(s, "DirectoryIndex")
            },
        },
        {
            Path: "/web.config", Severity: "medium", Description: "IIS/ASP.NET config exposed",
            SkipRedirects: true, MinBodySize: 50,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "<configuration") || strings.Contains(s, "<system.web") ||
                    strings.Contains(s, "connectionStrings")
            },
        },
        {
            Path: "/.DS_Store", Severity: "medium", Description: "macOS directory metadata exposed",
            SkipRedirects: true, MinBodySize: 8,
            BodyValidator: func(body []byte) bool {
                return len(body) >= 8 && body[0] == 0x00 && body[1] == 0x00 && body[2] == 0x00 && body[3] == 0x01
            },
        },
        {
            Path: "/elmah.axd", Severity: "medium", Description: "ASP.NET error log exposed",
            SkipRedirects: true, MinBodySize: 100,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "Error Log") || strings.Contains(s, "ELMAH") ||
                    strings.Contains(s, "Exception")
            },
        },
        {
            Path: "/trace.axd", Severity: "medium", Description: "ASP.NET trace log exposed",
            SkipRedirects: true, MinBodySize: 100,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "Application Trace") || strings.Contains(s, "Request Details")
            },
        },
        {
            Path: "/crossdomain.xml", Severity: "medium", Description: "Permissive crossdomain policy",
            SkipRedirects: true, MinBodySize: 30,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "cross-domain-policy") &&
                    strings.Contains(s, "domain=\"*\"")
            },
        },
        {
            Path: "/clientaccesspolicy.xml", Severity: "medium", Description: "Permissive Silverlight policy",
            SkipRedirects: true, MinBodySize: 30,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "access-policy") && strings.Contains(s, "*")
            },
        },
        {
            Path: "/robots.txt", Severity: "info", Description: "Robots.txt (may reveal hidden paths)",
            SkipRedirects: true, MinBodySize: 10,
            BodyValidator: func(body []byte) bool {
                s := strings.ToLower(string(body))
                return strings.Contains(s, "user-agent") || strings.Contains(s, "disallow") ||
                    strings.Contains(s, "sitemap")
            },
        },
        {
            Path: "/sitemap.xml", Severity: "info", Description: "Sitemap reveals URL structure",
            SkipRedirects: true, MinBodySize: 50,
            BodyValidator: func(body []byte) bool {
                s := string(body)
                return strings.Contains(s, "<urlset") || strings.Contains(s, "<sitemapindex") ||
                    strings.Contains(s, "<loc>")
            },
        },
        {
            Path: "/.well-known/security.txt", Severity: "info", Description: "Security contact information",
            SkipRedirects: true, MinBodySize: 20,
            BodyValidator: func(body []byte) bool {
                s := strings.ToLower(string(body))
                return strings.Contains(s, "contact:") || strings.Contains(s, "policy:")
            },
        },
    }
}

// ── HTTP Helpers ─────────────────────────────────────────

func (m *VulnModule) doRequest(ctx context.Context, client *http.Client, url string) (*http.Response, []byte, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, nil, err
    }
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    req.Header.Set("Accept", "*/*")

    resp, err := client.Do(req)
    if err != nil {
        return nil, nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
    if err != nil {
        return resp, nil, err
    }
    return resp, body, nil
}

// ── Utility ──────────────────────────────────────────────

func randomString(n int) string {
    bytes := make([]byte, n/2+1)
    rand.Read(bytes)
    return hex.EncodeToString(bytes)[:n]
}

func hashBody(body []byte) string {
    sum := sha256.Sum256(body)
    return hex.EncodeToString(sum[:])
}

func firstNonEmpty(vals ...string) string {
    for _, v := range vals {
        if strings.TrimSpace(v) != "" {
            return v
        }
    }
    return ""
}

func abs(x int) int {
    if x < 0 {
        return -x
    }
    return x
}
