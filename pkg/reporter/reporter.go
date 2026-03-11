package reporter

import (
    "encoding/json"
    "fmt"
    "html/template"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

type Reporter struct {
    cfg   *config.Config
    state *state.Manager
    log   *logger.Logger
}

func New(cfg *config.Config, sm *state.Manager, log *logger.Logger) *Reporter {
    return &Reporter{cfg: cfg, state: sm, log: log}
}

type ReportData struct {
    Title            string
    GeneratedAt      string
    ScanStatus       string
    Duration         string
    Domains          []string
    Stats            state.ScanStats
    Modules          map[string]*state.ModuleResult
    CriticalFindings []state.Finding
    HighFindings     []state.Finding
    MediumFindings   []state.Finding
    LowFindings      []state.Finding
    InfoFindings     []state.Finding
    Subdomains       []state.Finding
    OpenPorts        []state.Finding
    WebServers       []state.Finding
    Vulnerabilities  []state.Finding
    Secrets          []state.Finding
    AllFindings      []state.Finding
}

func (r *Reporter) buildReportData() ReportData {
    findings := r.state.GetFindings()
    stats := r.state.GetStats()

    startTime := r.state.GetStartTime()
    endTime := r.state.GetEndTime()
    if endTime.IsZero() {
        endTime = time.Now()
    }

    data := ReportData{
        Title:       fmt.Sprintf("ReconStorm Report — %s", strings.Join(r.cfg.Domains, ", ")),
        GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
        ScanStatus:  string(r.state.State.Status),
        Duration:    endTime.Sub(startTime).Round(time.Second).String(),
        Domains:     r.cfg.Domains,
        Stats:       stats,
        Modules:     r.state.State.Modules,
        AllFindings: findings,
    }

    for _, f := range findings {
        switch strings.ToLower(f.Severity) {
        case "critical":
            data.CriticalFindings = append(data.CriticalFindings, f)
        case "high":
            data.HighFindings = append(data.HighFindings, f)
        case "medium":
            data.MediumFindings = append(data.MediumFindings, f)
        case "low":
            data.LowFindings = append(data.LowFindings, f)
        default:
            data.InfoFindings = append(data.InfoFindings, f)
        }

        switch f.Type {
        case "subdomain":
            data.Subdomains = append(data.Subdomains, f)
        case "open_port":
            data.OpenPorts = append(data.OpenPorts, f)
        case "web_server":
            data.WebServers = append(data.WebServers, f)
        case "vulnerability", "vuln":
            data.Vulnerabilities = append(data.Vulnerabilities, f)
        case "secret":
            data.Secrets = append(data.Secrets, f)
        }
    }

    return data
}

func (r *Reporter) Generate() error {
    reportDir := filepath.Join(r.cfg.OutputDir, "reports")
    os.MkdirAll(reportDir, 0755)

    data := r.buildReportData()

    format := r.cfg.ReportFormat
    if format == "all" || strings.Contains(format, "json") {
        if err := r.generateJSON(reportDir, data); err != nil {
            r.log.Error("JSON report error: %v", err)
        }
    }
    if format == "all" || strings.Contains(format, "markdown") {
        if err := r.generateMarkdown(reportDir, data); err != nil {
            r.log.Error("Markdown report error: %v", err)
        }
    }
    if format == "all" || strings.Contains(format, "html") {
        if err := r.generateHTML(reportDir, data); err != nil {
            r.log.Error("HTML report error: %v", err)
        }
    }

    return nil
}

// ── JSON Report ──────────────────────────────────────────

func (r *Reporter) generateJSON(dir string, data ReportData) error {
    path := filepath.Join(dir, "report.json")
    jsonData, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        return err
    }
    r.log.Success("  JSON report: %s", path)
    return os.WriteFile(path, jsonData, 0644)
}

// ── Markdown Report ──────────────────────────────────────

func (r *Reporter) generateMarkdown(dir string, data ReportData) error {
    path := filepath.Join(dir, "report.md")
    f, err := os.Create(path)
    if err != nil {
        return err
    }
    defer f.Close()

    w := func(format string, args ...interface{}) {
        fmt.Fprintf(f, format+"\n", args...)
    }

    w("# 🔱 ReconStorm Report")
    w("")
    w("**Generated:** %s", data.GeneratedAt)
    w("**Status:** %s", data.ScanStatus)
    w("**Duration:** %s", data.Duration)
    w("**Domains:** %s", strings.Join(data.Domains, ", "))
    w("**Repository:** [ReconStorm](https://github.com/H3llKa1ser/recon-storm)")
    w("")

    w("## 📊 Summary")
    w("")
    w("| Metric | Count |")
    w("|--------|-------|")
    w("| Subdomains | %d |", data.Stats.TotalSubdomains)
    w("| Live Hosts | %d |", data.Stats.TotalLiveHosts)
    w("| Open Ports | %d |", data.Stats.TotalOpenPorts)
    w("| Endpoints | %d |", data.Stats.TotalEndpoints)
    w("| Vulnerabilities | %d |", data.Stats.TotalVulns)
    w("| Secrets Found | %d |", data.Stats.TotalSecrets)
    w("| Screenshots | %d |", data.Stats.TotalScreenshots)
    w("")

    w("## 🚨 Findings by Severity")
    w("")
    w("| Severity | Count |")
    w("|----------|-------|")
    w("| 🔴 Critical | %d |", len(data.CriticalFindings))
    w("| 🟠 High | %d |", len(data.HighFindings))
    w("| 🟡 Medium | %d |", len(data.MediumFindings))
    w("| 🔵 Low | %d |", len(data.LowFindings))
    w("| ⚪ Info | %d |", len(data.InfoFindings))
    w("")

    if len(data.CriticalFindings) > 0 {
        w("### 🔴 Critical Findings")
        w("")
        for _, f := range data.CriticalFindings {
            w("- **[%s]** %s (Source: %s)", f.Type, f.Value, f.Source)
        }
        w("")
    }

    if len(data.HighFindings) > 0 {
        w("### 🟠 High Findings")
        w("")
        for _, f := range data.HighFindings {
            w("- **[%s]** %s (Source: %s)", f.Type, f.Value, f.Source)
        }
        w("")
    }

    if len(data.MediumFindings) > 0 {
        w("### 🟡 Medium Findings")
        w("")
        for _, f := range data.MediumFindings {
            w("- **[%s]** %s (Source: %s)", f.Type, f.Value, f.Source)
        }
        w("")
    }

    w("## ⚙️ Module Status")
    w("")
    w("| Module | Status | Duration | Items |")
    w("|--------|--------|----------|-------|")

    moduleNames := make([]string, 0, len(data.Modules))
    for name := range data.Modules {
        moduleNames = append(moduleNames, name)
    }
    sort.Strings(moduleNames)

    for _, name := range moduleNames {
        mod := data.Modules[name]
        dur := mod.EndTime.Sub(mod.StartTime).Round(time.Millisecond).String()
        errStr := ""
        if mod.Error != "" {
            errStr = " ⚠️"
        }
        w("| %s | %s%s | %s | %d |", name, mod.Status, errStr, dur, mod.ItemCount)
    }
    w("")

    if len(data.Subdomains) > 0 {
        w("## 🌐 Subdomains (%d)", len(data.Subdomains))
        w("")
        w("```")
        for _, s := range data.Subdomains {
            w("%s", s.Value)
        }
        w("```")
        w("")
    }

    if len(data.Vulnerabilities) > 0 {
        w("## 🐛 Vulnerabilities (%d)", len(data.Vulnerabilities))
        w("")
        for _, v := range data.Vulnerabilities {
            w("- **[%s]** %s", strings.ToUpper(v.Severity), v.Value)
            if v.Metadata["template_id"] != "" {
                w("  - Template: `%s`", v.Metadata["template_id"])
            }
        }
        w("")
    }

    if len(data.Secrets) > 0 {
        w("## 🔑 Secrets (%d)", len(data.Secrets))
        w("")
        for _, s := range data.Secrets {
            w("- **%s** (found in: %s)", s.Value, s.Metadata["file"])
        }
        w("")
    }

    r.log.Success("  Markdown report: %s", path)
    return nil
}

// ── HTML Report ──────────────────────────────────────────

func (r *Reporter) generateHTML(dir string, data ReportData) error {
    path := filepath.Join(dir, "report.html")

    tmpl, err := template.New("report").Parse(htmlTemplate)
    if err != nil {
        return fmt.Errorf("template parse error: %w", err)
    }

    f, err := os.Create(path)
    if err != nil {
        return err
    }
    defer f.Close()

    if err := tmpl.Execute(f, data); err != nil {
        return fmt.Errorf("template execute error: %w", err)
    }

    r.log.Success("  HTML report: %s", path)
    return nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Title}}</title>
<style>
  :root {
    --bg: #0a0e17; --surface: #111827; --border: #1f2937;
    --text: #e5e7eb; --muted: #9ca3af; --accent: #3b82f6;
    --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #3b82f6; --info: #6b7280;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 2rem; margin-bottom: 0.5rem; background: linear-gradient(135deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  h2 { font-size: 1.4rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
  .meta { color: var(--muted); margin-bottom: 2rem; }
  .meta span { margin-right: 2rem; }
  .meta a { color: var(--accent); text-decoration: none; }
  .status-completed { color: #22c55e; } .status-interrupted { color: var(--high); } .status-failed { color: var(--critical); }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }
  .card .number { font-size: 2rem; font-weight: 700; }
  .card .label { color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; }
  .severity-bar { display: flex; gap: 0.5rem; margin: 1rem 0; flex-wrap: wrap; }
  .sev-badge { padding: 0.4rem 1rem; border-radius: 20px; font-size: 0.85rem; font-weight: 600; }
  .sev-critical { background: rgba(239,68,68,0.2); color: var(--critical); border: 1px solid var(--critical); }
  .sev-high { background: rgba(249,115,22,0.2); color: var(--high); border: 1px solid var(--high); }
  .sev-medium { background: rgba(234,179,8,0.2); color: var(--medium); border: 1px solid var(--medium); }
  .sev-low { background: rgba(59,130,246,0.2); color: var(--low); border: 1px solid var(--low); }
  .sev-info { background: rgba(107,114,128,0.2); color: var(--info); border: 1px solid var(--info); }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { padding: 0.7rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--surface); color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }
  tr:hover { background: rgba(59,130,246,0.05); }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin: 0.5rem 0; border-left: 3px solid; }
  .finding.critical { border-left-color: var(--critical); }
  .finding.high { border-left-color: var(--high); }
  .finding.medium { border-left-color: var(--medium); }
  .finding .type { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; }
  .finding .value { margin: 0.3rem 0; word-break: break-all; }
  .finding .source { font-size: 0.8rem; color: var(--accent); }
  code { background: var(--surface); padding: 0.2rem 0.5rem; border-radius: 3px; font-size: 0.9rem; }
  .interrupted-banner { background: rgba(249,115,22,0.1); border: 1px solid var(--high); border-radius: 8px; padding: 1rem; margin: 1rem 0; color: var(--high); text-align: center; }
</style>
</head>
<body>
<div class="container">
  <h1>🔱 ReconStorm Report</h1>
  <div class="meta">
    <span>📅 {{.GeneratedAt}}</span>
    <span>⏱️ {{.Duration}}</span>
    <span class="status-{{.ScanStatus}}">● {{.ScanStatus}}</span>
    <span><a href="https://github.com/H3llKa1ser/recon-storm" target="_blank">ReconStorm</a></span>
  </div>

  {{if eq .ScanStatus "interrupted"}}
  <div class="interrupted-banner">
    ⚠️ This scan was interrupted. Report contains partial results collected before interruption.
  </div>
  {{end}}

  <h2>📊 Summary</h2>
  <div class="cards">
    <div class="card"><div class="number">{{.Stats.TotalSubdomains}}</div><div class="label">Subdomains</div></div>
    <div class="card"><div class="number">{{.Stats.TotalLiveHosts}}</div><div class="label">Live Hosts</div></div>
    <div class="card"><div class="number">{{.Stats.TotalOpenPorts}}</div><div class="label">Open Ports</div></div>
    <div class="card"><div class="number">{{.Stats.TotalEndpoints}}</div><div class="label">Endpoints</div></div>
    <div class="card"><div class="number">{{.Stats.TotalVulns}}</div><div class="label">Vulnerabilities</div></div>
    <div class="card"><div class="number">{{.Stats.TotalSecrets}}</div><div class="label">Secrets</div></div>
    <div class="card"><div class="number">{{.Stats.TotalScreenshots}}</div><div class="label">Screenshots</div></div>
  </div>

  <h2>🚨 Severity Breakdown</h2>
  <div class="severity-bar">
    <span class="sev-badge sev-critical">Critical: {{len .CriticalFindings}}</span>
    <span class="sev-badge sev-high">High: {{len .HighFindings}}</span>
    <span class="sev-badge sev-medium">Medium: {{len .MediumFindings}}</span>
    <span class="sev-badge sev-low">Low: {{len .LowFindings}}</span>
    <span class="sev-badge sev-info">Info: {{len .InfoFindings}}</span>
  </div>

  {{if .CriticalFindings}}
  <h2>🔴 Critical Findings</h2>
  {{range .CriticalFindings}}
  <div class="finding critical">
    <div class="type">{{.Type}}</div>
    <div class="value">{{.Value}}</div>
    <div class="source">Source: {{.Source}} | Domain: {{.Domain}}</div>
  </div>
  {{end}}
  {{end}}

  {{if .HighFindings}}
  <h2>🟠 High Findings</h2>
  {{range .HighFindings}}
  <div class="finding high">
    <div class="type">{{.Type}}</div>
    <div class="value">{{.Value}}</div>
    <div class="source">Source: {{.Source}} | Domain: {{.Domain}}</div>
  </div>
  {{end}}
  {{end}}

  {{if .MediumFindings}}
  <h2>🟡 Medium Findings</h2>
  {{range .MediumFindings}}
  <div class="finding medium">
    <div class="type">{{.Type}}</div>
    <div class="value">{{.Value}}</div>
    <div class="source">Source: {{.Source}} | Domain: {{.Domain}}</div>
  </div>
  {{end}}
  {{end}}

  {{if .Vulnerabilities}}
  <h2>🐛 Vulnerabilities</h2>
  <table>
    <tr><th>Severity</th><th>Name</th><th>Location</th><th>Source</th></tr>
    {{range .Vulnerabilities}}
    <tr>
      <td><span class="sev-badge sev-{{.Severity}}">{{.Severity}}</span></td>
      <td>{{.Value}}</td>
      <td>{{.Domain}}</td>
      <td>{{.Source}}</td>
    </tr>
    {{end}}
  </table>
  {{end}}

  {{if .Secrets}}
  <h2>🔑 Secrets Found</h2>
  <table>
    <tr><th>Secret</th><th>Location</th><th>Source</th></tr>
    {{range .Secrets}}
    <tr>
      <td><code>{{.Value}}</code></td>
      <td>{{.Domain}}</td>
      <td>{{.Source}}</td>
    </tr>
    {{end}}
  </table>
  {{end}}

  <h2>⚙️ Module Status</h2>
  <table>
    <tr><th>Module</th><th>Status</th><th>Error</th></tr>
    {{range $name, $mod := .Modules}}
    <tr>
      <td>{{$name}}</td>
      <td class="status-{{$mod.Status}}">{{$mod.Status}}</td>
      <td>{{$mod.Error}}</td>
    </tr>
    {{end}}
  </table>

  <h2>🌐 Subdomains ({{len .Subdomains}})</h2>
  {{if .Subdomains}}
  <table>
    <tr><th>Subdomain</th><th>Source</th></tr>
    {{range .Subdomains}}
    <tr><td>{{.Value}}</td><td>{{.Source}}</td></tr>
    {{end}}
  </table>
  {{else}}
  <p style="color: var(--muted);">No subdomains discovered yet.</p>
  {{end}}

  <p style="margin-top: 3rem; color: var(--muted); text-align: center; font-size: 0.85rem;">
    Generated by <a href="https://github.com/H3llKa1ser/recon-storm" style="color: var(--accent);">ReconStorm v1.0</a> — Bug Bounty Recon Framework
  </p>
</div>
</body>
</html>`
