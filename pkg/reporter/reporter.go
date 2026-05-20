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

func (r *Reporter) buildData() ReportData {
    findings := r.state.GetFindings()
    stats := r.state.GetStats()
    start := r.state.GetStartTime()
    end := r.state.GetEndTime()
    if end.IsZero() {
        end = time.Now()
    }

    d := ReportData{
        Title:       fmt.Sprintf("ReconStorm Report — %s", strings.Join(r.cfg.Domains, ", ")),
        GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
        ScanStatus:  string(r.state.State.Status),
        Duration:    end.Sub(start).Round(time.Second).String(),
        Domains:     r.cfg.Domains,
        Stats:       stats,
        Modules:     r.state.State.Modules,
        AllFindings: findings,
    }

    for _, f := range findings {
        switch strings.ToLower(f.Severity) {
        case "critical":
            d.CriticalFindings = append(d.CriticalFindings, f)
        case "high":
            d.HighFindings = append(d.HighFindings, f)
        case "medium":
            d.MediumFindings = append(d.MediumFindings, f)
        case "low":
            d.LowFindings = append(d.LowFindings, f)
        default:
            d.InfoFindings = append(d.InfoFindings, f)
        }

        switch f.Type {
        case "subdomain":
            d.Subdomains = append(d.Subdomains, f)
        case "open_port":
            d.OpenPorts = append(d.OpenPorts, f)
        case "web_server":
            d.WebServers = append(d.WebServers, f)
        case "vulnerability", "vuln":
            d.Vulnerabilities = append(d.Vulnerabilities, f)
        case "secret":
            d.Secrets = append(d.Secrets, f)
        }
    }

    return d
}

func (r *Reporter) Generate() error {
    dir := filepath.Join(r.cfg.OutputDir, "reports")
    os.MkdirAll(dir, 0755)
    data := r.buildData()

    f := r.cfg.ReportFormat
    if f == "all" || strings.Contains(f, "json") {
        r.genJSON(dir, data)
    }
    if f == "all" || strings.Contains(f, "markdown") {
        r.genMarkdown(dir, data)
    }
    if f == "all" || strings.Contains(f, "html") {
        r.genHTML(dir, data)
    }
    return nil
}

func (r *Reporter) genJSON(dir string, d ReportData) {
    path := filepath.Join(dir, "report.json")
    data, err := json.MarshalIndent(d, "", "  ")
    if err != nil {
        r.log.Error("JSON error: %v", err)
        return
    }
    os.WriteFile(path, data, 0644)
    r.log.Success("  JSON report: %s", path)
}

func (r *Reporter) genMarkdown(dir string, d ReportData) {
    path := filepath.Join(dir, "report.md")
    f, err := os.Create(path)
    if err != nil {
        r.log.Error("Markdown error: %v", err)
        return
    }
    defer f.Close()

    w := func(format string, args ...interface{}) {
        fmt.Fprintf(f, format+"\n", args...)
    }

    w("# 🔱 ReconStorm Report")
    w("")
    w("**Generated:** %s", d.GeneratedAt)
    w("**Status:** %s | **Duration:** %s", d.ScanStatus, d.Duration)
    w("**Domains:** %s", strings.Join(d.Domains, ", "))
    w("**Repository:** [recon-storm](https://github.com/H3llKa1ser/recon-storm)")
    w("")

    w("## 📊 Summary")
    w("")
    w("| Metric | Count |")
    w("|--------|-------|")
    w("| Subdomains | %d |", d.Stats.TotalSubdomains)
    w("| Live Hosts | %d |", d.Stats.TotalLiveHosts)
    w("| Open Ports | %d |", d.Stats.TotalOpenPorts)
    w("| Endpoints | %d |", d.Stats.TotalEndpoints)
    w("| Vulnerabilities | %d |", d.Stats.TotalVulns)
    w("| Secrets | %d |", d.Stats.TotalSecrets)
    w("| Screenshots | %d |", d.Stats.TotalScreenshots)
    w("")

    w("## 🚨 Severity")
    w("")
    w("| Severity | Count |")
    w("|----------|-------|")
    w("| 🔴 Critical | %d |", len(d.CriticalFindings))
    w("| 🟠 High | %d |", len(d.HighFindings))
    w("| 🟡 Medium | %d |", len(d.MediumFindings))
    w("| 🔵 Low | %d |", len(d.LowFindings))
    w("| ⚪ Info | %d |", len(d.InfoFindings))
    w("")

    writeFindings := func(title string, findings []state.Finding) {
        if len(findings) == 0 {
            return
        }
        w("### %s", title)
        w("")
        for _, f := range findings {
            w("- **[%s]** %s (Source: %s)", f.Type, f.Value, f.Source)
        }
        w("")
    }

    writeFindings("🔴 Critical", d.CriticalFindings)
    writeFindings("🟠 High", d.HighFindings)
    writeFindings("🟡 Medium", d.MediumFindings)

    w("## ⚙️ Modules")
    w("")
    w("| Module | Status | Error |")
    w("|--------|--------|-------|")
    names := make([]string, 0, len(d.Modules))
    for n := range d.Modules {
        names = append(names, n)
    }
    sort.Strings(names)
    for _, n := range names {
        mod := d.Modules[n]
        w("| %s | %s | %s |", n, mod.Status, mod.Error)
    }
    w("")

    if len(d.Subdomains) > 0 {
        w("## 🌐 Subdomains (%d)", len(d.Subdomains))
        w("")
        w("```")
        for _, s := range d.Subdomains {
            w("%s", s.Value)
        }
        w("```")
        w("")
    }

    if len(d.Vulnerabilities) > 0 {
        w("## 🐛 Vulnerabilities (%d)", len(d.Vulnerabilities))
        w("")
        for _, v := range d.Vulnerabilities {
            w("- **[%s]** %s", strings.ToUpper(v.Severity), v.Value)
        }
        w("")
    }

    if len(d.Secrets) > 0 {
        w("## 🔑 Secrets (%d)", len(d.Secrets))
        w("")
        for _, s := range d.Secrets {
            w("- %s (in: %s)", s.Value, s.Metadata["file"])
        }
        w("")
    }

    r.log.Success("  Markdown report: %s", path)
}

func (r *Reporter) genHTML(dir string, d ReportData) {
    path := filepath.Join(dir, "report.html")
    tmpl, err := template.New("report").Parse(htmlTemplate)
    if err != nil {
        r.log.Error("HTML template error: %v", err)
        return
    }
    f, err := os.Create(path)
    if err != nil {
        r.log.Error("HTML create error: %v", err)
        return
    }
    defer f.Close()
    if err := tmpl.Execute(f, d); err != nil {
        r.log.Error("HTML render error: %v", err)
        return
    }
    r.log.Success("  HTML report: %s", path)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Title}}</title>
<style>
:root{--bg:#0a0e17;--sf:#111827;--bd:#1f2937;--tx:#e5e7eb;--mt:#9ca3af;--ac:#3b82f6;--cr:#ef4444;--hi:#f97316;--md:#eab308;--lo:#3b82f6;--in:#6b7280}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--tx);padding:2rem}
.c{max-width:1200px;margin:0 auto}
h1{font-size:2rem;margin-bottom:.5rem;background:linear-gradient(135deg,#3b82f6,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
h2{font-size:1.4rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--bd)}
.meta{color:var(--mt);margin-bottom:2rem}.meta span{margin-right:2rem}.meta a{color:var(--ac);text-decoration:none}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin:1rem 0}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:1.2rem;text-align:center}
.card .n{font-size:2rem;font-weight:700}.card .l{color:var(--mt);font-size:.85rem;margin-top:.3rem}
.sb{display:flex;gap:.5rem;margin:1rem 0;flex-wrap:wrap}
.sv{padding:.4rem 1rem;border-radius:20px;font-size:.85rem;font-weight:600}
.sv-cr{background:rgba(239,68,68,.2);color:var(--cr);border:1px solid var(--cr)}
.sv-hi{background:rgba(249,115,22,.2);color:var(--hi);border:1px solid var(--hi)}
.sv-md{background:rgba(234,179,8,.2);color:var(--md);border:1px solid var(--md)}
.sv-lo{background:rgba(59,130,246,.2);color:var(--lo);border:1px solid var(--lo)}
.sv-in{background:rgba(107,114,128,.2);color:var(--in);border:1px solid var(--in)}
table{width:100%;border-collapse:collapse;margin:1rem 0}
th,td{padding:.7rem 1rem;text-align:left;border-bottom:1px solid var(--bd)}
th{background:var(--sf);color:var(--mt);font-size:.85rem;text-transform:uppercase}
tr:hover{background:rgba(59,130,246,.05)}
.f{background:var(--sf);border:1px solid var(--bd);border-radius:6px;padding:1rem;margin:.5rem 0;border-left:3px solid}
.f.cr{border-left-color:var(--cr)}.f.hi{border-left-color:var(--hi)}.f.md{border-left-color:var(--md)}
.f .t{font-size:.75rem;color:var(--mt);text-transform:uppercase}
.f .v{margin:.3rem 0;word-break:break-all}.f .s{font-size:.8rem;color:var(--ac)}
code{background:var(--sf);padding:.2rem .5rem;border-radius:3px;font-size:.9rem}
.ib{background:rgba(249,115,22,.1);border:1px solid var(--hi);border-radius:8px;padding:1rem;margin:1rem 0;color:var(--hi);text-align:center}
</style>
</head>
<body>
<div class="c">
<h1>🔱 ReconStorm Report</h1>
<div class="meta">
<span>📅 {{.GeneratedAt}}</span><span>⏱️ {{.Duration}}</span>
<span>● {{.ScanStatus}}</span>
<span><a href="https://github.com/H3llKa1ser/recon-storm">recon-storm</a></span>
</div>

{{if eq .ScanStatus "interrupted"}}<div class="ib">⚠️ Scan interrupted — partial results below.</div>{{end}}

<h2>📊 Summary</h2>
<div class="cards">
<div class="card"><div class="n">{{.Stats.TotalSubdomains}}</div><div class="l">Subdomains</div></div>
<div class="card"><div class="n">{{.Stats.TotalLiveHosts}}</div><div class="l">Live Hosts</div></div>
<div class="card"><div class="n">{{.Stats.TotalOpenPorts}}</div><div class="l">Open Ports</div></div>
<div class="card"><div class="n">{{.Stats.TotalEndpoints}}</div><div class="l">Endpoints</div></div>
<div class="card"><div class="n">{{.Stats.TotalVulns}}</div><div class="l">Vulns</div></div>
<div class="card"><div class="n">{{.Stats.TotalSecrets}}</div><div class="l">Secrets</div></div>
<div class="card"><div class="n">{{.Stats.TotalScreenshots}}</div><div class="l">Screenshots</div></div>
</div>

<h2>🚨 Severity</h2>
<div class="sb">
<span class="sv sv-cr">Critical: {{len .CriticalFindings}}</span>
<span class="sv sv-hi">High: {{len .HighFindings}}</span>
<span class="sv sv-md">Medium: {{len .MediumFindings}}</span>
<span class="sv sv-lo">Low: {{len .LowFindings}}</span>
<span class="sv sv-in">Info: {{len .InfoFindings}}</span>
</div>

{{if .CriticalFindings}}<h2>🔴 Critical</h2>{{range .CriticalFindings}}<div class="f cr"><div class="t">{{.Type}}</div><div class="v">{{.Value}}</div><div class="s">{{.Source}} | {{.Domain}}</div></div>{{end}}{{end}}
{{if .HighFindings}}<h2>🟠 High</h2>{{range .HighFindings}}<div class="f hi"><div class="t">{{.Type}}</div><div class="v">{{.Value}}</div><div class="s">{{.Source}} | {{.Domain}}</div></div>{{end}}{{end}}
{{if .MediumFindings}}<h2>🟡 Medium</h2>{{range .MediumFindings}}<div class="f md"><div class="t">{{.Type}}</div><div class="v">{{.Value}}</div><div class="s">{{.Source}} | {{.Domain}}</div></div>{{end}}{{end}}

{{if .Vulnerabilities}}<h2>🐛 Vulnerabilities</h2>
<table><tr><th>Severity</th><th>Finding</th><th>Domain</th><th>Source</th></tr>
{{range .Vulnerabilities}}<tr><td><span class="sv sv-{{.Severity}}">{{.Severity}}</span></td><td>{{.Value}}</td><td>{{.Domain}}</td><td>{{.Source}}</td></tr>{{end}}
</table>{{end}}

{{if .Secrets}}<h2>🔑 Secrets</h2>
<table><tr><th>Secret</th><th>Domain</th><th>Source</th></tr>
{{range .Secrets}}<tr><td><code>{{.Value}}</code></td><td>{{.Domain}}</td><td>{{.Source}}</td></tr>{{end}}
</table>{{end}}

<h2>⚙️ Modules</h2>
<table><tr><th>Module</th><th>Status</th><th>Error</th></tr>
{{range $n, $m := .Modules}}<tr><td>{{$n}}</td><td>{{$m.Status}}</td><td>{{$m.Error}}</td></tr>{{end}}
</table>

{{if .Subdomains}}<h2>🌐 Subdomains ({{len .Subdomains}})</h2>
<table><tr><th>Subdomain</th><th>Source</th></tr>
{{range .Subdomains}}<tr><td>{{.Value}}</td><td>{{.Source}}</td></tr>{{end}}
</table>{{end}}

<p style="margin-top:3rem;color:var(--mt);text-align:center;font-size:.85rem">
<a href="https://github.com/H3llKa1ser/recon-storm" style="color:var(--ac)">ReconStorm v2.0</a> — H3llKa1ser
</p>
</div>
</body>
</html>`
