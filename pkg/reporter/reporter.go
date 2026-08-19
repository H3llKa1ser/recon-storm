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

// Screenshot pairs a captured image with the URL it belongs to (best-effort).
type Screenshot struct {
    RelPath string
    Label   string
}

type ReportData struct {
    Title            string
    GeneratedAt      string
    ScanStatus       string
    Duration         string
    Domains          []string
    Stats            state.ScanStats
    Modules          map[string]*state.ModuleResult
    ModuleNames      []string // sorted, for deterministic rendering
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
    TopFindings      []state.Finding // triage: worst-first, capped
    Screenshots      []Screenshot
}

// remediation returns a one-line "why this matters" for a finding type/value so
// the report is readable by someone who did not run the scan.
func remediation(f state.Finding) string {
    if d := f.Metadata["description"]; d != "" {
        return d
    }
    switch f.Type {
    case "subdomain":
        return "Enumerated hostname in scope; validate ownership and expand testing."
    case "dns_resolved":
        return "Resolvable host; a live attack surface for further probing."
    case "open_port":
        return "Reachable service; verify version and exposure."
    case "web_server":
        return "Live web application; candidate for deeper testing."
    case "vulnerability", "vuln":
        return "Reported by nuclei; confirm manually before triage."
    case "sensitive_file":
        return "Exposed file validated by content signature; review for data leakage."
    case "sensitive_endpoint":
        return "URL matched a sensitive pattern; inspect for exposure."
    case "secret":
        return "Potential credential in client-side code; rotate if valid."
    default:
        return ""
    }
}

// redactSecret masks a matched secret for report output, preserving only the
// last 4 characters so an analyst can correlate it against the source without
// the report itself carrying the live value.
func redactSecret(v string) string {
    v = strings.TrimSpace(v)
    if len(v) <= 4 {
        return strings.Repeat("•", len(v))
    }
    keep := v[len(v)-4:]
    maskLen := len(v) - 4
    if maskLen > 12 {
        maskLen = 12
    }
    return strings.Repeat("•", maskLen) + keep
}

// sevClass maps a severity string to the two-letter CSS class the stylesheet
// actually defines (cr/hi/md/lo/in). Previously the template interpolated the
// raw severity ("high" -> sv-high) which matched no class, leaving badges
// unstyled.
func sevClass(sev string) string {
    switch strings.ToLower(strings.TrimSpace(sev)) {
    case "critical":
        return "cr"
    case "high":
        return "hi"
    case "medium":
        return "md"
    case "low":
        return "lo"
    default:
        return "in"
    }
}

func (r *Reporter) buildData() ReportData {
    // Make headline numbers reproducible and consistent with the tables.
    r.state.RecomputeStats()

    findings := r.state.GetFindings()
    // Redact secret values in every generated report so a shared report.html /
    // .md / .json can't leak live credentials. The full value remains only in
    // the local working state.json. Redaction keeps the last 4 chars so an
    // analyst can still correlate against the source.
    for i := range findings {
        if findings[i].Type == "secret" {
            findings[i].Value = redactSecret(findings[i].Value)
        }
    }
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
        case "vulnerability", "vuln", "sensitive_file":
            d.Vulnerabilities = append(d.Vulnerabilities, f)
        case "secret":
            d.Secrets = append(d.Secrets, f)
        }
    }

    // Triage list: the actionable findings, worst-first, capped so the top of
    // the report answers "what should I look at first?".
    actionable := make([]state.Finding, 0)
    for _, f := range findings {
        switch strings.ToLower(f.Severity) {
        case "critical", "high", "medium":
            actionable = append(actionable, f)
        }
    }
    d.TopFindings = state.SortFindingsBySeverity(actionable)
    if len(d.TopFindings) > 15 {
        d.TopFindings = d.TopFindings[:15]
    }

    names := make([]string, 0, len(d.Modules))
    for n := range d.Modules {
        names = append(names, n)
    }
    sort.Strings(names)
    d.ModuleNames = names

    d.Screenshots = r.collectScreenshots()

    return d
}

// collectScreenshots walks each domain's screenshots directory for image files
// so the HTML report can render a visual-recon gallery. gowitness v2 writes PNGs
// directly; v3 nests them under a subdirectory, so we walk recursively.
func (r *Reporter) collectScreenshots() []Screenshot {
    var shots []Screenshot
    reportsDir := filepath.Join(r.cfg.OutputDir, "reports")
    for _, domain := range r.cfg.Domains {
        base := filepath.Join(r.cfg.OutputDir, domain, "screenshots")
        filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
            if err != nil || info == nil || info.IsDir() {
                return nil
            }
            ext := strings.ToLower(filepath.Ext(path))
            if ext != ".png" && ext != ".jpg" && ext != ".jpeg" {
                return nil
            }
            rel, rerr := filepath.Rel(reportsDir, path)
            if rerr != nil {
                rel = path
            }
            shots = append(shots, Screenshot{
                RelPath: filepath.ToSlash(rel),
                Label:   strings.TrimSuffix(filepath.Base(path), ext),
            })
            return nil
        })
    }
    sort.Slice(shots, func(i, j int) bool { return shots[i].Label < shots[j].Label })
    return shots
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
    w("")

    // Executive summary / triage — the first thing a reader should see.
    w("## 🎯 Triage — look at these first")
    w("")
    if len(d.TopFindings) == 0 {
        w("_No high or medium severity findings._")
    } else {
        for _, ff := range d.TopFindings {
            note := remediation(ff)
            if note != "" {
                note = " — " + note
            }
            w("- **[%s]** `%s` (%s)%s", strings.ToUpper(ff.Severity), ff.Value, ff.Source, note)
        }
    }
    w("")

    w("## 📊 Summary")
    w("")
    w("| Metric | Count |")
    w("|--------|-------|")
    w("| Subdomains | %d |", d.Stats.TotalSubdomains)
    w("| Live Hosts | %d |", d.Stats.TotalLiveHosts)
    w("| Open Ports | %d |", d.Stats.TotalOpenPorts)
    w("| Web Servers | %d |", len(d.WebServers))
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

    // Unified: render every non-empty severity bucket (previously Low/Info were
    // silently dropped from Markdown).
    writeFindings := func(title string, findings []state.Finding) {
        if len(findings) == 0 {
            return
        }
        w("### %s (%d)", title, len(findings))
        w("")
        for _, ff := range findings {
            note := remediation(ff)
            if note != "" {
                note = " — " + note
            }
            w("- **[%s]** %s (Source: %s)%s", ff.Type, ff.Value, ff.Source, note)
        }
        w("")
    }

    w("## Findings by severity")
    w("")
    writeFindings("🔴 Critical", d.CriticalFindings)
    writeFindings("🟠 High", d.HighFindings)
    writeFindings("🟡 Medium", d.MediumFindings)
    writeFindings("🔵 Low", d.LowFindings)
    writeFindings("⚪ Info", d.InfoFindings)

    w("## ⚙️ Modules")
    w("")
    w("| Module | Status | Detail |")
    w("|--------|--------|--------|")
    for _, n := range d.ModuleNames {
        mod := d.Modules[n]
        detail := mod.Error
        if detail == "" {
            detail = mod.SkipReason
        }
        w("| %s | %s | %s |", n, mod.Status, detail)
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

    if len(d.OpenPorts) > 0 {
        w("## 🔌 Open Ports (%d)", len(d.OpenPorts))
        w("")
        w("```")
        for _, p := range d.OpenPorts {
            w("%s", p.Value)
        }
        w("```")
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
    funcs := template.FuncMap{
        "sevClass":    sevClass,
        "remediation": remediation,
        "upper":       strings.ToUpper,
    }
    tmpl, err := template.New("report").Funcs(funcs).Parse(htmlTemplate)
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
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--tx);padding:2rem;line-height:1.5}
.c{max-width:1200px;margin:0 auto}
h1{font-size:2rem;margin-bottom:.5rem;background:linear-gradient(135deg,#3b82f6,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
h2{font-size:1.4rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--bd)}
.meta{color:var(--mt);margin-bottom:2rem}.meta span{margin-right:2rem}.meta a{color:var(--ac);text-decoration:none}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin:1rem 0}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:1.2rem;text-align:center}
.card .n{font-size:2rem;font-weight:700}.card .l{color:var(--mt);font-size:.85rem;margin-top:.3rem}
.sb{display:flex;gap:.5rem;margin:1rem 0;flex-wrap:wrap}
.sv{padding:.4rem 1rem;border-radius:20px;font-size:.85rem;font-weight:600;display:inline-block}
.sv-cr{background:rgba(239,68,68,.2);color:var(--cr);border:1px solid var(--cr)}
.sv-hi{background:rgba(249,115,22,.2);color:var(--hi);border:1px solid var(--hi)}
.sv-md{background:rgba(234,179,8,.2);color:var(--md);border:1px solid var(--md)}
.sv-lo{background:rgba(59,130,246,.2);color:var(--lo);border:1px solid var(--lo)}
.sv-in{background:rgba(107,114,128,.2);color:var(--in);border:1px solid var(--in)}
table{width:100%;border-collapse:collapse;margin:1rem 0}
th,td{padding:.7rem 1rem;text-align:left;border-bottom:1px solid var(--bd);vertical-align:top}
th{background:var(--sf);color:var(--mt);font-size:.85rem;text-transform:uppercase}
tr:hover{background:rgba(59,130,246,.05)}
.f{background:var(--sf);border:1px solid var(--bd);border-radius:6px;padding:1rem;margin:.5rem 0;border-left:3px solid}
.f.cr{border-left-color:var(--cr)}.f.hi{border-left-color:var(--hi)}.f.md{border-left-color:var(--md)}.f.lo{border-left-color:var(--lo)}.f.in{border-left-color:var(--in)}
.f .t{font-size:.75rem;color:var(--mt);text-transform:uppercase}
.f .v{margin:.3rem 0;word-break:break-all}.f .s{font-size:.8rem;color:var(--ac)}.f .r{font-size:.82rem;color:var(--mt);margin-top:.3rem}
code{background:var(--sf);padding:.2rem .5rem;border-radius:3px;font-size:.9rem}
.ib{background:rgba(249,115,22,.1);border:1px solid var(--hi);border-radius:8px;padding:1rem;margin:1rem 0;color:var(--hi);text-align:center}
details{background:var(--sf);border:1px solid var(--bd);border-radius:8px;margin:1rem 0;padding:0 1rem}
details>summary{cursor:pointer;padding:1rem;font-weight:600;list-style:none}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:'▸ ';color:var(--ac)}
details[open]>summary::before{content:'▾ '}
.triage{background:var(--sf);border:1px solid var(--hi);border-radius:8px;padding:1rem 1.2rem;margin:1rem 0}
.triage ol{margin:.5rem 0 0 1.2rem}.triage li{margin:.35rem 0;word-break:break-all}
.search{width:100%;padding:.6rem 1rem;margin:.5rem 0 1rem;background:var(--sf);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:.95rem}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:1rem;margin:1rem 0}
.gallery figure{background:var(--sf);border:1px solid var(--bd);border-radius:8px;overflow:hidden}
.gallery img{width:100%;height:170px;object-fit:cover;object-position:top;display:block;background:#000}
.gallery figcaption{padding:.5rem;font-size:.78rem;color:var(--mt);word-break:break-all}
.muted{color:var(--mt);font-size:.9rem}
</style>
</head>
<body>
<div class="c">
<h1>🔱 ReconStorm Report</h1>
<div class="meta">
<span>📅 {{.GeneratedAt}}</span><span>⏱️ {{.Duration}}</span>
<span>● {{.ScanStatus}}</span>
<span>🎯 {{range $i,$d := .Domains}}{{if $i}}, {{end}}{{$d}}{{end}}</span>
<span><a href="https://github.com/H3llKa1ser/recon-storm">recon-storm</a></span>
</div>

{{if eq .ScanStatus "interrupted"}}<div class="ib">⚠️ Scan interrupted — partial results below.</div>{{end}}

<h2>🎯 Triage — look at these first</h2>
<div class="triage">
{{if .TopFindings}}
<ol>
{{range .TopFindings}}<li><span class="sv sv-{{sevClass .Severity}}">{{upper .Severity}}</span> {{.Value}} <span class="muted">— {{remediation .}}</span></li>{{end}}
</ol>
{{else}}<span class="muted">No critical, high, or medium severity findings.</span>{{end}}
</div>

<h2>📊 Summary</h2>
<div class="cards">
<div class="card"><div class="n">{{.Stats.TotalSubdomains}}</div><div class="l">Subdomains</div></div>
<div class="card"><div class="n">{{.Stats.TotalLiveHosts}}</div><div class="l">Live Hosts</div></div>
<div class="card"><div class="n">{{.Stats.TotalOpenPorts}}</div><div class="l">Open Ports</div></div>
<div class="card"><div class="n">{{len .WebServers}}</div><div class="l">Web Servers</div></div>
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

{{if .CriticalFindings}}<h2>🔴 Critical</h2>{{range .CriticalFindings}}<div class="f cr"><div class="t">{{.Type}}</div><div class="v">{{.Value}}</div><div class="s">{{.Source}} | {{.Domain}}</div><div class="r">{{remediation .}}</div></div>{{end}}{{end}}
{{if .HighFindings}}<h2>🟠 High</h2>{{range .HighFindings}}<div class="f hi"><div class="t">{{.Type}}</div><div class="v">{{.Value}}</div><div class="s">{{.Source}} | {{.Domain}}</div><div class="r">{{remediation .}}</div></div>{{end}}{{end}}
{{if .MediumFindings}}<h2>🟡 Medium</h2>{{range .MediumFindings}}<div class="f md"><div class="t">{{.Type}}</div><div class="v">{{.Value}}</div><div class="s">{{.Source}} | {{.Domain}}</div><div class="r">{{remediation .}}</div></div>{{end}}{{end}}

{{if .Vulnerabilities}}<h2>🐛 Vulnerabilities ({{len .Vulnerabilities}})</h2>
<input class="search" id="vulnSearch" placeholder="Filter vulnerabilities…" onkeyup="filt('vulnSearch','vulnTable')">
<table id="vulnTable"><tr><th>Severity</th><th>Finding</th><th>Domain</th><th>Source</th></tr>
{{range .Vulnerabilities}}<tr><td><span class="sv sv-{{sevClass .Severity}}">{{.Severity}}</span></td><td>{{.Value}}</td><td>{{.Domain}}</td><td>{{.Source}}</td></tr>{{end}}
</table>{{end}}

{{if .Secrets}}<h2>🔑 Secrets ({{len .Secrets}})</h2>
<table><tr><th>Secret</th><th>Domain</th><th>Source</th></tr>
{{range .Secrets}}<tr><td><code>{{.Value}}</code></td><td>{{.Domain}}</td><td>{{.Source}}</td></tr>{{end}}
</table>{{end}}

{{if .Screenshots}}<h2>📸 Screenshots ({{len .Screenshots}})</h2>
<div class="gallery">
{{range .Screenshots}}<figure><a href="{{.RelPath}}" target="_blank"><img loading="lazy" src="{{.RelPath}}" alt="{{.Label}}"></a><figcaption>{{.Label}}</figcaption></figure>{{end}}
</div>{{end}}

<h2>⚙️ Modules</h2>
<table><tr><th>Module</th><th>Status</th><th>Detail</th></tr>
{{range $n := .ModuleNames}}{{$m := index $.Modules $n}}<tr><td>{{$n}}</td><td><span class="sv sv-{{if eq (printf "%s" $m.Status) "completed"}}lo{{else if eq (printf "%s" $m.Status) "failed"}}hi{{else if eq (printf "%s" $m.Status) "skipped"}}in{{else}}md{{end}}">{{$m.Status}}</span></td><td>{{if $m.Error}}{{$m.Error}}{{else}}{{$m.SkipReason}}{{end}}</td></tr>{{end}}
</table>

{{if .Subdomains}}<details><summary>🌐 Subdomains ({{len .Subdomains}})</summary>
<input class="search" id="subSearch" placeholder="Filter subdomains…" onkeyup="filt('subSearch','subTable')">
<table id="subTable"><tr><th>Subdomain</th><th>Source</th></tr>
{{range .Subdomains}}<tr><td>{{.Value}}</td><td>{{.Source}}</td></tr>{{end}}
</table></details>{{end}}

{{if .OpenPorts}}<details><summary>🔌 Open Ports ({{len .OpenPorts}})</summary>
<input class="search" id="portSearch" placeholder="Filter ports…" onkeyup="filt('portSearch','portTable')">
<table id="portTable"><tr><th>Host:Port</th><th>Source</th></tr>
{{range .OpenPorts}}<tr><td>{{.Value}}</td><td>{{.Source}}</td></tr>{{end}}
</table></details>{{end}}

<p style="margin-top:3rem;color:var(--mt);text-align:center;font-size:.85rem">
<a href="https://github.com/H3llKa1ser/recon-storm" style="color:var(--ac)">ReconStorm v2.1</a> — H3llKa1ser
</p>
</div>
<script>
function filt(inputId, tableId){
  var q = document.getElementById(inputId).value.toLowerCase();
  var rows = document.getElementById(tableId).getElementsByTagName('tr');
  for (var i = 1; i < rows.length; i++){
    rows[i].style.display = rows[i].innerText.toLowerCase().indexOf(q) > -1 ? '' : 'none';
  }
}
</script>
</body>
</html>`
