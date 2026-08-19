package reporter

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

func TestReporterFixes(t *testing.T) {
    dir := t.TempDir()
    cfg := &config.Config{OutputDir: dir, Domains: []string{"example.com"}, ReportFormat: "all"}
    sm := state.NewManager(dir)
    log := logger.New(dir, false)

    sm.SetStatus(state.StatusCompleted)
    sm.SetStartTime(time.Now().Add(-time.Minute))
    sm.SetEndTime(time.Now())
    sm.SetModuleResult("example.com_web", &state.ModuleResult{Name: "example.com_web", Status: state.StatusSkipped, SkipReason: "no input available"})

    // Same subdomain from two sources must collapse to ONE finding.
    sm.AddFinding(state.Finding{Type: "subdomain", Value: "a.example.com", Source: "subfinder", Domain: "example.com", Severity: "info"})
    sm.AddFinding(state.Finding{Type: "subdomain", Value: "a.example.com", Source: "crt.sh", Domain: "example.com", Severity: "info"})
    sm.AddFinding(state.Finding{Type: "subdomain", Value: "b.example.com", Source: "amass", Domain: "example.com", Severity: "info"})

    sm.AddFinding(state.Finding{Type: "vulnerability", Value: "[high] Something", Source: "nuclei", Domain: "example.com", Severity: "high", Metadata: map[string]string{"description": "test high"}})
    sm.AddFinding(state.Finding{Type: "vulnerability", Value: "[critical] Bad", Source: "nuclei", Domain: "example.com", Severity: "critical"})
    sm.AddFinding(state.Finding{Type: "sensitive_endpoint", Value: "https://example.com/admin", Source: "endpoint_analysis", Domain: "example.com", Severity: "low"})
    sm.AddFinding(state.Finding{Type: "web_server", Value: "https://a.example.com", Source: "httpx", Domain: "example.com", Severity: "info"})

    r := New(cfg, sm, log)
    if err := r.Generate(); err != nil {
        t.Fatalf("Generate: %v", err)
    }

    // Dedup: subdomain count is 2, not 3.
    if got := sm.GetStats().TotalSubdomains; got != 2 {
        t.Errorf("dedup failed: TotalSubdomains = %d, want 2", got)
    }
    // Escalation: the deduped subdomain records both sources.
    for _, f := range sm.GetFindings() {
        if f.Type == "subdomain" && f.Value == "a.example.com" {
            if !strings.Contains(f.Source, "subfinder") || !strings.Contains(f.Source, "crt.sh") {
                t.Errorf("merged source lost: %q", f.Source)
            }
        }
    }

    html, _ := os.ReadFile(filepath.Join(dir, "reports", "report.html"))
    hs := string(html)
    if strings.Contains(hs, "sv-high") {
        t.Error("HTML still emits invalid class sv-high (severity CSS bug not fixed)")
    }
    if !strings.Contains(hs, "sv-hi") {
        t.Error("HTML missing valid severity class sv-hi")
    }
    if !strings.Contains(hs, "Triage") {
        t.Error("HTML missing triage/executive summary section")
    }
    if !strings.Contains(hs, "skipped") {
        t.Error("HTML modules table missing skipped status")
    }

    md, _ := os.ReadFile(filepath.Join(dir, "reports", "report.md"))
    ms := string(md)
    if !strings.Contains(ms, "Low") || !strings.Contains(ms, "/admin") {
        t.Error("Markdown dropped Low-severity findings (unification bug not fixed)")
    }
    if !strings.Contains(ms, "Triage") {
        t.Error("Markdown missing triage section")
    }
}
