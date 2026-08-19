package state

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "sync"
    "time"
)

type ScanStatus string

const (
    StatusPending     ScanStatus = "pending"
    StatusRunning     ScanStatus = "running"
    StatusCompleted   ScanStatus = "completed"
    StatusInterrupted ScanStatus = "interrupted"
    StatusFailed      ScanStatus = "failed"
    StatusSkipped     ScanStatus = "skipped"
)

type ModuleResult struct {
    Name       string     `json:"name"`
    Status     ScanStatus `json:"status"`
    StartTime  time.Time  `json:"start_time"`
    EndTime    time.Time  `json:"end_time"`
    ItemCount  int        `json:"item_count"`
    Error      string     `json:"error,omitempty"`
    SkipReason string     `json:"skip_reason,omitempty"`
    DataFile   string     `json:"data_file"`
}

type Finding struct {
    Type      string            `json:"type"`
    Value     string            `json:"value"`
    Source    string            `json:"source"`
    Severity  string            `json:"severity"`
    Domain    string            `json:"domain"`
    Metadata  map[string]string `json:"metadata"`
    Timestamp time.Time         `json:"timestamp"`
}

// dedupKey identifies a logically-unique finding. Two findings that share a
// type, domain and value are the same discovery even if reported by different
// sources, so they collapse into one (the first source wins, extra sources are
// recorded in metadata).
func (f Finding) dedupKey() string {
    return f.Type + "\x00" + f.Domain + "\x00" + strings.ToLower(strings.TrimSpace(f.Value))
}

type ScanStats struct {
    TotalSubdomains  int `json:"total_subdomains"`
    TotalLiveHosts   int `json:"total_live_hosts"`
    TotalOpenPorts   int `json:"total_open_ports"`
    TotalURLs        int `json:"total_urls"`
    TotalVulns       int `json:"total_vulns"`
    TotalEndpoints   int `json:"total_endpoints"`
    TotalSecrets     int `json:"total_secrets"`
    TotalScreenshots int `json:"total_screenshots"`
}

type ScanState struct {
    mu        sync.RWMutex `json:"-"`
    outputDir string       `json:"-"`

    // findingIndex maps a finding dedupKey to its position in Findings so
    // AddFinding can deduplicate in O(1). Rebuilt on Load.
    findingIndex map[string]int `json:"-"`

    Version   string                   `json:"version"`
    Status    ScanStatus               `json:"status"`
    StartTime time.Time                `json:"start_time"`
    EndTime   time.Time                `json:"end_time"`
    Domains   []string                 `json:"domains"`
    Modules   map[string]*ModuleResult `json:"modules"`
    Findings  []Finding                `json:"findings"`
    Stats     ScanStats                `json:"stats"`
}

type Manager struct {
    State *ScanState
}

func NewManager(outputDir string) *Manager {
    os.MkdirAll(outputDir, 0755)
    return &Manager{
        State: &ScanState{
            outputDir:    outputDir,
            Version:      "2.1.0",
            Status:       StatusPending,
            Modules:      make(map[string]*ModuleResult),
            Findings:     make([]Finding, 0),
            findingIndex: make(map[string]int),
        },
    }
}

func (m *Manager) SetStatus(s ScanStatus) {
    m.State.mu.Lock()
    defer m.State.mu.Unlock()
    m.State.Status = s
}

func (m *Manager) SetStartTime(t time.Time) {
    m.State.mu.Lock()
    defer m.State.mu.Unlock()
    m.State.StartTime = t
}

func (m *Manager) SetEndTime(t time.Time) {
    m.State.mu.Lock()
    defer m.State.mu.Unlock()
    m.State.EndTime = t
}

func (m *Manager) GetStartTime() time.Time {
    m.State.mu.RLock()
    defer m.State.mu.RUnlock()
    return m.State.StartTime
}

func (m *Manager) GetEndTime() time.Time {
    m.State.mu.RLock()
    defer m.State.mu.RUnlock()
    return m.State.EndTime
}

func (m *Manager) SetDomains(domains []string) {
    m.State.mu.Lock()
    defer m.State.mu.Unlock()
    m.State.Domains = domains
}

// AddFinding records a finding, deduplicating on (type, domain, value). If the
// finding was already seen from a different source, the new source is appended
// to the existing finding's metadata rather than creating a duplicate row.
func (m *Manager) AddFinding(f Finding) {
    m.State.mu.Lock()
    defer m.State.mu.Unlock()

    if m.State.findingIndex == nil {
        m.State.rebuildIndex()
    }

    key := f.dedupKey()
    if idx, ok := m.State.findingIndex[key]; ok {
        existing := &m.State.Findings[idx]
        // Escalate severity if the duplicate carries a higher one.
        if severityRank(f.Severity) > severityRank(existing.Severity) {
            existing.Severity = f.Severity
        }
        // Track additional sources without losing the original.
        if f.Source != "" && !strings.Contains(existing.Source, f.Source) {
            existing.Source = existing.Source + "," + f.Source
            if existing.Metadata == nil {
                existing.Metadata = map[string]string{}
            }
            existing.Metadata["also_seen_by"] = strings.TrimPrefix(
                existing.Metadata["also_seen_by"]+","+f.Source, ",")
        }
        return
    }

    f.Timestamp = time.Now()
    m.State.Findings = append(m.State.Findings, f)
    m.State.findingIndex[key] = len(m.State.Findings) - 1
}

func (m *Manager) SetModuleResult(name string, result *ModuleResult) {
    m.State.mu.Lock()
    defer m.State.mu.Unlock()
    m.State.Modules[name] = result
}

func (m *Manager) IsModuleCompleted(name string) bool {
    m.State.mu.RLock()
    defer m.State.mu.RUnlock()
    mod, ok := m.State.Modules[name]
    return ok && mod.Status == StatusCompleted
}

func (m *Manager) CompletedCount() int {
    m.State.mu.RLock()
    defer m.State.mu.RUnlock()
    c := 0
    for _, mod := range m.State.Modules {
        if mod.Status == StatusCompleted {
            c++
        }
    }
    return c
}

func (m *Manager) UpdateStats(fn func(s *ScanStats)) {
    m.State.mu.Lock()
    defer m.State.mu.Unlock()
    fn(&m.State.Stats)
}

func (m *Manager) GetFindings() []Finding {
    m.State.mu.RLock()
    defer m.State.mu.RUnlock()
    cp := make([]Finding, len(m.State.Findings))
    copy(cp, m.State.Findings)
    return cp
}

// CountFindingsByType returns the number of unique findings of a given type.
// Stats derived from this are reproducible across resume runs because they are
// computed from the deduplicated finding set rather than accumulated counters.
func (m *Manager) CountFindingsByType(types ...string) int {
    m.State.mu.RLock()
    defer m.State.mu.RUnlock()
    want := make(map[string]bool, len(types))
    for _, t := range types {
        want[t] = true
    }
    c := 0
    for _, f := range m.State.Findings {
        if want[f.Type] {
            c++
        }
    }
    return c
}

// RecomputeStats rebuilds the finding-backed summary counters from the
// deduplicated findings so headline numbers match the tables and stay stable
// across resume runs. Counter-only metrics that are not stored as findings
// (TotalEndpoints, TotalScreenshots) are left untouched.
func (m *Manager) RecomputeStats() {
    m.State.mu.Lock()
    defer m.State.mu.Unlock()
    s := &m.State.Stats
    count := func(types ...string) int {
        want := map[string]bool{}
        for _, t := range types {
            want[t] = true
        }
        n := 0
        for _, f := range m.State.Findings {
            if want[f.Type] {
                n++
            }
        }
        return n
    }
    s.TotalSubdomains = count("subdomain")
    s.TotalLiveHosts = count("dns_resolved")
    s.TotalOpenPorts = count("open_port")
    s.TotalURLs = count("web_server")
    s.TotalVulns = count("vulnerability", "vuln", "sensitive_file")
    s.TotalSecrets = count("secret")
}

func (m *Manager) GetStats() ScanStats {
    m.State.mu.RLock()
    defer m.State.mu.RUnlock()
    return m.State.Stats
}

func (m *Manager) Save() error {
    m.State.mu.RLock()
    defer m.State.mu.RUnlock()
    statePath := filepath.Join(m.State.outputDir, "state.json")
    data, err := json.MarshalIndent(m.State, "", "  ")
    if err != nil {
        return fmt.Errorf("marshal failed: %w", err)
    }
    tmpPath := statePath + ".tmp"
    if err := os.WriteFile(tmpPath, data, 0644); err != nil {
        return fmt.Errorf("write failed: %w", err)
    }
    return os.Rename(tmpPath, statePath)
}

func (m *Manager) Load() error {
    statePath := filepath.Join(m.State.outputDir, "state.json")
    data, err := os.ReadFile(statePath)
    if err != nil {
        return err
    }
    m.State.mu.Lock()
    defer m.State.mu.Unlock()
    if err := json.Unmarshal(data, m.State); err != nil {
        return err
    }
    m.State.rebuildIndex()
    return nil
}

// rebuildIndex reconstructs findingIndex from Findings. Caller must hold the lock.
func (s *ScanState) rebuildIndex() {
    s.findingIndex = make(map[string]int, len(s.Findings))
    for i, f := range s.Findings {
        s.findingIndex[f.dedupKey()] = i
    }
}

func (m *Manager) AutoSave(interval time.Duration, stop <-chan struct{}) {
    go func() {
        ticker := time.NewTicker(interval)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                m.Save()
            case <-stop:
                m.Save()
                return
            }
        }
    }()
}

// severityRank orders severities so escalation can pick the worst one.
func severityRank(sev string) int {
    switch strings.ToLower(strings.TrimSpace(sev)) {
    case "critical":
        return 5
    case "high":
        return 4
    case "medium":
        return 3
    case "low":
        return 2
    case "info":
        return 1
    default:
        return 0
    }
}

// SortFindingsBySeverity returns findings ordered worst-first, stable within a
// severity. Useful for report triage ordering.
func SortFindingsBySeverity(in []Finding) []Finding {
    out := make([]Finding, len(in))
    copy(out, in)
    sort.SliceStable(out, func(i, j int) bool {
        return severityRank(out[i].Severity) > severityRank(out[j].Severity)
    })
    return out
}
