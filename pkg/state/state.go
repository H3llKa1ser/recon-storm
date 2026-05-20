package state

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
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
)

type ModuleResult struct {
    Name      string     `json:"name"`
    Status    ScanStatus `json:"status"`
    StartTime time.Time  `json:"start_time"`
    EndTime   time.Time  `json:"end_time"`
    ItemCount int        `json:"item_count"`
    Error     string     `json:"error,omitempty"`
    DataFile  string     `json:"data_file"`
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
            outputDir: outputDir,
            Version:   "2.0.0",
            Status:    StatusPending,
            Modules:   make(map[string]*ModuleResult),
            Findings:  make([]Finding, 0),
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

func (m *Manager) AddFinding(f Finding) {
    m.State.mu.Lock()
    defer m.State.mu.Unlock()
    f.Timestamp = time.Now()
    m.State.Findings = append(m.State.Findings, f)
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
    return json.Unmarshal(data, m.State)
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
