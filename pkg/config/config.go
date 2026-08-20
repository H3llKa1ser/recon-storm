package config

import (
    "bufio"
    "fmt"
    "os"
    "strings"
    "time"
)

type Config struct {
    Domain         string
    DomainListFile string
    Domains        []string

    OutputDir         string
    Threads           int
    DomainConcurrency int
    NucleiExcludeTags string
    Dast              bool
    GlobalTimeout     time.Duration
    ModuleTimeout     time.Duration
    SkipInstall   bool
    Resume        bool
    Modules       string
    PassiveOnly   bool
    ReportFormat  string
    Verbose       bool

    ShodanAPIKey      string
    CensysAPIID       string
    CensysAPISecret   string
    GitHubToken       string
    VirusTotalAPIKey  string
    SecurityTrailsKey string
}

func (c *Config) ResolveDomains() error {
    if c.Domain != "" {
        c.Domains = append(c.Domains, strings.TrimSpace(c.Domain))
    }
    if c.DomainListFile != "" {
        file, err := os.Open(c.DomainListFile)
        if err != nil {
            return fmt.Errorf("cannot open domain list: %w", err)
        }
        defer file.Close()
        sc := bufio.NewScanner(file)
        for sc.Scan() {
            line := strings.TrimSpace(sc.Text())
            if line != "" && !strings.HasPrefix(line, "#") {
                c.Domains = append(c.Domains, line)
            }
        }
    }
    if len(c.Domains) == 0 {
        return fmt.Errorf("no domains specified")
    }
    seen := make(map[string]bool)
    unique := []string{}
    for _, d := range c.Domains {
        if !seen[d] {
            seen[d] = true
            unique = append(unique, d)
        }
    }
    c.Domains = unique
    return nil
}

func (c *Config) ModuleEnabled(module string) bool {
    if c.Modules == "all" {
        return true
    }
    for _, m := range strings.Split(c.Modules, ",") {
        if strings.TrimSpace(m) == module {
            return true
        }
    }
    return false
}
