package config

import (
    "bufio"
    "fmt"
    "os"
    "strings"
    "time"
)

type Config struct {
    // Targets
    Domain         string
    DomainListFile string
    Domains        []string

    // Execution
    OutputDir     string
    Threads       int
    GlobalTimeout time.Duration
    ModuleTimeout time.Duration
    SkipInstall   bool
    Resume        bool
    Modules       string
    PassiveOnly   bool
    ReportFormat  string
    Verbose       bool

    // API Keys
    ShodanAPIKey      string
    CensysAPIID       string
    CensysAPISecret   string
    GitHubToken       string
    VirusTotalAPIKey  string
    SecurityTrailsKey string
}

// ResolveDomains populates the Domains slice from either -d or -dL
func (c *Config) ResolveDomains() error {
    if c.Domain != "" {
        c.Domains = append(c.Domains, strings.TrimSpace(c.Domain))
    }

    if c.DomainListFile != "" {
        file, err := os.Open(c.DomainListFile)
        if err != nil {
            return fmt.Errorf("cannot open domain list file: %w", err)
        }
        defer file.Close()

        sc := bufio.NewScanner(file)
        for sc.Scan() {
            line := strings.TrimSpace(sc.Text())
            if line != "" && !strings.HasPrefix(line, "#") {
                c.Domains = append(c.Domains, line)
            }
        }
        if err := sc.Err(); err != nil {
            return fmt.Errorf("error reading domain list: %w", err)
        }
    }

    if len(c.Domains) == 0 {
        return fmt.Errorf("no domains specified")
    }

    // Deduplicate
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

// ModuleEnabled checks if a specific module is enabled
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

// HasAPIKey checks if a given API key category is configured
func (c *Config) HasAPIKey(name string) bool {
    switch name {
    case "shodan":
        return c.ShodanAPIKey != ""
    case "censys":
        return c.CensysAPIID != "" && c.CensysAPISecret != ""
    case "github":
        return c.GitHubToken != ""
    case "virustotal":
        return c.VirusTotalAPIKey != ""
    case "securitytrails":
        return c.SecurityTrailsKey != ""
    }
    return false
}
