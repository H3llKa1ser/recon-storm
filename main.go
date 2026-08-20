package main

import (
    "flag"
    "fmt"
    "os"
    "os/signal"
    "runtime/debug"
    "syscall"
    "time"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/installer"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/reporter"
    "github.com/H3llKa1ser/recon-storm/pkg/scanner"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

const banner = `
╦═╗┌─┐┌─┐┌─┐┌┐┌╔═╗┌┬┐┌─┐┬─┐┌┬┐
╠╦╝├┤ │  │ ││││╚═╗ │ │ │├┬┘│││
╩╚═└─┘└─┘└─┘┘└┘╚═╝ ┴ └─┘┴└─┴ ┴
    Bug Bounty Recon Framework v2.0
    github.com/H3llKa1ser/recon-storm
    Crash-Resilient • Auto-Install • Full Reports
`

func main() {
    fmt.Print(banner)

    domain := flag.String("d", "", "Target domain (required)")
    domainList := flag.String("dL", "", "File containing list of domains")
    outputDir := flag.String("o", "", "Output directory (default: ./recon-<domain>)")
    threads := flag.Int("t", 50, "Number of concurrent threads")
    domainConcurrency := flag.Int("domain-concurrency", 1, "Number of domains to scan in parallel (with -dL)")
    nucleiExcludeTags := flag.String("nuclei-exclude-tags", "", "Comma-separated nuclei template tags to exclude (e.g. ssl,dns). Empty = run all.")
    dast := flag.Bool("dast", false, "Enable nuclei DAST parameter fuzzing on discovered parameterized URLs (active, slower)")
    timeout := flag.Duration("timeout", 45*time.Minute, "Global timeout for entire scan")
    moduleTimeout := flag.Duration("module-timeout", 10*time.Minute, "Timeout per scan module")
    skipInstall := flag.Bool("skip-install", false, "Skip tool installation check")
    resume := flag.Bool("resume", false, "Resume a previous interrupted scan")
    modules := flag.String("modules", "all", "Comma-separated: subdomains,ports,web,dns,vulns,endpoints,secrets,screenshots")
    passive := flag.Bool("passive", false, "Passive recon only (no active scanning)")
    reportFormat := flag.String("report", "all", "Report format: html,json,markdown,all")
    verbose := flag.Bool("v", false, "Verbose output")

    shodanKey := flag.String("shodan-key", "", "Shodan API key")
    censysID := flag.String("censys-id", "", "Censys API ID")
    censysSecret := flag.String("censys-secret", "", "Censys API secret")
    githubToken := flag.String("github-token", "", "GitHub personal access token")
    virusTotalKey := flag.String("vt-key", "", "VirusTotal API key")
    securityTrailsKey := flag.String("st-key", "", "SecurityTrails API key")

    flag.Parse()

    if *domain == "" && *domainList == "" {
        fmt.Println("[!] Error: specify -d <domain> or -dL <file>")
        flag.Usage()
        os.Exit(1)
    }

    cfg := &config.Config{
        Domain:            *domain,
        DomainListFile:    *domainList,
        Threads:           *threads,
        DomainConcurrency: *domainConcurrency,
        NucleiExcludeTags: *nucleiExcludeTags,
        Dast:              *dast,
        GlobalTimeout:     *timeout,
        ModuleTimeout:     *moduleTimeout,
        SkipInstall:       *skipInstall,
        Resume:            *resume,
        Modules:           *modules,
        PassiveOnly:       *passive,
        ReportFormat:      *reportFormat,
        Verbose:           *verbose,
        ShodanAPIKey:      *shodanKey,
        CensysAPIID:       *censysID,
        CensysAPISecret:   *censysSecret,
        GitHubToken:       *githubToken,
        VirusTotalAPIKey:  *virusTotalKey,
        SecurityTrailsKey: *securityTrailsKey,
    }

    if err := cfg.ResolveDomains(); err != nil {
        fmt.Printf("[!] %v\n", err)
        os.Exit(1)
    }

    if *outputDir != "" {
        cfg.OutputDir = *outputDir
    } else {
        cfg.OutputDir = fmt.Sprintf("./recon-%s-%s", cfg.Domains[0], time.Now().Format("20060102-150405"))
    }

    log := logger.New(cfg.OutputDir, cfg.Verbose)
    log.Info("ReconStorm v2.0 initialized for %d domain(s)", len(cfg.Domains))

    sm := state.NewManager(cfg.OutputDir)
    if cfg.Resume {
        if err := sm.Load(); err != nil {
            log.Warn("No previous state found, starting fresh: %v", err)
        } else {
            log.Info("Resumed previous scan — %d modules completed", sm.CompletedCount())
        }
    }

    reportGen := reporter.New(cfg, sm, log)

    emergencyReport := func(reason string) {
        log.Warn("=== EMERGENCY REPORT: %s ===", reason)
        sm.SetStatus(state.StatusInterrupted)
        sm.SetEndTime(time.Now())
        sm.Save()
        if err := reportGen.Generate(); err != nil {
            log.Error("Emergency report failed: %v", err)
        } else {
            log.Info("Emergency report saved to %s/reports/", cfg.OutputDir)
        }
    }

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
    go func() {
        sig := <-sigChan
        emergencyReport(fmt.Sprintf("Signal: %v", sig))
        os.Exit(130)
    }()

    defer func() {
        if r := recover(); r != nil {
            log.Error("PANIC: %v\n%s", r, string(debug.Stack()))
            emergencyReport(fmt.Sprintf("Panic: %v", r))
            os.Exit(1)
        }
    }()

    if !cfg.SkipInstall {
        log.Section("DEPENDENCY CHECK & INSTALLATION")
        inst := installer.New(log)
        if err := inst.CheckAndInstall(); err != nil {
            log.Error("Installation errors: %v", err)
            log.Warn("Continuing with available tools...")
        }
    }

    sm.SetStatus(state.StatusRunning)
    sm.SetStartTime(time.Now())
    sm.Save()

    scanEngine := scanner.New(cfg, sm, log)

    done := make(chan bool, 1)
    go func() {
        timer := time.NewTimer(cfg.GlobalTimeout)
        select {
        case <-timer.C:
            log.Warn("Global timeout (%v) — generating partial report...", cfg.GlobalTimeout)
            emergencyReport("Global timeout")
            os.Exit(124)
        case <-done:
            timer.Stop()
        }
    }()

    if err := scanEngine.Run(); err != nil {
        log.Error("Scan errors: %v", err)
    }

    done <- true

    sm.SetStatus(state.StatusCompleted)
    sm.SetEndTime(time.Now())
    sm.Save()

    log.Section("REPORT GENERATION")
    if err := reportGen.Generate(); err != nil {
        log.Error("Report generation failed: %v", err)
        os.Exit(1)
    }

    duration := sm.GetEndTime().Sub(sm.GetStartTime()).Round(time.Second)
    log.Info("Scan completed in %v", duration)
    log.Info("Results: %s", cfg.OutputDir)
    log.Info("Reports: %s/reports/", cfg.OutputDir)
}
