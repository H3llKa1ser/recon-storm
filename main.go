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
    Bug Bounty Recon Framework v1.0
    github.com/H3llKa1ser/B00t2R00t
    Crash-Resilient • Auto-Install • Full Reports
`

func main() {
    fmt.Println(banner)

    // ── CLI Flags ──────────────────────────────────────────
    domain := flag.String("d", "", "Target domain (required)")
    domainList := flag.String("dL", "", "File containing list of domains")
    outputDir := flag.String("o", "", "Output directory (default: ./recon-<domain>)")
    threads := flag.Int("t", 50, "Number of concurrent threads")
    timeout := flag.Duration("timeout", 30*time.Minute, "Global timeout for entire scan")
    moduleTimeout := flag.Duration("module-timeout", 10*time.Minute, "Timeout per scan module")
    skipInstall := flag.Bool("skip-install", false, "Skip tool installation check")
    resume := flag.Bool("resume", false, "Resume a previous interrupted scan")
    modules := flag.String("modules", "all", "Comma-separated modules: subdomains,ports,web,dns,vulns,endpoints,secrets,screenshots")
    passive := flag.Bool("passive", false, "Passive recon only (no active scanning)")
    reportFormat := flag.String("report", "all", "Report format: html,json,markdown,all")
    verbose := flag.Bool("v", false, "Verbose output")

    // API keys (optional, enhance results)
    shodanKey := flag.String("shodan-key", "", "Shodan API key")
    censysID := flag.String("censys-id", "", "Censys API ID")
    censysSecret := flag.String("censys-secret", "", "Censys API secret")
    githubToken := flag.String("github-token", "", "GitHub personal access token")
    virusTotalKey := flag.String("vt-key", "", "VirusTotal API key")
    securityTrailsKey := flag.String("st-key", "", "SecurityTrails API key")

    flag.Parse()

    // ── Validate Input ─────────────────────────────────────
    if *domain == "" && *domainList == "" {
        fmt.Println("[!] Error: You must specify a target domain (-d) or domain list (-dL)")
        flag.Usage()
        os.Exit(1)
    }

    // ── Build Config ───────────────────────────────────────
    cfg := &config.Config{
        Domain:            *domain,
        DomainListFile:    *domainList,
        Threads:           *threads,
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

    // Resolve domains list
    if err := cfg.ResolveDomains(); err != nil {
        fmt.Printf("[!] Error resolving domains: %v\n", err)
        os.Exit(1)
    }

    // Set output directory
    if *outputDir != "" {
        cfg.OutputDir = *outputDir
    } else {
        cfg.OutputDir = fmt.Sprintf("./recon-%s-%s", cfg.Domains[0], time.Now().Format("20060102-150405"))
    }

    // ── Initialize Logger ──────────────────────────────────
    log := logger.New(cfg.OutputDir, cfg.Verbose)
    log.Info("ReconStorm initialized for %d domain(s)", len(cfg.Domains))

    // ── Initialize Persistent State ────────────────────────
    sm := state.NewManager(cfg.OutputDir)
    if cfg.Resume {
        if err := sm.Load(); err != nil {
            log.Warn("No previous state found, starting fresh: %v", err)
        } else {
            log.Info("Resumed previous scan state — %d modules already completed", sm.CompletedCount())
        }
    }

    // ── Setup Crash Recovery ───────────────────────────────
    reportGen := reporter.New(cfg, sm, log)

    emergencyReport := func(reason string) {
        log.Warn("=== EMERGENCY REPORT TRIGGERED: %s ===", reason)
        sm.SetStatus(state.StatusInterrupted)
        sm.SetEndTime(time.Now())
        sm.Save()
        if err := reportGen.Generate(); err != nil {
            log.Error("Failed to generate emergency report: %v", err)
        } else {
            log.Info("Emergency report saved to %s/reports/", cfg.OutputDir)
        }
    }

    // Catch OS signals (Ctrl+C, kill, etc.)
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
    go func() {
        sig := <-sigChan
        emergencyReport(fmt.Sprintf("Received signal: %v", sig))
        os.Exit(130)
    }()

    // Catch panics
    defer func() {
        if r := recover(); r != nil {
            stackTrace := string(debug.Stack())
            log.Error("PANIC RECOVERED: %v\n%s", r, stackTrace)
            emergencyReport(fmt.Sprintf("Panic: %v", r))
            os.Exit(1)
        }
    }()

    // ── Install Dependencies ───────────────────────────────
    if !cfg.SkipInstall {
        log.Section("DEPENDENCY CHECK & INSTALLATION")
        inst := installer.New(log)
        if err := inst.CheckAndInstall(); err != nil {
            log.Error("Tool installation had errors: %v", err)
            log.Warn("Continuing with available tools...")
        }
    }

    // ── Run Scan ───────────────────────────────────────────
    sm.SetStatus(state.StatusRunning)
    sm.SetStartTime(time.Now())
    sm.Save()

    scanEngine := scanner.New(cfg, sm, log)

    // Global timeout watchdog
    done := make(chan bool, 1)
    go func() {
        timer := time.NewTimer(cfg.GlobalTimeout)
        select {
        case <-timer.C:
            log.Warn("Global timeout reached (%v), generating report with current findings...", cfg.GlobalTimeout)
            emergencyReport("Global timeout exceeded")
            os.Exit(124)
        case <-done:
            timer.Stop()
        }
    }()

    // Execute scan
    if err := scanEngine.Run(); err != nil {
        log.Error("Scan encountered errors: %v", err)
    }

    done <- true

    // ── Generate Final Report ──────────────────────────────
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
    log.Info("Results saved to: %s", cfg.OutputDir)
    log.Info("Reports saved to: %s/reports/", cfg.OutputDir)
}
