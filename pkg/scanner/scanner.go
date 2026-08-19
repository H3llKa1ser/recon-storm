package scanner

import (
    "context"
    "fmt"
    "path/filepath"
    "sync"
    "time"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

type Module interface {
    Name() string
    Run(ctx context.Context, domain string) error
}

type Scanner struct {
    cfg     *config.Config
    state   *state.Manager
    log     *logger.Logger
    modules []Module
}

func New(cfg *config.Config, sm *state.Manager, log *logger.Logger) *Scanner {
    s := &Scanner{cfg: cfg, state: sm, log: log}

    if cfg.ModuleEnabled("subdomains") {
        s.modules = append(s.modules, NewSubdomainModule(cfg, sm, log))
    }
    if cfg.ModuleEnabled("dns") {
        s.modules = append(s.modules, NewDNSModule(cfg, sm, log))
    }
    if cfg.ModuleEnabled("ports") && !cfg.PassiveOnly {
        s.modules = append(s.modules, NewPortModule(cfg, sm, log))
    }
    if cfg.ModuleEnabled("web") {
        s.modules = append(s.modules, NewWebModule(cfg, sm, log))
    }
    if cfg.ModuleEnabled("endpoints") {
        s.modules = append(s.modules, NewEndpointsModule(cfg, sm, log))
    }
    if cfg.ModuleEnabled("vulns") && !cfg.PassiveOnly {
        s.modules = append(s.modules, NewVulnModule(cfg, sm, log))
    }
    if cfg.ModuleEnabled("secrets") {
        s.modules = append(s.modules, NewSecretsModule(cfg, sm, log))
    }
    if cfg.ModuleEnabled("screenshots") && !cfg.PassiveOnly {
        s.modules = append(s.modules, NewScreenshotsModule(cfg, sm, log))
    }

    return s
}

// moduleInputs lists, per module, the candidate input files it can consume. A
// module is skipped (with a reason) only when none of its inputs exist, which
// turns the previous silent "return nil" into an explicit, reported outcome.
func (s *Scanner) moduleInputs(domain, module string) []string {
    d := func(parts ...string) string {
        return filepath.Join(append([]string{s.cfg.OutputDir, domain}, parts...)...)
    }
    switch module {
    case "dns":
        return []string{d("subdomains", "all_subdomains.txt")}
    case "ports":
        return []string{d("dns", "live_hosts.txt"), d("subdomains", "all_subdomains.txt")}
    case "web":
        return []string{d("ports", "host_ports.txt"), d("dns", "live_hosts.txt"), d("subdomains", "all_subdomains.txt")}
    case "endpoints":
        return []string{d("subdomains", "all_subdomains.txt"), d("web", "live_urls.txt")}
    case "vulns":
        return []string{d("web", "live_urls.txt")}
    case "secrets":
        return []string{d("web", "live_urls.txt"), d("endpoints", "js_files.txt")}
    case "screenshots":
        return []string{d("web", "live_urls.txt")}
    default:
        return nil // no declared prerequisites
    }
}

// prerequisiteMissing returns true and a human reason when a module has declared
// inputs and none of them are present.
func (s *Scanner) prerequisiteMissing(domain, module string) (bool, string) {
    inputs := s.moduleInputs(domain, module)
    if len(inputs) == 0 {
        return false, ""
    }
    for _, p := range inputs {
        if fileExists(p) {
            return false, ""
        }
    }
    return true, fmt.Sprintf("no input available (expected one of: %v)", baseNames(inputs))
}

func (s *Scanner) Run() error {
    s.state.SetDomains(s.cfg.Domains)

    stop := make(chan struct{})
    s.state.AutoSave(30*time.Second, stop)
    defer close(stop)

    concurrency := s.cfg.DomainConcurrency
    if concurrency < 1 {
        concurrency = 1
    }
    if concurrency > len(s.cfg.Domains) {
        concurrency = len(s.cfg.Domains)
    }

    // Keep the outbound thread budget global. Each domain's modules read
    // cfg.Threads independently, so without this the real concurrency would be
    // domainConcurrency * Threads — enough to trip rate limits / bot defenses
    // and skew results. Divide the budget across the domains running in parallel.
    if concurrency > 1 {
        perDomain := s.cfg.Threads / concurrency
        if perDomain < 1 {
            perDomain = 1
        }
        if perDomain != s.cfg.Threads {
            s.log.Info("Thread budget: %d total across %d parallel domains → %d per domain",
                s.cfg.Threads, concurrency, perDomain)
            s.cfg.Threads = perDomain
        }
    }

    var (
        errMu sync.Mutex
        errs  []error
        sem   = make(chan struct{}, concurrency)
        wg    sync.WaitGroup
    )

    if concurrency > 1 {
        s.log.Info("Scanning %d domains with up to %d in parallel", len(s.cfg.Domains), concurrency)
    }

    for _, domain := range s.cfg.Domains {
        domain := domain
        wg.Add(1)
        sem <- struct{}{}
        go func() {
            defer wg.Done()
            defer func() { <-sem }()
            if err := s.scanDomain(domain); err != nil {
                errMu.Lock()
                errs = append(errs, err)
                errMu.Unlock()
            }
        }()
    }
    wg.Wait()

    if len(errs) > 0 {
        return fmt.Errorf("%d module(s) had errors", len(errs))
    }
    return nil
}

// scanDomain runs the module chain for a single domain sequentially, preserving
// the data dependencies between modules (dns needs subdomains, web needs dns…).
func (s *Scanner) scanDomain(domain string) error {
    s.log.Section(fmt.Sprintf("SCANNING: %s", domain))
    var errs []error

    for _, mod := range s.modules {
        key := fmt.Sprintf("%s_%s", domain, mod.Name())

        if s.cfg.Resume && s.state.IsModuleCompleted(key) {
            s.log.Info("  ⏭ Skipping %s (completed)", mod.Name())
            continue
        }

        // Dependency gate: record an explicit skip instead of a silent success.
        if missing, reason := s.prerequisiteMissing(domain, mod.Name()); missing {
            s.log.Warn("  ⏭ Skipping %s → %s: %s", mod.Name(), domain, reason)
            s.state.SetModuleResult(key, &state.ModuleResult{
                Name:       key,
                Status:     state.StatusSkipped,
                StartTime:  time.Now(),
                EndTime:    time.Now(),
                SkipReason: reason,
            })
            s.state.Save()
            continue
        }

        s.log.Section(fmt.Sprintf("MODULE: %s → %s", mod.Name(), domain))

        ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ModuleTimeout)

        result := &state.ModuleResult{
            Name:      key,
            Status:    state.StatusRunning,
            StartTime: time.Now(),
        }
        s.state.SetModuleResult(key, result)
        s.state.Save()

        err := s.runSafe(ctx, mod, domain)
        cancel()

        result.EndTime = time.Now()
        if err != nil {
            result.Status = state.StatusFailed
            result.Error = err.Error()
            s.log.Error("  %s failed: %v", mod.Name(), err)
            errs = append(errs, err)
        } else {
            result.Status = state.StatusCompleted
            s.log.Success("  %s completed in %v", mod.Name(),
                result.EndTime.Sub(result.StartTime).Round(time.Millisecond))
        }

        s.state.SetModuleResult(key, result)
        s.state.Save()
    }

    if len(errs) > 0 {
        return fmt.Errorf("%d module(s) failed for %s", len(errs), domain)
    }
    return nil
}

func (s *Scanner) runSafe(ctx context.Context, mod Module, domain string) (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic: %v", r)
        }
    }()

    ch := make(chan error, 1)
    go func() {
        defer func() {
            if r := recover(); r != nil {
                ch <- fmt.Errorf("panic: %v", r)
            }
        }()
        ch <- mod.Run(ctx, domain)
    }()

    select {
    case err := <-ch:
        return err
    case <-ctx.Done():
        return fmt.Errorf("timeout after %v", s.cfg.ModuleTimeout)
    }
}

func baseNames(paths []string) []string {
    out := make([]string, len(paths))
    for i, p := range paths {
        out[i] = filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)
    }
    return out
}
