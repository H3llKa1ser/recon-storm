package scanner

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

// Module is the interface every scan module implements
type Module interface {
    Name() string
    Run(ctx context.Context, domain string) error
}

// Scanner orchestrates all recon modules
type Scanner struct {
    cfg     *config.Config
    state   *state.Manager
    log     *logger.Logger
    modules []Module
}

func New(cfg *config.Config, sm *state.Manager, log *logger.Logger) *Scanner {
    s := &Scanner{
        cfg:   cfg,
        state: sm,
        log:   log,
    }

    // Register modules based on config
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

func (s *Scanner) Run() error {
    s.state.SetDomains(s.cfg.Domains)

    // Start auto-save (saves state every 30 seconds)
    stopAutoSave := make(chan struct{})
    s.state.AutoSave(30*time.Second, stopAutoSave)
    defer close(stopAutoSave)

    var allErrors []error

    for _, domain := range s.cfg.Domains {
        s.log.Section(fmt.Sprintf("SCANNING: %s", domain))

        for _, mod := range s.modules {
            moduleName := mod.Name()

            // Skip if already completed (resume mode)
            moduleKey := fmt.Sprintf("%s_%s", domain, moduleName)
            if s.cfg.Resume && s.state.IsModuleCompleted(moduleKey) {
                s.log.Info("  ⏭  Skipping %s (already completed)", moduleName)
                continue
            }

            s.log.Section(fmt.Sprintf("MODULE: %s → %s", moduleName, domain))

            // Create module-level context with timeout
            ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ModuleTimeout)

            // Track module timing
            result := &state.ModuleResult{
                Name:      moduleKey,
                Status:    state.StatusRunning,
                StartTime: time.Now(),
            }
            s.state.SetModuleResult(moduleKey, result)
            s.state.Save()

            // Run module
            err := s.runModuleWithRecovery(ctx, mod, domain)
            cancel()

            result.EndTime = time.Now()

            if err != nil {
                result.Status = state.StatusFailed
                result.Error = err.Error()
                s.log.Error("  Module %s failed: %v", moduleName, err)
                allErrors = append(allErrors, fmt.Errorf("%s@%s: %w", moduleName, domain, err))
            } else {
                result.Status = state.StatusCompleted
                s.log.Success("  Module %s completed in %v",
                    moduleName, result.EndTime.Sub(result.StartTime).Round(time.Millisecond))
            }

            s.state.SetModuleResult(moduleKey, result)
            s.state.Save()
        }
    }

    if len(allErrors) > 0 {
        return fmt.Errorf("%d module(s) had errors", len(allErrors))
    }
    return nil
}

// runModuleWithRecovery runs a module and catches panics
func (s *Scanner) runModuleWithRecovery(ctx context.Context, mod Module, domain string) (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("module panicked: %v", r)
        }
    }()

    var wg sync.WaitGroup
    errChan := make(chan error, 1)

    wg.Add(1)
    go func() {
        defer wg.Done()
        errChan <- mod.Run(ctx, domain)
    }()

    select {
    case err := <-errChan:
        return err
    case <-ctx.Done():
        return fmt.Errorf("module timed out after %v", s.cfg.ModuleTimeout)
    }
}
