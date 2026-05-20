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

func (s *Scanner) Run() error {
    s.state.SetDomains(s.cfg.Domains)

    stop := make(chan struct{})
    s.state.AutoSave(30*time.Second, stop)
    defer close(stop)

    var errs []error

    for _, domain := range s.cfg.Domains {
        s.log.Section(fmt.Sprintf("SCANNING: %s", domain))

        for _, mod := range s.modules {
            key := fmt.Sprintf("%s_%s", domain, mod.Name())

            if s.cfg.Resume && s.state.IsModuleCompleted(key) {
                s.log.Info("  ⏭ Skipping %s (completed)", mod.Name())
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
    }

    if len(errs) > 0 {
        return fmt.Errorf("%d module(s) had errors", len(errs))
    }
    return nil
}

func (s *Scanner) runSafe(ctx context.Context, mod Module, domain string) (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic: %v", r)
        }
    }()

    var wg sync.WaitGroup
    ch := make(chan error, 1)
    wg.Add(1)
    go func() {
        defer wg.Done()
        ch <- mod.Run(ctx, domain)
    }()

    select {
    case err := <-ch:
        return err
    case <-ctx.Done():
        return fmt.Errorf("timeout after %v", s.cfg.ModuleTimeout)
    }
}
