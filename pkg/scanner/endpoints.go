package scanner

import (
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "sort"
    "strings"
    "sync"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

type EndpointsModule struct {
    cfg   *config.Config
    state *state.Manager
    log   *logger.Logger
}

func NewEndpointsModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *EndpointsModule {
    return &EndpointsModule{cfg: cfg, state: sm, log: log}
}

func (m *EndpointsModule) Name() string { return "endpoints" }

func (m *EndpointsModule) Run(ctx context.Context, domain string) error {
    outDir := filepath.Join(m.cfg.OutputDir, domain, "endpoints")
