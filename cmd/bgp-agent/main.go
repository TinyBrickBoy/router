// bgp-agent läuft auf den Backends und empfängt IPs per WireGuard vom bgp-router.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tinybrickboy/router/internal/agent"
	"github.com/tinybrickboy/router/internal/sysexec"
	"github.com/tinybrickboy/router/internal/version"
)

func main() {
	cmd, args := "run", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if cmd == "version" {
		fmt.Println(version.Version)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/bgp-agent/config.json", "konfigurationsdatei")
	dryRun := fs.Bool("dry-run", false, "systembefehle nur protokollieren")
	_ = fs.Parse(args)

	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("konfiguration: %v", err)
	}
	a := agent.New(cfg, &sysexec.Runner{DryRun: *dryRun})

	switch cmd {
	case "run":
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := a.Run(ctx); err != nil {
			log.Fatal(err)
		}
		log.Printf("beendet (tunnel und adressen bleiben aktiv, entfernen mit `bgp-agent down`)")
	case "once":
		if err := a.Once(); err != nil {
			log.Fatal(err)
		}
	case "down":
		if err := a.Down(); err != nil {
			log.Fatal(err)
		}
		log.Printf("konfiguration entfernt")
	default:
		fmt.Fprintf(os.Stderr, "unbekannter befehl %q\n\nbefehle:\n  run      dauerhaft synchronisieren (standard)\n  once     einmal synchronisieren und anwenden\n  down     tunnel, adressen und routen entfernen\n  version  version ausgeben\n", cmd)
		os.Exit(2)
	}
}
