// bgp-router läuft auf dem BGP VPS: WebUI, BIRD Konfiguration, WireGuard Hub und Routing.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tinybrickboy/router/internal/router"
	"github.com/tinybrickboy/router/internal/store"
	"github.com/tinybrickboy/router/internal/sysexec"
	"github.com/tinybrickboy/router/internal/tlsutil"
	"github.com/tinybrickboy/router/internal/update"
	"github.com/tinybrickboy/router/internal/version"
	"github.com/tinybrickboy/router/internal/wgkey"
)

const listenFDEnv = "BGP_ROUTER_LISTEN_FD"

func main() {
	cmd, args := "run", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		run(args)
	case "passwd":
		passwd(args)
	case "version":
		fmt.Println(version.Version)
	default:
		fmt.Fprintf(os.Stderr, "unbekannter befehl %q\n\nbefehle:\n  run      webinterface und steuerung starten (standard)\n  passwd   admin passwort setzen\n  version  version ausgeben\n", cmd)
		os.Exit(2)
	}
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "adresse des webinterfaces")
	statePath := fs.String("state", "/var/lib/bgp-router/state.json", "zustandsdatei")
	dist := fs.String("dist", "/var/lib/bgp-router/dist", "verzeichnis mit agent/router binaries für updates")
	dryRun := fs.Bool("dry-run", false, "systembefehle nur protokollieren")
	tlsCert := fs.String("tls-cert", "", "tls zertifikat einer CA (optional, sonst selbst signiert mit key pinning)")
	tlsKey := fs.String("tls-key", "", "tls schlüssel zu -tls-cert")
	plainHTTP := fs.Bool("http", false, "ohne TLS lauschen (nur hinter einem HTTPS reverse proxy auf localhost verwenden)")
	_ = fs.Parse(args)

	log.SetFlags(log.LstdFlags)
	st, err := store.Open(*statePath)
	if err != nil {
		log.Fatalf("zustand laden: %v", err)
	}
	stateDir := filepath.Dir(*statePath)
	// Zustand enthält Schlüssel und Tokens: nur root darf lesen
	_ = os.Chmod(stateDir, 0o700)
	if err := initState(st, stateDir); err != nil {
		log.Fatalf("initialisieren: %v", err)
	}

	runner := &sysexec.Runner{DryRun: *dryRun}
	applier := router.NewApplier(st, runner, stateDir)
	srv := &router.Server{Store: st, Applier: applier, Runner: runner, DistDir: *dist, StateDir: stateDir}
	handler := srv.Handler()

	rawLn, inherited, err := listener(*listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	var tlsConf *tls.Config
	switch {
	case *tlsCert != "":
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	case *plainHTTP:
		log.Printf("WARNUNG: webinterface ohne TLS. nur hinter einem HTTPS reverse proxy verwenden und öffentliche url auf https:// setzen")
	default:
		cert, err := tlsutil.EnsureSelfSigned(filepath.Join(stateDir, "tls"))
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		srv.Pin, _ = tlsutil.SPKIPin(cert)
		tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		log.Printf("tls mit selbst signiertem zertifikat, public key pin sha256//%s", srv.Pin)
	}
	wrap := func(l net.Listener) net.Listener {
		if tlsConf != nil {
			return tls.NewListener(l, tlsConf)
		}
		return l
	}
	newHTTPServer := func() *http.Server {
		return &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       10 * time.Minute, // Uploads von Binaries
			WriteTimeout:      10 * time.Minute, // GitHub Release Download im Request
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
		}
	}
	httpSrv := newHTTPServer()

	srv.Restart = func() error {
		// Laufende Konfiguration nicht mitten im Anwenden unterbrechen
		applier.Lock()
		f, err := rawLn.File() // dupliziert den Socket, er bleibt über exec offen
		if err != nil {
			applier.Unlock()
			return err
		}
		// fd über SyscallConn holen: f.Fd() würde den geteilten Socket auf blocking stellen
		var fd uintptr
		rc, err := f.SyscallConn()
		if err == nil {
			cerr := rc.Control(func(v uintptr) { fd, err = v, update.ClearCloexec(v) })
			if err == nil {
				err = cerr
			}
		}
		if err != nil {
			f.Close()
			applier.Unlock()
			return err
		}
		log.Printf("starte neu mit neuem binary (%s)", update.Executable())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = httpSrv.Shutdown(ctx) // wartet auf laufende Anfragen, neue warten im Kernel Backlog
		cancel()
		err = update.Reexec(listenFDEnv + "=" + strconv.Itoa(int(fd)))
		// Nur im Fehlerfall erreicht: ohne Ausfall mit dem alten Binary weitermachen
		log.Printf("exec fehlgeschlagen, alter prozess läuft weiter: %v", err)
		applier.Unlock()
		nl, lerr := net.FileListener(f)
		if lerr != nil {
			log.Fatalf("listener wiederherstellen: %v", lerr)
		}
		rawLn = nl.(*net.TCPListener)
		httpSrv = newHTTPServer()
		go serve(httpSrv, wrap(nl))
		return err
	}

	go applier.Loop()

	if inherited {
		log.Printf("bgp-router %s nach update gestartet, übernehme %s", version.Version, rawLn.Addr())
	} else {
		log.Printf("bgp-router %s hört auf %s", version.Version, rawLn.Addr())
	}
	go serve(httpSrv, wrap(rawLn))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("beende (netzwerkkonfiguration bleibt bestehen)")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

func serve(s *http.Server, ln net.Listener) {
	if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("http: %v", err)
	}
}

// listener übernimmt nach einem Update den Socket des alten Prozesses.
func listener(addr string) (*net.TCPListener, bool, error) {
	if v := os.Getenv(listenFDEnv); v != "" {
		os.Unsetenv(listenFDEnv)
		fd, err := strconv.Atoi(v)
		if err == nil {
			f := os.NewFile(uintptr(fd), "listener")
			l, err := net.FileListener(f)
			f.Close()
			if err == nil {
				if tl, ok := l.(*net.TCPListener); ok {
					return tl, true, nil
				}
			}
			log.Printf("geerbter listener unbrauchbar (%v), öffne neu", err)
		}
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, false, err
	}
	return l.(*net.TCPListener), false, nil
}

func initState(st *store.Store, stateDir string) error {
	return st.Update(func(s *store.State) error {
		if s.WGPrivateKey == "" {
			priv, _, err := wgkey.Generate()
			if err != nil {
				return err
			}
			s.WGPrivateKey = priv
		}
		if s.Admin.PasswordHash == "" {
			pw := os.Getenv("BGP_ROUTER_PASSWORD")
			if pw == "" {
				pw = store.RandomHex(8)
			}
			if err := router.SetPassword(&s.Admin, pw); err != nil {
				return err
			}
			pwFile := filepath.Join(stateDir, "initial-password")
			if err := os.WriteFile(pwFile, []byte(pw+"\n"), 0o600); err != nil {
				return err
			}
			// Passwort nicht ins Journal schreiben (für die Gruppe adm lesbar)
			log.Printf("erster start: benutzer admin, initiales passwort steht in %s", pwFile)
		}
		return s.AllocateTunnelIPs()
	})
}

func passwd(args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	statePath := fs.String("state", "/var/lib/bgp-router/state.json", "zustandsdatei")
	user := fs.String("user", "", "benutzer (standard: hauptbenutzer)")
	_ = fs.Parse(args)
	fmt.Print("neues passwort: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		log.Fatal(err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if len(pw) < 8 {
		log.Fatal("mindestens 8 zeichen")
	}
	st, err := store.Open(*statePath)
	if err != nil {
		log.Fatal(err)
	}
	if err := st.Update(func(s *store.State) error {
		s.Settings.OIDC.DisablePassword = false // Notfallzugang bei OIDC Problemen
		u := &s.Admin
		if *user != "" {
			if u = s.User(*user); u == nil {
				return fmt.Errorf("benutzer %s nicht gefunden", *user)
			}
		}
		return router.SetPassword(u, pw)
	}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("passwort gesetzt. jetzt `systemctl restart bgp-router` ausführen.")
}
