package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	restserver "github.com/restic/rest-server"
	"github.com/spf13/cobra"
)

// cmdRoot is the base command when no other command has been specified.
var cmdRoot = &cobra.Command{
	Use:           "rest-server",
	Short:         "Run a REST server for use with restic",
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE:          runRoot,
	Version:       fmt.Sprintf("rest-server %s compiled with %v on %v/%v\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH),
}

var server = restserver.Server{
	Path:   filepath.Join(os.TempDir(), "restic"),
	Listen: ":8000",
}

var (
	cpuProfile string
)

func init() {
	flags := cmdRoot.Flags()
	flags.StringVar(&cpuProfile, "cpu-profile", cpuProfile, "write CPU profile to file")
	flags.BoolVar(&server.Debug, "debug", server.Debug, "output debug messages")
	flags.StringVar(&server.Listen, "listen", server.Listen, "listen address")
	flags.StringVar(&server.Log, "log", server.Log, "write HTTP requests in the combined log format to the specified `filename`")
	flags.Int64Var(&server.MaxRepoSize, "max-size", server.MaxRepoSize, "the maximum size of the repository in bytes")
	flags.StringVar(&server.Path, "path", server.Path, "data directory")
	flags.BoolVar(&server.TLS, "tls", server.TLS, "turn on TLS support")
	flags.StringVar(&server.TLSCACert, "tls-cacert", server.TLSCACert, "TLS CA certificate path")
	flags.StringVar(&server.TLSCert, "tls-cert", server.TLSCert, "TLS certificate path")
	flags.StringVar(&server.TLSKey, "tls-key", server.TLSKey, "TLS key path")
	flags.BoolVar(&server.NoAuth, "no-auth", server.NoAuth, "disable .htpasswd authentication")
	flags.StringVar(&server.HtpasswdPath, "htpasswd-file", server.HtpasswdPath, "location of .htpasswd file (default: \"<data directory>/.htpasswd)\"")
	flags.BoolVar(&server.NoVerifyUpload, "no-verify-upload", server.NoVerifyUpload,
		"do not verify the integrity of uploaded data. DO NOT enable unless the rest-server runs on a very low-power device")
	flags.BoolVar(&server.AppendOnly, "append-only", server.AppendOnly, "enable append only mode")
	flags.BoolVar(&server.PrivateRepos, "private-repos", server.PrivateRepos, "users can only access their private repo")
	flags.BoolVar(&server.Prometheus, "prometheus", server.Prometheus, "enable Prometheus metrics")
	flags.BoolVar(&server.PrometheusNoAuth, "prometheus-no-auth", server.PrometheusNoAuth, "disable auth for Prometheus /metrics endpoint")
	flags.DurationVar(&server.InactivityTimeout, "inactivity-timeout", server.InactivityTimeout, "stop server when inactive")

}

var version = "0.11.0"

func tlsSettings() (bool, string, string, error) {
	var key, cert string
	if !server.TLS && (server.TLSKey != "" || server.TLSCert != "") {
		return false, "", "", errors.New("requires enabled TLS")
	} else if !server.TLS {
		return false, "", "", nil
	}
	if server.TLSKey != "" {
		key = server.TLSKey
	} else {
		key = filepath.Join(server.Path, "private_key")
	}
	if server.TLSCert != "" {
		cert = server.TLSCert
	} else {
		cert = filepath.Join(server.Path, "public_key")
	}
	return server.TLS, key, cert, nil
}

type IdleTracker struct {
	mu     sync.Mutex
	active map[net.Conn]bool
	idle   time.Duration
	timer  *time.Timer
}

func NewIdleTracker(idle time.Duration) *IdleTracker {
	return &IdleTracker{
		active: make(map[net.Conn]bool),
		idle:   idle,
		timer:  time.NewTimer(idle),
	}
}

func (t *IdleTracker) ConnState(conn net.Conn, state http.ConnState) {
	t.mu.Lock()
	defer t.mu.Unlock()

	oldActive := len(t.active)
	switch state {
	case http.StateNew, http.StateActive, http.StateHijacked:
		t.active[conn] = true
		if oldActive == 0 {
			t.timer.Stop()
		}
	case http.StateIdle, http.StateClosed:
		delete(t.active, conn)
		if oldActive > 0 && len(t.active) == 0 {
			t.timer.Reset(t.idle)
		}
	}
}

func (t *IdleTracker) Done() <-chan time.Time {
	return t.timer.C
}

func runRoot(cmd *cobra.Command, args []string) error {
	log.SetFlags(0)

	log.Printf("Data directory: %s", server.Path)

	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			return err
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		log.Println("CPU profiling enabled")

		// clean profiling shutdown on sigint
		sigintCh := make(chan os.Signal, 1)
		go func() {
			for range sigintCh {
				pprof.StopCPUProfile()
				log.Println("Stopped CPU profiling")
				err := f.Close()
				if err != nil {
					log.Printf("error closing CPU profile file: %v", err)
				}
				os.Exit(130)
			}
		}()
		signal.Notify(sigintCh, syscall.SIGINT)
	}

	if server.NoAuth {
		log.Println("Authentication disabled")
	} else {
		log.Println("Authentication enabled")
	}

	handler, err := restserver.NewHandler(&server)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	if server.PrivateRepos {
		log.Println("Private repositories enabled")
	} else {
		log.Println("Private repositories disabled")
	}

	enabledTLS, privateKey, publicKey, err := tlsSettings()
	if err != nil {
		return err
	}

	listener, err := findListener(server.Listen)
	if err != nil {
		return fmt.Errorf("unable to listen: %w", err)
	}

	httpServer := &http.Server{
		Handler: handler,
	}

	if server.InactivityTimeout > 0 {
		log.Printf("Set inactivity timeout to %v", server.InactivityTimeout)

		idle := NewIdleTracker(server.InactivityTimeout)
		httpServer.ConnState = idle.ConnState

		go func() {
			<-idle.Done()
			if err := httpServer.Shutdown(context.Background()); err != nil {
				log.Fatalf("error shutting down: %v\n", err)
			}
		}()
	}

	if !enabledTLS {
		err = httpServer.Serve(listener)
	} else {
		log.Printf("TLS enabled, private key %s, pubkey %v", privateKey, publicKey)

		if server.TLSCACert != "" {
			log.Printf("TLS Client Authentication enabled, CA cert %s", server.TLSCACert)

			caCert, err := ioutil.ReadFile(server.TLSCACert)
			if err != nil {
				return fmt.Errorf("unable to read CA certificate: %w", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			tlsConfig := &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  caCertPool,
			}
			httpServer.TLSConfig = tlsConfig
		}

		err = httpServer.ServeTLS(listener, publicKey, privateKey)
	}

	if err == http.ErrServerClosed {
		err = nil
	}

	return err
}

func main() {
	if err := cmdRoot.Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
