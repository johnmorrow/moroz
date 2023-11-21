package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/gorilla/mux"
	"github.com/kolide/kit/env"
	"github.com/kolide/kit/httputil"
	"github.com/kolide/kit/logutil"
	"github.com/kolide/kit/version"
	"github.com/oklog/run"

	"github.com/groob/moroz/moroz"
	"github.com/groob/moroz/santaconfig"
)

const openSSLBash = `
Looks like you're missing a TLS certificate and private key. You can quickly generate one 
by using the commands below:

	./tools/dev/certificate/create

Add the santa hostname to your hosts file.

	sudo echo "127.0.0.1 santa" >> /etc/hosts

And then, add the cert to roots.

	./tools/dev/certificate/add-trusted-cert


The latest version of santa is available on the github repo page:
	https://github.com/google/santa/releases
`

const createCABash = `
Looks like you're missing a client CA certificate required for mutual TLS. 
To generate a CA and vend a new certificate to an authorized client, follow these steps:

1. Generate a CA certificate:
   openssl genrsa -out ca.key 2048
   openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt

2. Create a client certificate and private key:
   openssl genrsa -out client.key 2048
   openssl req -new -key client.key -out client.csr

3. Sign the client certificate with the CA:
   openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 500 -sha256

Replace "ca.key", "ca.crt", "client.key", "client.csr", and "client.crt" with your preferred file names.
`

func main() {
	var (
		flTLSCert  = flag.String("tls-cert", env.String("MOROZ_TLS_CERT", "server.crt"), "path to TLS certificate")
		flTLSKey   = flag.String("tls-key", env.String("MOROZ_TLS_KEY", "server.key"), "path to TLS private key")
		flAddr     = flag.String("http-addr", env.String("MOROZ_HTTP_ADDRESS", ":8080"), "http address ex: -http-addr=:8080")
		flConfigs  = flag.String("configs", env.String("MOROZ_CONFIGS", "../../configs"), "path to config folder")
		flEvents   = flag.String("event-dir", env.String("MOROZ_EVENT_DIR", "/tmp/santa_events"), "Path to root directory where events will be stored.")
		flVersion  = flag.Bool("version", false, "print version information")
		flDebug    = flag.Bool("debug", false, "log at a debug level by default.")
		flUseTLS   = flag.Bool("use-tls", true, "I promise I terminated TLS elsewhere when changing this")
		flMTLS     = flag.Bool("mtls", false, "enable mutual TLS")
		flClientCA = flag.String("mtls-ca", env.String("MOROZ_CLIENT_CA", "ca.crt"), "path to client CA certificate for mutual TLS")
	)
	flag.Parse()

	if *flVersion {
		version.PrintFull()
		return
	}

	if _, err := os.Stat(*flTLSCert); *flUseTLS && os.IsNotExist(err) {
		fmt.Printf(openSSLBash)
		os.Exit(2)
	}

	if !validateConfigExists(*flConfigs) {
		fmt.Println("you need to provide at least a 'global.toml' configuration file in the configs folder. See the configs folder in the git repo for an example")
		os.Exit(2)
	}

	logger := logutil.NewServerLogger(*flDebug)

	var clientCAs *x509.CertPool
	if *flMTLS {
		if _, err := os.Stat(*flClientCA); os.IsNotExist(err) {
			fmt.Printf(createCABash)
			os.Exit(2)
		}

		caCert, err := ioutil.ReadFile(*flClientCA)
		if err != nil {
			logutil.Fatal(logger, "msg", "failed to read client CA certificate", "err", err)
		}
		clientCAs = x509.NewCertPool()
		clientCAs.AppendCertsFromPEM(caCert)
	}

	repo := santaconfig.NewFileRepo(*flConfigs)
	var svc moroz.Service
	{
		s, err := moroz.NewService(repo, *flEvents)
		if err != nil {
			logutil.Fatal(logger, err)
		}
		svc = s
		svc = moroz.LoggingMiddleware(logger)(svc)
	}

	endpoints := moroz.MakeServerEndpoints(svc)

	r := mux.NewRouter()
	moroz.AddHTTPRoutes(r, endpoints, logger)

	var g run.Group
	{
		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
			select {
			case sig := <-c:
				return fmt.Errorf("received signal %s", sig)
			case <-ctx.Done():
				return ctx.Err()
			}
		}, func(error) {
			cancel()
		})
	}

	{
		srv := httputil.NewServer(*flAddr, r)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "serve http", "tls", *flUseTLS, "mtls", *flMTLS, "addr", *flAddr)
			if *flUseTLS {
				tlsConfig := &tls.Config{
					ClientAuth: tls.NoClientCert,
				}
				if *flMTLS {
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
					tlsConfig.ClientCAs = clientCAs
				}
				srv.TLSConfig = tlsConfig
				return srv.ListenAndServeTLS(*flTLSCert, *flTLSKey)
			} else {
				return srv.ListenAndServe()
			}
		}, func(error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			srv.Shutdown(ctx)
		})
	}

	logutil.Fatal(logger, "msg", "terminated", "err", g.Run())
}

func validateConfigExists(configsPath string) bool {
	var hasConfig = true
	if _, err := os.Stat(configsPath); os.IsNotExist(err) {
		hasConfig = false
	}
	if _, err := os.Stat(configsPath + "/global.toml"); os.IsNotExist(err) {
		hasConfig = false
	}
	if !hasConfig {
	}
	return hasConfig
}
