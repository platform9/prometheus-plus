package main

/*
 Copyright [2019] [Platform9 Systems, Inc]

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/platform9/prometheus-plus/pkg/sysprom"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

var mode string
var logLevel string
var initMode bool

var landingPage = []byte(`<html>
<head><title>Event exporter</title></head>
<body>
<h1>Event exporter</h1>
<p><a href='` + "/metrics" + `'>Metrics</a></p>
</body>
</html>
`)

const (
	defaultMode     = "standalone"
	defaultLogLevel = "INFO"
	defaultInitMode = false
)

func setupEventExporter() {
	config, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		log.Fatalf("build kubeconfig: %v", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("create client:", err)
	}
	store := NewEventStore(client,
		time.Duration(20)*time.Second,
		time.Duration(30000)*time.Second,
		core_v1.NamespaceAll)
	go store.Run()
	exporter := NewExporter(store)
	prometheus.MustRegister(exporter)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(landingPage)
	})

	log.Info("Listening on", ":9102")
	log.Fatal(http.ListenAndServe(":9102", nil))
}

// Main is the entry point of helper controller
func Main() int {
	log.SetFormatter(&log.JSONFormatter{})

	init := viper.GetBool("initmode")
	if init == true {
		log.Info("Starting in Init mode")

		if err := sysprom.SetupSystemPrometheus(); err != nil {
			log.Fatal(err, "while deploying system prometheus")
		}

		log.Info("Successfully installed system prometheus")
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg, ctx := errgroup.WithContext(ctx)

	setupEventExporter()
	//wg.Go(func() error { return pc.Run(ctx.Done()) })

	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	select {
	case <-term:
		log.Info("exiting gracefully...")
	case <-ctx.Done():
	}

	cancel()
	if err := wg.Wait(); err != nil {
		log.Error(err, "when waiting for watchers to terminate....")
		return 1
	}

	return 0
}

func buildCmd() *cobra.Command {
	cobra.OnInitialize(initCfg)
	rootCmd := &cobra.Command{
		Use:   "monhelper",
		Short: "Monhelper enhances user experience of prometheus operator",
		Long: "Monhelper creates helper services to access prometheus and alertmanager instances" +
			" created by prometheus-operator",
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(Main())
		},
	}

	pf := rootCmd.PersistentFlags()
	pf.StringVar(&mode, "mode", defaultMode, "Operational mode: k8s or standalone")
	viper.BindPFlag("mode", pf.Lookup("mode"))
	pf.StringVar(&logLevel, "log-level", defaultLogLevel, "Log level: DEBUG, INFO, WARN or FATAL")
	viper.BindPFlag("log-level", pf.Lookup("log-level"))
	pf.BoolVar(&initMode, "initmode", defaultInitMode, "Initialization mode: true or false")
	viper.BindPFlag("initmode", pf.Lookup("initmode"))

	return rootCmd
}

func initCfg() {
	mode := viper.GetString("mode")
	if mode != "k8s" && mode != "standalone" {
		fmt.Fprintf(os.Stderr, "mode %s is invalid", mode)
		os.Exit(1)
	}

	lvl := viper.GetString("log-level")
	switch lvl {
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	case "WARN":
		log.SetLevel(log.WarnLevel)
	case "FATAL":
		log.SetLevel(log.FatalLevel)
	default:
		fmt.Fprintf(os.Stderr, "log level %s is invalid", lvl)
	}
}

func main() {
	cmd := buildCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
	}
}
