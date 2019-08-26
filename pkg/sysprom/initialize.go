package sysprom

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
	"log"
	"os"
	"path"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	prometheus "github.com/coreos/prometheus-operator/pkg/client/versioned/typed/monitoring/v1"
	"github.com/spf13/viper"
	apiv1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1beta1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"

	"github.com/pkg/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	prometheusPort   = 9090
	alertmanagerPort = 9093
	monitoringNS     = "pf9-monitoring"
)

// InitConfig stores configuration all system prometheus objects
type InitConfig struct {
	cfg     *rest.Config
	client  kubernetes.Interface
	mClient monitoringclient.Interface
}

// New returns new instance of InitConfig
func New() (*InitConfig, error) {
	// TODO: make flag-dependent
	switch viper.GetString("mode") {
	case "standalone":
		return getByKubeCfg()
	case "k8s":
		return getInCluster()
	}

	return nil, errors.New("Invalid mode")
}

func buildInitConfig(cfg *rest.Config) (*InitConfig, error) {
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating kubernetes client")
	}

	mclient, err := monitoringclient.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating monitoring client")
	}

	return &InitConfig{
		cfg:     cfg,
		client:  client,
		mClient: mclient,
	}, nil
}

func getInCluster() (*InitConfig, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return buildInitConfig(cfg)
}

func getByKubeCfg() (*InitConfig, error) {
	defaultKubeCfg := path.Join(os.Getenv("HOME"), ".kube", "config")

	if os.Getenv("KUBECONFIG") != "" {
		defaultKubeCfg = os.Getenv("KUBECONFIG")
	}

	cfg, err := clientcmd.BuildConfigFromFlags("", defaultKubeCfg)
	if err != nil {
		return nil, errors.Wrap(err, "building kubecfg")
	}

	return buildInitConfig(cfg)
}

//CreatePrometheus resource
func CreatePrometheus(w *InitConfig) error {
	var replicas int32
	replicas = 1
	cpu, _ := resource.ParseQuantity("50m")  //500m
	mem, _ := resource.ParseQuantity("52Mi") //512Mi

	promclientset, err := prometheus.NewForConfig(w.cfg)
	if err != nil {
		return err
	}

	// Create Prometheus Resource
	prometheusClient := promclientset.Prometheuses(monitoringNS)
	promObject := &monitoringv1.Prometheus{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system",
			Namespace: monitoringNS,
		},
		Spec: monitoringv1.PrometheusSpec{
			ServiceMonitorSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"prometheus": "system",
					"role":       "service-monitor",
				},
			},
			ServiceAccountName: "prometheus",
			Replicas:           &replicas,
			Retention:          "15d",
			RuleSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"prometheus": "system",
					"role":       "alert-rules",
				},
			},
			Resources: apiv1.ResourceRequirements{
				Requests: map[apiv1.ResourceName]resource.Quantity{
					"cpu":    cpu,
					"memory": mem,
				},
			},
			Alerting: &monitoringv1.AlertingSpec{
				[]monitoringv1.AlertmanagerEndpoints{
					monitoringv1.AlertmanagerEndpoints{
						Name:      "alertmanager-sysalert",
						Namespace: monitoringNS,
						Port:      intstr.FromString("web"),
					},
				},
			},
		},
	}
	_, err = prometheusClient.Create(promObject)
	if err != nil {
		log.Fatal("Failed to create prometheus object", err)
		return err
	}

	// Creating service for sample application
	serviceClient := w.client.CoreV1().Services(monitoringNS)
	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus",
			Namespace: monitoringNS,
		},
		Spec: apiv1.ServiceSpec{
			Type: "NodePort",
			Selector: map[string]string{
				"prometheus": "system",
			},
			Ports: []apiv1.ServicePort{
				{
					Name:     "web",
					Port:     9090,
					NodePort: 30900,
					Protocol: "TCP",
				},
			},
		},
	}
	_, err = serviceClient.Create(service)
	if err != nil {
		return err
	}

	return nil
}

func CreatePrometheusRules(w *InitConfig) error {
	promclientset, err := prometheus.NewForConfig(w.cfg)
	if err != nil {
		return err
	}

	// Create Prometheus Rules
	prometheusClient := promclientset.PrometheusRules(monitoringNS)
	promObject := &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system-prometheus-rules",
			Namespace: monitoringNS,
			Labels: map[string]string{
				"prometheus": "system",
				"role":       "alert-rules",
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				monitoringv1.RuleGroup{
					Name: "system-rule-group",
					Rules: []monitoringv1.Rule{
						monitoringv1.Rule{ // Main memory less than 90% available
							Alert: "OutofMemory",
							Expr:  intstr.FromString("(node_memory_MemFree_bytes + node_memory_Cached_bytes + node_memory_Buffers_bytes) / node_memory_MemTotal_bytes * 100 < 90"),
							For:   "5m",
						},
						monitoringv1.Rule{ // Receiving data on network > 100 mb/s
							Alert: "UnusualNetworkThroughputIn",
							Expr:  intstr.FromString("sum by (instance) (irate(node_network_receive_bytes_total[2m])) / 1024 / 1024 > 100"),
							For:   "5m",
						},
						monitoringv1.Rule{ // Sending data on network > 100 mb/s
							Alert: "UnusualNetworkThroughputOut",
							Expr:  intstr.FromString("sum by (instance) (irate(node_network_transmit_bytes_total[2m])) / 1024 / 1024 > 100"),
							For:   "5m",
						},
						monitoringv1.Rule{ // Disk reading too much data > 50 mb/s
							Alert: "UnusualDiskReadRate",
							Expr:  intstr.FromString("sum by (instance) (irate(node_disk_read_bytes_total[2m])) / 1024 / 1024 > 50"),
							For:   "5m",
						},
						monitoringv1.Rule{ // Disk writing much data 50 mb/s
							Alert: "UnusualDiskWriteRate",
							Expr:  intstr.FromString("sum by (instance) (irate(node_disk_written_bytes_total[2m])) / 1024 / 1024 > 50"),
							For:   "5m",
						},
						monitoringv1.Rule{ // Very high disk read latency > 100 ms
							Alert: "UnusualDiskReadLatency",
							Expr:  intstr.FromString("rate(node_disk_read_time_seconds_total[1m]) / rate(node_disk_reads_completed_total[1m]) > 100"),
							For:   "5m",
						},
						monitoringv1.Rule{ // Very high disk write latency > 100 ms
							Alert: "UnusualDiskWriteLatency",
							Expr:  intstr.FromString("rate(node_disk_write_time_seconds_total[1m]) / rate(node_disk_writes_completed_total[1m]) > 100"),
							For:   "5m",
						},
						monitoringv1.Rule{ // High CPU load > 80%
							Alert: "HighCpuLoad",
							Expr:  intstr.FromString("100 - (avg by(instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100) > 80"),
							For:   "5m",
						},
						monitoringv1.Rule{ // Swap is filling up > 80%
							Alert: "SwapIsFillingUp",
							Expr:  intstr.FromString("(1 - (node_memory_SwapFree_bytes / node_memory_SwapTotal_bytes)) * 100 > 80"),
							For:   "5m",
						},
					},
				},
			},
		},
	}

	_, err = prometheusClient.Create(promObject)
	if err != nil {
		log.Fatal("Failed to create prometheus rule", err)
		return err
	}

	return nil
}

func CreateServiceMonitor(w *InitConfig) error {
	promclientset, err := prometheus.NewForConfig(w.cfg)
	if err != nil {
		return err
	}

	// Create Prometheus Rules
	svcMonClient := promclientset.ServiceMonitors(monitoringNS)
	svcMonObject := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system-service-monitor",
			Namespace: monitoringNS,
			Labels: map[string]string{
				"prometheus": "system",
				"role":       "service-monitor",
			},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Endpoints: []monitoringv1.Endpoint{
				monitoringv1.Endpoint{
					Port: "https",
				},
			},
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "node-exporter",
				},
			},
		},
	}

	_, err = svcMonClient.Create(svcMonObject)
	if err != nil {
		log.Fatal("Failed to create service monitor", err)
		return err
	}

	return nil
}

func CreateAlertManager(w *InitConfig) error {
	var replicas int32
	replicas = 1
	cpu, _ := resource.ParseQuantity("10m")  //100m
	mem, _ := resource.ParseQuantity("52Mi") //512m

	promclientset, err := prometheus.NewForConfig(w.cfg)
	if err != nil {
		return err
	}

	// Create Prometheus Resource
	alertMgrClient := promclientset.Alertmanagers(monitoringNS)
	alertMgrObject := &monitoringv1.Alertmanager{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sysalert",
			Namespace: monitoringNS,
		},
		Spec: monitoringv1.AlertmanagerSpec{
			ServiceAccountName: "prometheus",
			Replicas:           &replicas,
			Resources: apiv1.ResourceRequirements{
				Requests: map[apiv1.ResourceName]resource.Quantity{
					"cpu":    cpu,
					"memory": mem,
				},
			},
		},
	}
	_, err = alertMgrClient.Create(alertMgrObject)
	if err != nil {
		log.Fatal("Failed to create alert manager object", err)
		return err
	}

	// Creating service for alert manager
	serviceClient := w.client.CoreV1().Services(monitoringNS)
	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alertmanager-sysalert",
			Namespace: monitoringNS,
		},
		Spec: apiv1.ServiceSpec{
			Type: "NodePort",
			Selector: map[string]string{
				"alertmanager": "sysalert",
			},
			Ports: []apiv1.ServicePort{
				{
					Name:     "web",
					Port:     9093,
					NodePort: 30903,
					Protocol: "TCP",
				},
			},
		},
	}
	_, err = serviceClient.Create(service)
	if err != nil {
		return err
	}

	return nil
}

func CreateRBAC(w *InitConfig) error {
	// Create Service Account for Prometheus
	serviceAccountClient := w.client.CoreV1().ServiceAccounts(monitoringNS)
	serviceAccount := &apiv1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus",
		},
	}
	_, err := serviceAccountClient.Create(serviceAccount)
	if err != nil {
		return err
	}

	// Create Cluster Role for Prometheus
	clusterRoleClient := w.client.RbacV1beta1().ClusterRoles()
	clusterRole := &rbac.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus",
		},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"nodes",
					"services",
					"endpoints",
					"pods",
					"configmaps",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
			{
				NonResourceURLs: []string{
					"/metrics",
				},
				Verbs: []string{
					"get",
				},
			},
		},
	}
	_, err = clusterRoleClient.Create(clusterRole)
	if err != nil {
		return err
	}

	// Create Cluster Role Binding for Prometheus
	clusterRoleBindingClient := w.client.RbacV1beta1().ClusterRoleBindings()
	clusterRoleBinding := &rbac.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus",
		},
		RoleRef: rbac.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "prometheus",
		},
		Subjects: []rbac.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "prometheus",
				Namespace: monitoringNS,
			},
		},
	}
	_, err = clusterRoleBindingClient.Create(clusterRoleBinding)
	if err != nil {
		return err
	}

	return nil
}

/*func CreateSecret(w *InitConfig) error {
	secret := apiv1.Secret{
		Type: "Opaque",

	}
	//w.client.CoreV1().Secrets
	//client.CoreV1().Secrets("").Create()
}*/
