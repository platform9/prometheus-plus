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
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"time"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	prometheus "github.com/coreos/prometheus-operator/pkg/client/versioned/typed/monitoring/v1"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	appsv1 "k8s.io/api/apps/v1"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	prometheusPort   = 9090
	alertmanagerPort = 9093
	monitoringNS     = "pf9-monitoring"
	configDir        = "/etc/promplus"
)

// InitConfig stores configuration all system prometheus objects
type InitConfig struct {
	cfg       *rest.Config
	client    kubernetes.Interface
	mClient   monitoringclient.Interface
	crdclient clientset.Interface
}

// New returns new instance of InitConfig
func new() (*InitConfig, error) {
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

	crdclient, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s instantiating clientset client", err.Error())
	}

	return &InitConfig{
		cfg:       cfg,
		client:    client,
		mClient:   mclient,
		crdclient: crdclient,
	}, nil
}

func getInCluster() (*InitConfig, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Error("Failed to create a in cluster kube config")
		return nil, err
	}
	log.Info("Created an in cluster kube config")
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

// SetupSystemPrometheus deployment on a new PMK cluster
func SetupSystemPrometheus() error {
	syspc, err := new()
	if err != nil {
		log.Error(err, "when starting system prometheus controller")
	}
	if err := waitForCRD(syspc); err != nil {
		log.Error(err, "while waiting for CRD's to come up")
	}
	if err := createPrometheus(syspc); err != nil {
		log.Error(err, "while creating prometheus instance")
	}
	if err := createPrometheusRules(syspc); err != nil {
		log.Error(err, "while creating prometheus rules")
	}
	if err := createServiceMonitor(syspc); err != nil {
		log.Error(err, "while creating service-monitor instance")
	}
	if err := createAlertManager(syspc); err != nil {
		log.Error(err, "while creating alert-manager instance")
	}
	if err := createGrafana(syspc); err != nil {
		log.Error(err, "while creating grafana instance")
	}

	return nil
}

// waitForCRD waits for CRD's to be created
func waitForCRD(w *InitConfig) error {
	var crds = []string{
		"prometheuses.monitoring.coreos.com",
		"prometheusrules.monitoring.coreos.com",
		"servicemonitors.monitoring.coreos.com",
		"alertmanagers.monitoring.coreos.com",
	}

	// Set timeout value for wait
	var waitPeriodValue int = 10
	waitPeriod, exists := os.LookupEnv("CRD_WAIT_TIME")
	if exists {
		waitPeriodValue, _ = strconv.Atoi(waitPeriod)
	}
	timeout := time.After(time.Duration(waitPeriodValue) * time.Minute)
	tick := time.Tick(10 * time.Second)

	for _, value := range crds {
	Loop:
		for {
			select {
			case <-timeout:
				return fmt.Errorf("CRD's not created")
			case <-tick:
				list, err := w.crdclient.ApiextensionsV1beta1().CustomResourceDefinitions().List(metav1.ListOptions{})
				if err != nil {
					log.Error("Failed to get list of CRDs")
					return err
				}
				for _, d := range list.Items {
					if d.Name == value {
						break Loop
					}
				}
			}
		}
	}
	return nil
}

// CreatePrometheus resource
func createPrometheus(w *InitConfig) error {
	var replicas int32
	replicas = 1
	cpuResource, exists := os.LookupEnv("PROMETHEUS_CPU_RESOURCE")
	if !exists {
		cpuResource = "500m"
	}
	cpu, _ := resource.ParseQuantity(cpuResource)

	memResource, exists := os.LookupEnv("PROMETHEUS_MEM_RESOURCE")
	if !exists {
		memResource = "512Mi"
	}
	mem, _ := resource.ParseQuantity(memResource)

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
			ServiceAccountName: "system-prometheus",
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
						Name:      "sys-alertmanager",
						Namespace: monitoringNS,
						Port:      intstr.FromString("web"),
					},
				},
			},
		},
	}
	_, err = prometheusClient.Create(promObject)
	if err != nil {
		return fmt.Errorf("Failed to create prometheus object. Error: %v", err.Error())
	}

	// Creating service for sample application
	serviceClient := w.client.CoreV1().Services(monitoringNS)
	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sys-prometheus",
			Namespace: monitoringNS,
		},
		Spec: apiv1.ServiceSpec{
			Type: "ClusterIP",
			Selector: map[string]string{
				"prometheus": "system",
			},
			Ports: []apiv1.ServicePort{
				{
					Name:     "web",
					Port:     9090,
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

func createPrometheusRules(w *InitConfig) error {
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
		return fmt.Errorf("Failed to create prometheus rule object. Error: %v", err.Error())
	}

	return nil
}

func createServiceMonitor(w *InitConfig) error {
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
					Port: "web",
				},
			},
			Selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					metav1.LabelSelectorRequirement{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values: []string{
							"node-exporter",
							"kube-state-metrics",
						},
					},
				},
			},
			NamespaceSelector: monitoringv1.NamespaceSelector{
				MatchNames: []string{
					monitoringNS,
				},
			},
		},
	}

	_, err = svcMonClient.Create(svcMonObject)
	if err != nil {
		return fmt.Errorf("Failed to create service-monitor object. Error: %v", err.Error())
	}

	return nil
}

func createAlertManager(w *InitConfig) error {
	var replicas int32
	replicas = 1
	cpuResource, exists := os.LookupEnv("ALERTMANAGER_CPU_RESOURCE")
	if !exists {
		cpuResource = "100m"
	}
	cpu, _ := resource.ParseQuantity(cpuResource)

	memResource, exists := os.LookupEnv("ALERTMANAGER_MEM_RESOURCE")
	if !exists {
		memResource = "512Mi"
	}
	mem, _ := resource.ParseQuantity(memResource)

	file, err := os.Open(configDir + "/alertmanager.yaml")
	if err != nil {
		return err
	}
	defer file.Close()
	alertmgrSecret, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	err = createSecret(w, "alertmanager-sysalert", monitoringNS, "alertmanager.yaml", alertmgrSecret)
	if err != nil {
		return err
	}

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
			ServiceAccountName: "system-prometheus",
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
		return fmt.Errorf("Failed to create alert-manager object. Error: %v", err.Error())
	}

	// Creating service for alert manager
	serviceClient := w.client.CoreV1().Services(monitoringNS)
	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sys-alertmanager",
			Namespace: monitoringNS,
		},
		Spec: apiv1.ServiceSpec{
			Type: "ClusterIP",
			Selector: map[string]string{
				"alertmanager": "sysalert",
			},
			Ports: []apiv1.ServicePort{
				{
					Name:     "web",
					Port:     9093,
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

func createGrafana(w *InitConfig) error {
	var replicas int32
	replicas = 1
	cpuResource, exists := os.LookupEnv("GRAFANA_CPU_RESOURCE")
	if !exists {
		cpuResource = "100m"
	}
	cpu, _ := resource.ParseQuantity(cpuResource)

	memResource, exists := os.LookupEnv("GRAFANA_MEM_RESOURCE")
	if !exists {
		memResource = "100Mi"
	}
	mem, _ := resource.ParseQuantity(memResource)

	// Create Secret for Grafana
	file, err := os.Open(configDir + "/grafana-datasources")
	if err != nil {
		return err
	}
	defer file.Close()
	secretData, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	err = createSecret(w, "grafana-datasources", monitoringNS, "datasources.yaml", secretData)
	if err != nil {
		return err
	}

	// Create configmap for adding dashboard in Grafana
	err = createConfigMap(w, "grafana-dashboards", monitoringNS, "dashboards.yaml", configDir+"/grafana-dashboards")
	if err != nil {
		return err
	}

	// Create configmap for adding prometheus dashboard definition in Grafana
	err = createConfigMap(w, "grafana-dashboard-prometheus", monitoringNS, "prometheus.json", configDir+"/grafana-dashboard-prometheus")
	if err != nil {
		return err
	}

	// Create configmap for adding node-exporter dashboard definition in Grafana
	err = createConfigMap(w, "grafana-dashboard-node-exporter", monitoringNS, "node-exporter.json", configDir+"/grafana-dashboard-node-exporter")
	if err != nil {
		return err
	}

	// Create configmap for adding nginx configs in Grafana
	err = createConfigMap(w, "nginx-conf", monitoringNS, "nginx.conf", configDir+"/nginx-config")
	if err != nil {
		return err
	}

	// Create configmap for adding grafana configs
	err = createConfigMap(w, "grafana-conf", monitoringNS, "grafana.ini", configDir+"/grafana-config")
	if err != nil {
		return err
	}

	// Create deployment for grafana
	deploymentClient := w.client.AppsV1().Deployments(monitoringNS)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grafana",
			Namespace: monitoringNS,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "grafana",
				},
			},
			Template: apiv1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "grafana",
					},
				},
				Spec: apiv1.PodSpec{
					Containers: []apiv1.Container{
						{
							Name:  "proxy",
							Image: "nginx",
							Ports: []apiv1.ContainerPort{
								{
									ContainerPort: 80,
								},
							},
							VolumeMounts: []apiv1.VolumeMount{
								{
									Name:      "nginx-conf",
									MountPath: "/etc/nginx",
									ReadOnly:  true,
								},
								{
									Name:      "log",
									MountPath: "/var/log/nginx",
								},
							},
						},
						{
							Name:  "grafana",
							Image: "grafana/grafana:6.3.2",
							Ports: []apiv1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 3000,
								},
							},
							ReadinessProbe: &apiv1.Probe{
								Handler: apiv1.Handler{
									HTTPGet: &apiv1.HTTPGetAction{
										Path: "/api/health",
										Port: intstr.IntOrString(intstr.FromString("http")),
									},
								},
							},
							Resources: apiv1.ResourceRequirements{
								Requests: map[apiv1.ResourceName]resource.Quantity{
									"cpu":    cpu,
									"memory": mem,
								},
							},
							VolumeMounts: []apiv1.VolumeMount{
								{
									Name:      "grafana-conf",
									MountPath: "/etc/grafana",
									ReadOnly:  true,
								},
								{
									Name:      "grafana-storage",
									MountPath: "/var/lib/grafana",
									ReadOnly:  false,
								},
								{
									Name:      "grafana-datasources",
									MountPath: "/etc/grafana/provisioning/datasources",
									ReadOnly:  false,
								},
								{
									Name:      "grafana-dashboards",
									MountPath: "/etc/grafana/provisioning/dashboards",
									ReadOnly:  false,
								},
								{
									Name:      "grafana-dashboard-prometheus",
									MountPath: "/grafana-dashboard-definitions/0/prometheus",
									ReadOnly:  false,
								},
								{
									Name:      "grafana-dashboard-node-exporter",
									MountPath: "/grafana-dashboard-definitions/1/node-exporter",
									ReadOnly:  false,
								},
							},
						},
					},
					Volumes: []apiv1.Volume{
						{
							Name: "grafana-storage",
							VolumeSource: apiv1.VolumeSource{
								EmptyDir: &apiv1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "log",
							VolumeSource: apiv1.VolumeSource{
								EmptyDir: &apiv1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "grafana-datasources",
							VolumeSource: apiv1.VolumeSource{
								Secret: &apiv1.SecretVolumeSource{
									SecretName: "grafana-datasources",
								},
							},
						},
						{
							Name: "nginx-conf",
							VolumeSource: apiv1.VolumeSource{
								ConfigMap: &apiv1.ConfigMapVolumeSource{
									LocalObjectReference: apiv1.LocalObjectReference{
										Name: "nginx-conf",
									},
									Items: []apiv1.KeyToPath{
										{
											Key:  "nginx.conf",
											Path: "nginx.conf",
										},
									},
								},
							},
						},
						{
							Name: "grafana-conf",
							VolumeSource: apiv1.VolumeSource{
								ConfigMap: &apiv1.ConfigMapVolumeSource{
									LocalObjectReference: apiv1.LocalObjectReference{
										Name: "grafana-conf",
									},
									Items: []apiv1.KeyToPath{
										{
											Key:  "grafana.ini",
											Path: "grafana.ini",
										},
									},
								},
							},
						},
						{
							Name: "grafana-dashboards",
							VolumeSource: apiv1.VolumeSource{
								ConfigMap: &apiv1.ConfigMapVolumeSource{
									LocalObjectReference: apiv1.LocalObjectReference{
										Name: "grafana-dashboards",
									},
								},
							},
						},
						{
							Name: "grafana-dashboard-prometheus",
							VolumeSource: apiv1.VolumeSource{
								ConfigMap: &apiv1.ConfigMapVolumeSource{
									LocalObjectReference: apiv1.LocalObjectReference{
										Name: "grafana-dashboard-prometheus",
									},
								},
							},
						},
						{
							Name: "grafana-dashboard-node-exporter",
							VolumeSource: apiv1.VolumeSource{
								ConfigMap: &apiv1.ConfigMapVolumeSource{
									LocalObjectReference: apiv1.LocalObjectReference{
										Name: "grafana-dashboard-node-exporter",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	_, err = deploymentClient.Create(deployment)
	if err != nil {
		return err
	}

	// Create service for grafana
	serviceClient := w.client.CoreV1().Services(monitoringNS)
	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grafana-ui",
			Namespace: monitoringNS,
		},
		Spec: apiv1.ServiceSpec{
			Selector: map[string]string{
				"app": "grafana",
			},
			Ports: []apiv1.ServicePort{
				{
					Port:     80,
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

func createSecret(w *InitConfig, name string, namespace string, key string, data []byte) error {
	secretClient := w.client.CoreV1().Secrets(namespace)
	secret := &apiv1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			key: data,
		},
	}
	_, err := secretClient.Create(secret)
	if err != nil {
		return err
	}
	return nil
}

func createConfigMap(w *InitConfig, name string, namespace string, param string, fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	configData, err := ioutil.ReadAll(file)

	configMapClient := w.client.CoreV1().ConfigMaps(namespace)
	configMap := &apiv1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string]string{
			param: string(configData),
		},
	}
	_, err = configMapClient.Create(configMap)
	if err != nil {
		return err
	}
	return nil
}

func int32Ptr(i int32) *int32 { return &i }
