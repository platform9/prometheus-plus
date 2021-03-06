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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	jsonenc "encoding/json"

	appsv1 "k8s.io/api/apps/v1"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	prometheusPort   = 9090
	alertmanagerPort = 9093
	monitoringNS     = "pf9-monitoring"
	operatorsNS      = "pf9-operators"
	defaultDashboard = "grafana-dashboard-cluster-explorer"
	ownerCfgMap      = "monitoring-owner"
)

//SystemPrometheusConfig stores system prometheus configuration
type SystemPrometheusConfig struct {
	configDir               string
	grafanaCPUResource      string
	grafanaMemResource      string
	prometheusCPUResource   string
	prometheusMemResource   string
	alertmanagerCPUResource string
	alertmanagerMemResource string

	prometheusSvcName   string
	alertmanagerSvcName string
	grafanaSvcName      string

	crdWaitTime int

	ownerInstanceName string
	ownerInstanceUID  types.UID

	portName                 string
	prometheusInstanceName   string
	alertmanagerInstanceName string

	prometheusRetentionTime string
	svcMonLabels            []string
}

// InitConfig stores configuration all system prometheus objects
type InitConfig struct {
	cfg       *rest.Config
	client    kubernetes.Interface
	mClient   monitoringclient.Interface
	crdclient clientset.Interface
	sysCfg    *SystemPrometheusConfig
}

// PromRules stores all default system prometheus rules
type PromRules struct {
	ruleGroup []monitoringv1.RuleGroup
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

func getEnv(env, def string) string {
	value, exists := os.LookupEnv(env)
	if exists {
		return value
	}
	return def
}

func getSystemPrometheusEnv() (systemcfg *SystemPrometheusConfig) {
	var syscfg SystemPrometheusConfig
	syscfg.configDir = getEnv("CONFIG_DIR", "/etc/promplus")

	waitPeriod := getEnv("CRD_WAIT_TIME_MIN", "10")
	syscfg.crdWaitTime, _ = strconv.Atoi(waitPeriod)

	syscfg.prometheusCPUResource = getEnv("PROMETHEUS_CPU_RESOURCE", "500m")
	syscfg.prometheusMemResource = getEnv("PROMETHEUS_MEM_RESOURCE", "512Mi")

	syscfg.alertmanagerCPUResource = getEnv("ALERTMANAGER_CPU_RESOURCE", "100m")
	syscfg.alertmanagerMemResource = getEnv("ALERTMANAGER_MEM_RESOURCE", "512Mi")

	syscfg.grafanaCPUResource = getEnv("GRAFANA_CPU_RESOURCE", "100m")
	syscfg.grafanaMemResource = getEnv("GRAFANA_MEM_RESOURCE", "100Mi")

	syscfg.prometheusInstanceName = getEnv("PROMETHEUS_INSTANCE_NAME", "system")
	syscfg.alertmanagerInstanceName = getEnv("ALERTMANAGER_INSTANCE_NAME", "sysalert")

	syscfg.prometheusSvcName = getEnv("PROMETHEUS_SVC_NAME", "sys-prometheus")
	syscfg.alertmanagerSvcName = getEnv("ALERTMANAGER_SVC_NAME", "sys-alertmanager")
	syscfg.grafanaSvcName = getEnv("GRAFANA_SVC_NAME", "grafana-ui")

	syscfg.portName = getEnv("PORT_NAME", "web")

	syscfg.prometheusRetentionTime = getEnv("PROMETHEUS_RETENTION_TIME", "7d")

	syscfg.ownerInstanceName = getEnv("OWNER_INSTANCE_NAME", "monitoring-owner")

	defSvcMonLabel := []string{
		"node-exporter",
		"kube-state-metrics",
		"mon-helper",
	}

	svcMonLabels := getEnv("SERVICE_MONITOR_LABELS", "")
	if svcMonLabels == "" {
		syscfg.svcMonLabels = defSvcMonLabel
	} else {
		syscfg.svcMonLabels = strings.Split(svcMonLabels, ",")
	}
	return &syscfg
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
		sysCfg:    getSystemPrometheusEnv(),
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

func (p *PromRules) walkApps(path string, f os.FileInfo, err error) error {
	if f == nil {
		return fmt.Errorf("FileInfo %s is nil  Error : %s", path, err)
	}

	if f.IsDir() || !strings.Contains(f.Name(), "json") {
		return nil
	}
	log.Debugf("Listing rule file: %s", f.Name())

	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("Failed to read file", err)
		return err
	}
	var ruleGroup monitoringv1.RuleGroup
	err = jsonenc.Unmarshal(data, &ruleGroup)
	if err != nil {
		log.Error("Failed to unmarshal rule json ", err)
		return err
	}

	p.ruleGroup = append(p.ruleGroup, ruleGroup)

	return nil
}

func (p *PromRules) walkDir(w *InitConfig) error {
	if err := filepath.Walk(w.sysCfg.configDir+"/rules", p.walkApps); err != nil {
		return err
	}

	return nil
}

// SetupSystemPrometheus deployment on a new PMK cluster
func SetupSystemPrometheus() error {
	syspc, err := new()
	if err != nil {
		log.Error(err, "when starting system prometheus controller")
		return err
	}
	if err := syspc.getOwnerUID(); err != nil {
		log.Error(err, "while getting parent UID")
		return err
	}
	if err := syspc.waitForCRD(); err != nil {
		log.Error(err, "while waiting for CRD's to come up")
		return err
	}
	if err := syspc.createPrometheus(); err != nil {
		log.Error(err, "while creating prometheus instance")
		return err
	}

	if err := syspc.createPrometheusRules(); err != nil {
		log.Error(err, "while creating prometheus rules")
		return err
	}

	if err := syspc.createServiceMonitor(); err != nil {
		log.Error(err, "while creating service-monitor instance")
		return err
	}
	if err := syspc.createAlertManager(); err != nil {
		log.Error(err, "while creating alert-manager instance")
		return err
	}
	if err := syspc.createGrafana(); err != nil {
		log.Error(err, "while creating grafana instance")
		return err
	}

	return nil
}

// waitForCRD waits for CRD's to be created
func (w *InitConfig) waitForCRD() error {
	var crds = []string{
		"prometheuses.monitoring.coreos.com",
		"prometheusrules.monitoring.coreos.com",
		"servicemonitors.monitoring.coreos.com",
		"alertmanagers.monitoring.coreos.com",
	}

	// Set timeout value for wait
	timeout := time.After(time.Duration(w.sysCfg.crdWaitTime) * time.Minute)
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

// getOwnerUID gets UID of the owner resource
func (w *InitConfig) getOwnerUID() error {

	configMapClient := w.client.CoreV1().ConfigMaps(monitoringNS)
	var options metav1.GetOptions
	cfgMap, err := configMapClient.Get(ownerCfgMap, options)
	if err != nil {
		log.Infof("Failed to get owner configmap: %s", ownerCfgMap)
		return err
	}

	w.sysCfg.ownerInstanceUID = cfgMap.ObjectMeta.UID
	return nil
}

func (w *InitConfig) createPrometheus() error {
	var replicas int32
	replicas = 1
	cpu, _ := resource.ParseQuantity(w.sysCfg.prometheusCPUResource)
	mem, _ := resource.ParseQuantity(w.sysCfg.prometheusMemResource)

	file, err := os.Open(w.sysCfg.configDir + "/additional-scrape-config.yaml")
	if err != nil {
		return err
	}
	defer file.Close()
	promSecret, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	err = createSecret(w, "scrapeconfig", monitoringNS, "additional-scrape-config.yaml", promSecret)
	if err != nil {
		return err
	}

	// Create Prometheus Resource
	prometheusClient := w.mClient.MonitoringV1().Prometheuses(monitoringNS)
	promObject := &monitoringv1.Prometheus{
		ObjectMeta: metav1.ObjectMeta{
			Name:      w.sysCfg.prometheusInstanceName,
			Namespace: monitoringNS,
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
		},
		Spec: monitoringv1.PrometheusSpec{
			ScrapeInterval: "2m",
			ServiceMonitorSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"prometheus": w.sysCfg.prometheusInstanceName,
					"role":       "service-monitor",
				},
			},
			ServiceAccountName: "system-prometheus",
			Replicas:           &replicas,
			Retention:          w.sysCfg.prometheusRetentionTime,
			RuleSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"prometheus": w.sysCfg.prometheusInstanceName,
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
				Alertmanagers: []monitoringv1.AlertmanagerEndpoints{
					monitoringv1.AlertmanagerEndpoints{
						Name:      w.sysCfg.alertmanagerSvcName,
						Namespace: monitoringNS,
						Port:      intstr.FromString(w.sysCfg.portName),
					},
				},
			},
			AdditionalScrapeConfigs: &apiv1.SecretKeySelector{
				Key: "additional-scrape-config.yaml",
				LocalObjectReference: apiv1.LocalObjectReference{
					Name: "scrapeconfig",
				},
			},
		},
	}

	var options metav1.GetOptions
	_, err = prometheusClient.Get(w.sysCfg.prometheusInstanceName, options)
	if err != nil {
		_, err = prometheusClient.Create(promObject)
		if err != nil {
			log.Errorf("Failed to create prometheus object. Error: %v", err.Error())
			return err
		}
	} else {
		log.Infof("Prometheus instance: %s already exists", w.sysCfg.prometheusInstanceName)
	}

	// Creating service for sample application
	serviceClient := w.client.CoreV1().Services(monitoringNS)
	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      w.sysCfg.prometheusSvcName,
			Namespace: monitoringNS,
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
		},
		Spec: apiv1.ServiceSpec{
			Type: "ClusterIP",
			Selector: map[string]string{
				"prometheus": w.sysCfg.prometheusInstanceName,
			},
			Ports: []apiv1.ServicePort{
				{
					Name:     w.sysCfg.portName,
					Port:     9090,
					Protocol: "TCP",
				},
			},
		},
	}

	_, err = serviceClient.Get(w.sysCfg.prometheusSvcName, options)
	if err != nil {
		_, err = serviceClient.Create(service)
		if err != nil {
			log.Errorf("Failed to create prometheus service Error: %v", err.Error())
			return err
		}
	} else {
		log.Infof("Prometheus service: %s already exists", w.sysCfg.prometheusSvcName)
	}

	return nil
}

func (w *InitConfig) createPrometheusRules() error {
	p := &PromRules{}
	p.walkDir(w)

	for _, rule := range p.ruleGroup {
		log.Debugf("Found rule: %s", rule.Name)
	}

	// Create Prometheus Rules Resource
	prometheusRulesClient := w.mClient.MonitoringV1().PrometheusRules(monitoringNS)
	promObject := &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system-prometheus-rules",
			Namespace: monitoringNS,
			Labels: map[string]string{
				"prometheus": w.sysCfg.prometheusInstanceName,
				"role":       "alert-rules",
			},
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: p.ruleGroup,
		},
	}

	var options metav1.GetOptions
	_, err := prometheusRulesClient.Get("system-prometheus-rules", options)
	if err != nil {
		_, err = prometheusRulesClient.Create(promObject)
		if err != nil {
			log.Errorf("Failed to create prometheus rule object. Error: %v", err.Error())
			return err
		}
	} else {
		log.Info("Prometheus rule object: system-prometheus-rules already exists")
	}

	return nil
}

func (w *InitConfig) createServiceMonitor() error {
	// Create Service Monitor Resource
	serviceMonitorClient := w.mClient.MonitoringV1().ServiceMonitors(monitoringNS)
	svcMonObject := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "system-service-monitor",
			Namespace: monitoringNS,
			Labels: map[string]string{
				"prometheus": w.sysCfg.prometheusInstanceName,
				"role":       "service-monitor",
			},
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Endpoints: []monitoringv1.Endpoint{
				monitoringv1.Endpoint{
					Port: w.sysCfg.portName,
				},
			},
			Selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					metav1.LabelSelectorRequirement{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   w.sysCfg.svcMonLabels,
					},
				},
			},
			NamespaceSelector: monitoringv1.NamespaceSelector{
				MatchNames: []string{
					monitoringNS,
					operatorsNS,
				},
			},
		},
	}

	var options metav1.GetOptions
	_, err := serviceMonitorClient.Get("system-service-monitor", options)
	if err != nil {
		_, err = serviceMonitorClient.Create(svcMonObject)
		if err != nil {
			log.Errorf("Failed to create prometheus rule object. Error: %v", err.Error())
			return err
		}
	} else {
		log.Info("Prometheus service monitor: system-service-monitor already exists")
	}

	return nil
}

func (w *InitConfig) createAlertManager() error {
	var replicas int32
	replicas = 1
	cpu, _ := resource.ParseQuantity(w.sysCfg.alertmanagerCPUResource)
	mem, _ := resource.ParseQuantity(w.sysCfg.alertmanagerMemResource)

	file, err := os.Open(w.sysCfg.configDir + "/alertmanager.yaml")
	if err != nil {
		log.Errorf("Failed to open alertmanager secret file Error: %v", err.Error())
		return err
	}
	defer file.Close()
	alertmgrSecret, err := ioutil.ReadAll(file)
	if err != nil {
		log.Errorf("Failed to read alertmanager secret file Error: %v", err.Error())
		return err
	}

	err = createSecret(w, "alertmanager-"+w.sysCfg.alertmanagerInstanceName, monitoringNS, "alertmanager.yaml", alertmgrSecret)
	if err != nil {
		return err
	}

	// Create Alert Manager Resource
	alertMgrClient := w.mClient.MonitoringV1().Alertmanagers(monitoringNS)
	alertMgrObject := &monitoringv1.Alertmanager{
		ObjectMeta: metav1.ObjectMeta{
			Name:      w.sysCfg.alertmanagerInstanceName,
			Namespace: monitoringNS,
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
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

	var options metav1.GetOptions
	_, err = alertMgrClient.Get(w.sysCfg.alertmanagerInstanceName, options)
	if err != nil {
		_, err = alertMgrClient.Create(alertMgrObject)
		if err != nil {
			log.Errorf("Failed to create alertmanager object. Error: %v", err.Error())
			return err
		}
	} else {
		log.Infof("Alertmanager object: %s already exists", w.sysCfg.alertmanagerInstanceName)
	}

	// Creating service for alert manager
	serviceClient := w.client.CoreV1().Services(monitoringNS)
	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      w.sysCfg.alertmanagerSvcName,
			Namespace: monitoringNS,
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
		},
		Spec: apiv1.ServiceSpec{
			Type: "ClusterIP",
			Selector: map[string]string{
				"alertmanager": w.sysCfg.alertmanagerInstanceName,
			},
			Ports: []apiv1.ServicePort{
				{
					Name:     w.sysCfg.portName,
					Port:     9093,
					Protocol: "TCP",
				},
			},
		},
	}

	_, err = serviceClient.Get(w.sysCfg.alertmanagerSvcName, options)
	if err != nil {
		_, err = serviceClient.Create(service)
		if err != nil {
			log.Errorf("Failed to create Alertmanager service Error: %v", err.Error())
			return err
		}
	} else {
		log.Infof("Alertmanager service: %s already exists", w.sysCfg.alertmanagerSvcName)
	}

	return nil
}

func getDashboards(configDir string) ([]string, error) {
	// Walk config dir and create configmaps for each dashboard.
	configFiles := make([]string, 0)
	if err := filepath.Walk(configDir, func(path string, f os.FileInfo, err error) error {
		fName := strings.ToLower(f.Name())
		if !strings.HasPrefix(fName, "grafana-dashboard-") {
			log.Debugf("Skipping %s, not a dashboard", fName)
			return nil
		}
		log.Debugf("Treating %s as dashboard", fName)
		configFiles = append(configFiles, fName)

		return nil
	}); err != nil {
		return []string{}, err
	}

	return configFiles, nil
}

func getVolumeMounts(dashboards []string) []apiv1.VolumeMount {
	volumeMounts := []apiv1.VolumeMount{
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
	}

	index := 0
	for _, d := range dashboards {
		if d == defaultDashboard {
			volumeMounts = append(volumeMounts, apiv1.VolumeMount{
				Name:      d,
				MountPath: "/usr/share/grafana/public/dashboards/home.json",
				SubPath:   "home.json",
				ReadOnly:  false,
			})
			continue
		}
		volumeMounts = append(volumeMounts, apiv1.VolumeMount{
			Name:      d,
			MountPath: fmt.Sprintf("/grafana-dashboard-definitions/%d/%s", index, d),
			ReadOnly:  false,
		})
		index++
	}

	return volumeMounts
}

func getVolumes(dashboards []string) []apiv1.Volume {
	volumes := []apiv1.Volume{
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
	}

	for _, d := range dashboards {
		volumes = append(volumes, apiv1.Volume{
			Name: d,
			VolumeSource: apiv1.VolumeSource{
				ConfigMap: &apiv1.ConfigMapVolumeSource{
					LocalObjectReference: apiv1.LocalObjectReference{
						Name: d,
					},
				},
			},
		})
	}

	return volumes
}

func (w *InitConfig) createGrafana() error {
	var replicas int32
	replicas = 1
	cpu, _ := resource.ParseQuantity(w.sysCfg.grafanaCPUResource)

	mem, _ := resource.ParseQuantity(w.sysCfg.grafanaMemResource)

	// Create Secret for Grafana
	file, err := os.Open(w.sysCfg.configDir + "/grafana-datasources")
	if err != nil {
		log.Errorf("Failed to open grafana secret file Error: %v", err.Error())
		return err
	}
	defer file.Close()
	secretData, err := ioutil.ReadAll(file)
	if err != nil {
		log.Errorf("Failed to read grafana secret file Error: %v", err.Error())
		return err
	}

	err = createSecret(w, "grafana-datasources", monitoringNS, "datasources.yaml", secretData)
	if err != nil {
		return err
	}

	// Create configmap for adding dashboard in Grafana
	err = createConfigMap(w, "grafana-dashboards", monitoringNS, "dashboards.yaml", w.sysCfg.configDir+"/grafana-dashboards")
	if err != nil {
		return err
	}

	dashboards, err := getDashboards(w.sysCfg.configDir)
	if err != nil {
		log.Errorf("Failed to get grafana dashboards Error: %v", err.Error())
		return err
	}

	// Configmaps for dashboards
	for _, cfgFile := range dashboards {
		log.Debugf("Creating configmap for %s", cfgFile)
		if cfgFile == defaultDashboard {
			if err := createConfigMap(w, cfgFile, monitoringNS, "home.json", w.sysCfg.configDir+"/"+cfgFile); err != nil {
				return err
			}
			continue
		}
		if err := createConfigMap(w, cfgFile, monitoringNS, cfgFile+".json", w.sysCfg.configDir+"/"+cfgFile); err != nil {
			return err
		}
	}

	// Create configmap for adding nginx configs in Grafana
	err = createConfigMap(w, "nginx-conf", monitoringNS, "nginx.conf", w.sysCfg.configDir+"/nginx-config")
	if err != nil {
		return err
	}

	// Create configmap for adding grafana configs
	err = createConfigMap(w, "grafana-conf", monitoringNS, "grafana.ini", w.sysCfg.configDir+"/grafana-config")
	if err != nil {
		return err
	}

	// Create deployment for grafana
	deploymentClient := w.client.AppsV1().Deployments(monitoringNS)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grafana",
			Namespace: monitoringNS,
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
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
							Name:            "proxy",
							Image:           "nginx:stable",
							ImagePullPolicy: "IfNotPresent",
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
							Image: "grafana/grafana:7.2.0",
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
							VolumeMounts: getVolumeMounts(dashboards),
						},
					},
					Volumes: getVolumes(dashboards),
				},
			},
		},
	}

	var options metav1.GetOptions
	_, err = deploymentClient.Get("grafana", options)
	if err != nil {
		_, err = deploymentClient.Create(deployment)
		if err != nil {
			log.Errorf("Failed to create grafana deployment Error: %v", err.Error())
			return err
		}
	} else {
		log.Info("grafana deployment already exists")
	}

	// Create service for grafana
	serviceClient := w.client.CoreV1().Services(monitoringNS)
	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      w.sysCfg.grafanaSvcName,
			Namespace: monitoringNS,
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
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

	_, err = serviceClient.Get(w.sysCfg.grafanaSvcName, options)
	if err != nil {
		_, err = serviceClient.Create(service)
		if err != nil {
			log.Errorf("Failed to create grafana service %s Error: %v", w.sysCfg.grafanaSvcName, err.Error())
			return err
		}
	} else {
		log.Infof("grafana service: %s already exists", w.sysCfg.grafanaSvcName)
	}

	return nil
}

func createSecret(w *InitConfig, name string, namespace string, key string, data []byte) error {
	secretClient := w.client.CoreV1().Secrets(namespace)
	secret := &apiv1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
		},
		Data: map[string][]byte{
			key: data,
		},
	}

	var options metav1.GetOptions
	_, err := secretClient.Get(name, options)
	if err != nil {
		_, err = secretClient.Create(secret)
		if err != nil {
			log.Errorf("Failed to create secret %s Error: %v", name, err.Error())
			return err
		}
	} else {
		log.Infof("secret: %s already exists", name)
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
			OwnerReferences: []metav1.OwnerReference{
				getDefaultOwnerRefs(w),
			},
		},
		Data: map[string]string{
			param: string(configData),
		},
	}

	var options metav1.GetOptions
	_, err = configMapClient.Get(name, options)
	if err != nil {
		_, err = configMapClient.Create(configMap)
		if err != nil {
			log.Errorf("Failed to create configmap %s Error: %v", name, err.Error())
			return err
		}
	} else {
		log.Infof("configmap: %s already exists", name)
	}

	return nil
}

func boolPtr(i bool) *bool { return &i }

func getDefaultOwnerRefs(w *InitConfig) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion:         "v1",
		BlockOwnerDeletion: boolPtr(false),
		Controller:         boolPtr(false),
		Kind:               "ConfigMap",
		Name:               w.sysCfg.ownerInstanceName,
		UID:                w.sysCfg.ownerInstanceUID,
	}
}
