package prometheus

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
	"time"

	"gopkg.in/yaml.v2"

	"github.com/platform9/prometheus-plus/pkg/util"
	"github.com/spf13/viper"
	"k8s.io/client-go/rest"

	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/apimachinery/pkg/watch"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
)

const (
	resyncPeriod     = 5 * time.Minute
	prometheusPort   = 9090
	alertmanagerPort = 9093
	suffixLen        = 8
	configDir        = "/etc/promplus"
	monitoringNS     = "pf9-monitoring"
)

type global struct {
	ResolveTimeout string `yaml:"resolve_timeout"`
}

type route struct {
	GroupBy        []string `yaml:"group_by"`
	GroupWait      string   `yaml:"group_wait"`
	GroupInterval  string   `yaml:"group_interval"`
	RepeatInterval string   `yaml:"repeat_interval"`
	Receiver       string   `yaml:"receiver"`
}

type slackconfig struct {
	ApiURL  string `yaml:"api_url"`
	Channel string `yaml:"channel"`
}

type emailconfig struct {
	To        string `yaml:"to"`
	From      string `yaml:"from"`
	SmartHost string `yaml:"smarthost"`
}

type receiver struct {
	Name         string        `yaml:"name"`
	SlackConfigs []slackconfig `yaml:"slack_configs,omitempty"`
	EmailConfigs []emailconfig `yaml:"email_configs,omitempty"`
}

type alertConfig struct {
	Global    global     `yaml:"global"`
	Route     route      `yaml:"route"`
	Receivers []receiver `yaml:"receivers"`
}

type format interface {
	formatAlert(amc *monitoringv1.AlertmanagerConfig, acfg *alertConfig) error
}

// Watcher watches for changes in Prometheus and AlertManager objects
type Watcher struct {
	client    kubernetes.Interface
	mClient   monitoringclient.Interface
	promInf   cache.SharedIndexInformer
	amInf     cache.SharedIndexInformer
	amcInf    cache.SharedIndexInformer
	promQueue workqueue.RateLimitingInterface
	amQueue   workqueue.RateLimitingInterface
	amcQueue  workqueue.RateLimitingInterface
}

// New returns new instance of watcher
func New() (*Watcher, error) {
	// TODO: make flag-dependent
	switch viper.GetString("mode") {
	case "standalone":
		return getByKubeCfg()
	case "k8s":
		return getInCluster()
	}

	return nil, errors.New("Invalid mode")
}

func buildWatcher(cfg *rest.Config) (*Watcher, error) {
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating kubernetes client")
	}

	mclient, err := monitoringclient.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating monitoring client")
	}

	promInf := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return mclient.MonitoringV1().Prometheuses(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return mclient.MonitoringV1().Prometheuses(metav1.NamespaceAll).Watch(options)
			},
		},
		&monitoringv1.Prometheus{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	amInf := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return mclient.MonitoringV1().Alertmanagers(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return mclient.MonitoringV1().Alertmanagers(metav1.NamespaceAll).Watch(options)
			},
		},
		&monitoringv1.Alertmanager{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	amcInf := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return mclient.MonitoringV1().AlertmanagerConfigs(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return mclient.MonitoringV1().AlertmanagerConfigs(metav1.NamespaceAll).Watch(options)
			},
		},
		&monitoringv1.AlertmanagerConfig{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	return &Watcher{
		client:    client,
		mClient:   mclient,
		promInf:   promInf,
		amInf:     amInf,
		amcInf:    amcInf,
		promQueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "prometheus"),
		amQueue:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "alertmanager"),
		amcQueue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "alertmanagerconfig"),
	}, nil
}

func getInCluster() (*Watcher, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return buildWatcher(cfg)
}

func getByKubeCfg() (*Watcher, error) {
	defaultKubeCfg := path.Join(os.Getenv("HOME"), ".kube", "config")

	if os.Getenv("KUBECONFIG") != "" {
		defaultKubeCfg = os.Getenv("KUBECONFIG")
	}

	cfg, err := clientcmd.BuildConfigFromFlags("", defaultKubeCfg)
	if err != nil {
		return nil, errors.Wrap(err, "building kubecfg")
	}

	return buildWatcher(cfg)
}

func keyFunc(obj interface{}) (string, bool) {
	k, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		log.Error(err, "creating key failed")
		return "", false
	}

	return k, true
}

func enqueue(queue workqueue.RateLimitingInterface, obj interface{}) {
	if obj == nil {
		return
	}

	key, ok := obj.(string)
	if !ok {
		key, ok = keyFunc(obj)
		if !ok {
			return
		}
	}
	queue.Add(key)
}

// Run starts sync workers
func (w *Watcher) Run(stopc <-chan struct{}) error {
	log.Debug("In prom run")
	defer w.promQueue.ShutDown()
	defer w.amQueue.ShutDown()

	go worker(w.promQueue, w.syncPrometheus)
	go worker(w.amQueue, w.syncAlertManager)
	go worker(w.amcQueue, w.syncAlertManagerConfig)

	go w.promInf.Run(stopc)
	go w.amInf.Run(stopc)
	go w.amcInf.Run(stopc)

	if err := w.waitForCacheSync(stopc); err != nil {
		return err
	}

	w.addHandlers()
	select {
	case <-stopc:
		return nil
	}
}

// waitForCacheSync waits for the informers' caches to be synced.
func (w *Watcher) waitForCacheSync(stopc <-chan struct{}) error {
	ok := true
	informers := []struct {
		name     string
		informer cache.SharedIndexInformer
	}{
		{"Prometheus", w.promInf},
		{"Alertmanager", w.amInf},
		{"AlertmanagerConfig", w.amcInf},
	}

	for _, inf := range informers {
		if !cache.WaitForCacheSync(stopc, inf.informer.HasSynced) {
			log.Errorf("failed to sync %s cache", inf.name)
			ok = false
		} else {
			log.Debugf("successfully synced %s cache", inf.name)
		}
	}
	if !ok {
		return errors.New("failed to sync caches")
	}
	log.Info("successfully synced all caches")
	return nil
}

func worker(queue workqueue.RateLimitingInterface, syncFn func(string) error) {
	for processNext(queue, syncFn) {
	}
}

func processNext(queue workqueue.RateLimitingInterface, syncFn func(string) error) bool {
	key, quit := queue.Get()
	log.Debugf("Processing key in processnext: %s", key)
	if quit {
		return false
	}

	defer queue.Done(key)
	log.Debug("Calling sync function")
	err := syncFn(key.(string))
	if err == nil {
		queue.Forget(key)
		return true
	}

	log.Error(err, "sync failed")
	queue.AddRateLimited(key)

	return true
}

func (w *Watcher) addHandlers() {
	w.promInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.handlePrometheusAdd,
		DeleteFunc: w.handlePrometheusDelete,
	})
	w.amInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.handleAlertmanagerAdd,
		DeleteFunc: w.handleAlertmanagerDelete,
	})
	w.amcInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.handleAlertmanagerConfigAdd,
		UpdateFunc: w.handleAlertmanagerConfigUpdate,
		DeleteFunc: w.handleAlertmanagerConfigDelete,
	})
}

func (w *Watcher) handlePrometheusAdd(obj interface{}) {
	key, ok := keyFunc(obj)
	if !ok {
		return
	}

	log.Debugf("Prometheus added: %s", key)

	enqueue(w.promQueue, key)
}

func (w *Watcher) checkSvcExists(ns string, annotations map[string]string) (bool, error) {
	if annotations == nil {
		return false, nil
	}

	svcName, ok := annotations["service"]
	if !ok {
		return false, nil
	}

	_, err := w.client.CoreV1().Services(ns).Get(svcName, metav1.GetOptions{})

	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (w *Watcher) deleteSecret(ns string, secretName string) (bool, error) {

	err := w.client.CoreV1().Secrets(ns).Delete(secretName, &metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (w *Watcher) checkSecretExists(ns string, secretName string) (bool, error) {

	_, err := w.client.CoreV1().Secrets(ns).Get(secretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (w *Watcher) handlePrometheusDelete(obj interface{}) {
	key, ok := keyFunc(obj)
	if !ok {
		return
	}

	log.Debugf("Prometheus deleted: %s", key)

	enqueue(w.promQueue, key)
}

func (w *Watcher) createSvc(obj metav1.ObjectMeta, kind string, selector map[string]string, port int32, portName string) (map[string]string, error) {
	svcClient := w.client.CoreV1().Services(obj.GetNamespace())
	svcName := fmt.Sprintf("%s-%s", obj.GetName(), util.RandString(suffixLen))
	annotations := map[string]string{}
	_, err := svcClient.Get(svcName, metav1.GetOptions{})
	if err == nil {
		return annotations, nil
	}

	if !apierrors.IsNotFound(err) {
		return annotations, err
	}

	trueVar := true

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
			OwnerReferences: []metav1.OwnerReference{
				metav1.OwnerReference{
					APIVersion: monitoringv1.SchemeGroupVersion.String(),
					Name:       obj.GetName(),
					Kind:       kind,
					UID:        obj.GetUID(),
					Controller: &trueVar,
				},
			},
			Annotations: map[string]string{
				"created_by": "monhelper",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				v1.ServicePort{
					Name:       portName,
					Port:       port,
					Protocol:   v1.ProtocolTCP,
					TargetPort: intstr.FromString(portName),
				},
			},
			Selector: selector,
		},
	}

	if svc, err = svcClient.Create(svc); err != nil {
		return annotations, err
	}

	annotations["service"] = svcName
	annotations["service_path"] = fmt.Sprintf("%s:%s/proxy", svc.SelfLink, portName)

	return annotations, nil
}

func (w *Watcher) getFormatter(ftype string) (format, error) {
	var f format
	switch ftype {
	case "slack":
		log.Debug("Creating slack object")
		f = slackconfig{}
	case "email":
		log.Debug("Creating email object")
		f = emailconfig{}
	default:
		log.Errorf("Got an invalid type: %s", ftype)
		return nil, os.ErrInvalid
	}

	return f, nil
}

func (w *Watcher) formatReceiver(amc *monitoringv1.AlertmanagerConfig, acfg *alertConfig) error {

	var f format
	f, err := w.getFormatter(amc.Spec.Type)
	if err != nil {
		log.Errorf("Failed to create a formatter: %s for %s", amc.Spec.Type, amc.Name)
		return err
	}

	err = f.formatAlert(amc, acfg)
	if err != nil {
		log.Errorf("Failed to format alert: %s for %s", amc.Spec.Type, amc.Name)
		return err
	}

	return nil
}

func (f slackconfig) formatAlert(amc *monitoringv1.AlertmanagerConfig, acfg *alertConfig) error {
	var url, channel string
	for _, param := range amc.Spec.Params {
		log.Debugf("Params: %s %s", param.Name, param.Value)
		switch param.Name {
		case "url":
			url = param.Value
		case "channel":
			channel = param.Value
		}
	}

	if url == "" {
		log.Error("url field missing in slack config")
		return os.ErrInvalid
	}

	if channel == "" {
		log.Error("channel field missing in slack config")
		return os.ErrInvalid
	}

	acfg.Receivers[0].SlackConfigs = append(acfg.Receivers[0].SlackConfigs,
		slackconfig{
			ApiURL:  url,
			Channel: channel,
		})

	return nil
}

func (f emailconfig) formatAlert(amc *monitoringv1.AlertmanagerConfig, acfg *alertConfig) error {
	var to, from, smarthost string
	for _, param := range amc.Spec.Params {
		log.Debugf("Params: %s %s", param.Name, param.Value)
		switch param.Name {
		case "to":
			to = param.Value
		case "from":
			from = param.Value
		case "smarthost":
			smarthost = param.Value
		}
	}

	if to == "" {
		log.Error("to field missing in email config")
		return os.ErrInvalid
	}

	if from == "" {
		log.Error("from field missing in email config")
		return os.ErrInvalid
	}

	if smarthost == "" {
		log.Error("smarthost field missing in email config")
		return os.ErrInvalid
	}

	acfg.Receivers[0].EmailConfigs = append(acfg.Receivers[0].EmailConfigs,
		emailconfig{
			To:        to,
			From:      from,
			SmartHost: smarthost,
		})

	return nil
}

func (w *Watcher) createSecret(obj metav1.ObjectMeta, secretName string, kind string, data []byte) error {
	secretClient := w.client.CoreV1().Secrets(obj.GetNamespace())

	trueVar := true

	cfg := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: monitoringNS,
			OwnerReferences: []metav1.OwnerReference{
				metav1.OwnerReference{
					APIVersion: monitoringv1.SchemeGroupVersion.String(),
					Name:       obj.GetName(),
					Kind:       kind,
					UID:        obj.GetUID(),
					Controller: &trueVar,
				},
			},
			Annotations: map[string]string{
				"created_by": "monhelper",
			},
		},
		Data: map[string][]byte{
			"alertmanager.yaml": data,
		},
	}

	if _, err := secretClient.Create(cfg); err != nil {
		log.Errorf("Failed to create secret: %s", secretName)
		return err
	}

	log.Debugf("Created secret: %s", secretName)
	return nil
}

func merge(a, b map[string]string) map[string]string {
	if a == nil {
		return b
	}

	if b == nil {
		return a
	}

	for k, v := range b {
		if _, ok := a[k]; !ok {
			a[k] = v
		}
	}

	return a
}

func (w *Watcher) syncPrometheus(key string) error {
	log.Debug("In sync Prometheus function")
	obj, exists, err := w.promInf.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	}

	if !exists {
		// Service has ownerref set to prometheus. No action needed.
		return nil
	}

	p := obj.(*monitoringv1.Prometheus)

	log.Infof("syncing prometheus: %s", key)

	exists, err = w.checkSvcExists(p.Namespace, p.Annotations)
	if err != nil {
		return err
	}

	if exists {
		log.Infof("service for prometheus: %s exists", key)
		return nil
	}

	annotations, err := w.createSvc(p.ObjectMeta, monitoringv1.PrometheusesKind, map[string]string{
		"prometheus": p.Name,
	}, prometheusPort, "web")

	if err != nil {
		return err
	}

	p.ObjectMeta.Annotations = merge(p.ObjectMeta.Annotations, annotations)
	_, err = w.mClient.MonitoringV1().Prometheuses(p.Namespace).Update(p)
	return err
}

func (w *Watcher) handleAlertmanagerAdd(obj interface{}) {
	key, ok := keyFunc(obj)
	if !ok {
		return
	}

	log.Debugf("Alertmanager added: %s", key)

	enqueue(w.amQueue, key)
}

func (w *Watcher) handleAlertmanagerDelete(obj interface{}) {
	key, ok := keyFunc(obj)
	if !ok {
		return
	}

	log.Debugf("Alertmanager deleted: %s", key)

	enqueue(w.amQueue, key)
}

func (w *Watcher) syncAlertManager(key string) error {
	obj, exists, err := w.amInf.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	}

	if !exists {
		// Service has ownerref set to prometheus. No action needed.
		return nil
	}

	am := obj.(*monitoringv1.Alertmanager)

	log.Infof("syncing alert manager: %s", key)

	exists, err = w.checkSvcExists(am.Namespace, am.Annotations)
	if err != nil {
		return err
	}

	if exists {
		log.Infof("service for alertmanager: %s exists", key)
		return nil
	}

	annotations, err := w.createSvc(am.ObjectMeta, monitoringv1.AlertmanagersKind, map[string]string{
		"alertmanager": am.Name,
	}, alertmanagerPort, "web")

	if err != nil {
		return err
	}

	am.ObjectMeta.Annotations = merge(am.ObjectMeta.Annotations, annotations)
	_, err = w.mClient.MonitoringV1().Alertmanagers(am.Namespace).Update(am)
	return err
}

func (w *Watcher) handleAlertmanagerConfigAdd(obj interface{}) {
	key, ok := keyFunc(obj)
	if !ok {
		return
	}

	log.Debugf("Alertmanager config added: %s", key)

	enqueue(w.amcQueue, key)
}

func (w *Watcher) handleAlertmanagerConfigUpdate(oldObj, newObj interface{}) {
	key, ok := keyFunc(newObj)
	if !ok {
		return
	}

	log.Debugf("Alertmanager config added: %s", key)

	enqueue(w.amcQueue, key)
}

func (w *Watcher) handleAlertmanagerConfigDelete(obj interface{}) {
	key, ok := keyFunc(obj)
	if !ok {
		return
	}

	log.Debugf("Alertmanager config deleted: %s", key)

	enqueue(w.amcQueue, key)
}

func (w *Watcher) syncAlertManagerConfig(key string) error {
	var alertManagerName string

	log.Debugf("syncing alert manager config: key: %s", key)
	obj, exists, err := w.amcInf.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	}

	if !exists {
		log.Errorf("Key %s not found...", key)
		return nil
	}

	amc := obj.(*monitoringv1.AlertmanagerConfig)
	if nil == amc {
		log.Errorf("Got an invalid amc object for: %s", key)
		return nil
	}

	log.Debugf("syncing alert manager config: key: %s, type: %s", key, amc.Spec.Type)
	for key, val := range amc.Labels {
		log.Debugf("Labels: %s %s", key, val)
		if key == "alertmanager" {
			alertManagerName = val
			break
		}
	}
	log.Debugf("Alert manager label: %s", alertManagerName)

	if alertManagerName == "" {
		log.Errorf("Alert manager label missing in alertmanager config: %s", key)
		return nil
	}

	file, err := os.Open(configDir + "/alertmanager.yaml")
	if err != nil {
		log.Error("Failed to open alert manager config file", err)
		return os.ErrInvalid
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Error("Failed to read alert manager config file", err)
		return os.ErrInvalid
	}

	var acfg alertConfig
	yaml.Unmarshal(data, &acfg)

	err = w.formatReceiver(amc, &acfg)
	if err != nil {
		log.Errorf("Failed to format receiver for: %s", amc.Spec.Type)
		return err
	}

	var options metav1.ListOptions
	var amcList *monitoringv1.AlertmanagerConfigList
	amcList, err = w.mClient.MonitoringV1().AlertmanagerConfigs(metav1.NamespaceAll).List(options)
	if err != nil {
		log.Error("Failed to get list of alert manager config objects ", err)
		return err
	}
	for _, amcItr := range amcList.Items {
		log.Debugf("Name: %s, ns: %s", amcItr.Name, amcItr.Namespace)

		for key, val := range amcItr.Labels {
			log.Infof("Labels: %s %s", key, val)
			if key == "alertmanager" && val == alertManagerName {
				if amc.Name == amcItr.Name {
					log.Debugf("Ignoring current amc object: %s", amcItr.Name)
					continue
				}
				log.Debugf("Formatting receiver for: %s", amcItr.Name)
				err = w.formatReceiver(amcItr, &acfg)
				if err != nil {
					log.Errorf("Failed to format receiver for: %s", amc.Spec.Type)
					return err
				}
			}
		}
	}

	secretName := "alertmanager-" + alertManagerName

	exists, _ = w.checkSecretExists(amc.Namespace, secretName)
	if exists {
		log.Infof("Secret for alertmanager: %s exists deleting it", key)
		_, err = w.deleteSecret(amc.Namespace, secretName)
		if err != nil {
			log.Errorf("Failed to delete secret: %s", secretName)
			return err
		}
	}

	data, err = yaml.Marshal(&acfg)
	if err != nil {
		log.Error("Failed to marshal alert mgr secret ", err)
		return err
	}

	err = w.createSecret(amc.ObjectMeta, secretName, monitoringv1.AlertmanagersKind, data)
	if err != nil {
		return err
	}
	log.Infof("Created secret: %s for %s", secretName, key)
	return nil
}
