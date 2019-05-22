package prometheus

/**
 * Copyright (c) 2019, Platform9 Systems.
 * All rights reserved.
 */

import (
	"fmt"
	"os"
	"path"
	"time"

	"k8s.io/client-go/rest"

	"github.com/platform9/prometheus-plus/pkg/util"
	"github.com/spf13/viper"

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
)

// Watcher watches for changes in Prometheus and AlertManager objects
type Watcher struct {
	client    kubernetes.Interface
	mClient   monitoringclient.Interface
	promInf   cache.SharedIndexInformer
	amInf     cache.SharedIndexInformer
	promQueue workqueue.RateLimitingInterface
	amQueue   workqueue.RateLimitingInterface
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

	return &Watcher{
		client:    client,
		mClient:   mclient,
		promInf:   promInf,
		amInf:     amInf,
		promQueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "prometheus"),
		amQueue:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "alertmanager"),
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
	defer w.promQueue.ShutDown()
	defer w.amQueue.ShutDown()

	go worker(w.promQueue, w.syncPrometheus)
	go worker(w.amQueue, w.syncAlertManager)

	go w.promInf.Run(stopc)
	go w.amInf.Run(stopc)

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
	if quit {
		return false
	}

	defer queue.Done(key)

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
