package events

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
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"k8s.io/client-go/rest"

	"github.com/spf13/viper"

	"k8s.io/apimachinery/pkg/watch"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
)

const (
	resyncPeriod   = 5 * time.Minute
	prometheusPort = 9090
	suffixLen      = 8
)

// Watcher watches for changes in kubernetes events
type Watcher struct {
	client     kubernetes.Interface
	eventInf   cache.SharedIndexInformer
	eventQueue workqueue.RateLimitingInterface
	eventCache map[string]*evstore
	lock       sync.Mutex
}

type evstore struct {
	ev        *v1.Event
	createdAt time.Time
}

type eventCollector struct {
	eventMetric *prometheus.Desc
	w           *Watcher
}

//NewEventCollector creates new collector
func NewEventCollector(w *Watcher) *eventCollector {
	return &eventCollector{
		eventMetric: prometheus.NewDesc(
			"kubernetes_events",
			"State of kubernetes events",
			[]string{"event_namespace", "event_name", "event_kind", "event_objname", "event_reason", "event_type", "event_message", "event_source"},
			nil,
		),
		w: w,
	}
}

func (collector *eventCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.eventMetric
}

func (collector *eventCollector) Collect(ch chan<- prometheus.Metric) {

	for _, e := range collector.w.eventCache {
		ev := e.ev
		ch <- prometheus.MustNewConstMetric(collector.eventMetric, prometheus.GaugeValue, float64(ev.Count),
			ev.Namespace,
			ev.Name,
			ev.InvolvedObject.Kind,
			ev.InvolvedObject.Name,
			ev.Reason,
			ev.Type,
			ev.Message,
			ev.Source.Component,
		)
	}
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

	eventInf := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector = "type!=Normal"
				return client.CoreV1().Events(metav1.NamespaceAll).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector = "type!=Normal"
				return client.CoreV1().Events(metav1.NamespaceAll).Watch(options)
			},
		},
		&v1.Event{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	return &Watcher{
		client:     client,
		eventInf:   eventInf,
		eventQueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "prometheus"),
		eventCache: map[string]*evstore{},
		lock:       sync.Mutex{},
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
	defer w.eventQueue.ShutDown()

	go worker(w.eventQueue, w.syncEvent)

	go w.eventInf.Run(stopc)

	if err := w.waitForCacheSync(stopc); err != nil {
		return err
	}

	stop := make(chan bool)
	done := make(chan bool)
	go w.deleteEvents(stop, done)

	w.addHandlers()

	select {
	case <-stopc:
		stop <- true
		<-done
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
		{"Events", w.eventInf},
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
	w.eventInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: w.handleEventAdd,
		UpdateFunc: func(old, cur interface{}) {
			w.handleEventAdd(cur)
		},
	})
}

func (w *Watcher) handleEventAdd(obj interface{}) {
	key, ok := keyFunc(obj)
	if !ok {
		return
	}

	log.Debugf("Event added: %s", key)

	enqueue(w.eventQueue, key)
}

func (w *Watcher) syncEvent(key string) error {
	obj, exists, err := w.eventInf.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	}

	if !exists {
		return nil
	}

	e := obj.(*v1.Event)
	log.Debugf("%s/%s: %d", e.Namespace, e.Name, e.Count)

	w.lock.Lock()
	defer w.lock.Unlock()

	staleEvent := false

	oldev, existingEvent := w.eventCache[e.Name]
	if existingEvent {
		log.Debugf("Found existing event: %s", e.Name)
		if e.Count <= oldev.ev.Count {
			log.Debugf("Existing event has not changed: %s", e.Name)
			staleEvent = true
		}
	}

	if !existingEvent || !staleEvent {
		log.Debugf("Adding new event %s/%s: %d", e.Namespace, e.Name, e.Count)
		w.eventCache[e.Name] = &evstore{
			createdAt: time.Now(),
			ev:        e,
		}
	}

	/*log.Debugf("\nns: %s, \nname: %s, \nreason: %s, \nkind: %s, \ninv obj: %s, \ninv obj ns: %s,\nmsg: %s, \ncnt: %d, \nevtm: %s, \ncn: %s, \nrc: %s, \nri: %s, \nac: %s",
	e.Namespace,
	e.Name,
	e.Reason,
	e.InvolvedObject.Kind,
	e.InvolvedObject.Name,
	e.InvolvedObject.Namespace,
	e.Message,
	e.Count,
	e.EventTime,
	e.ClusterName,
	e.ReportingController,
	e.ReportingInstance,
	e.Action)*/

	return nil
}

func (w *Watcher) deleteEvent(retain int) {
	w.lock.Lock()
	defer w.lock.Unlock()
	t := time.Now()
	for n, ev := range w.eventCache {
		if t.After(ev.createdAt.Add(time.Duration(retain) * time.Minute)) {
			log.Debugf("Deleting old entry: %s/%s: %d", ev.ev.Namespace, ev.ev.Name, ev.ev.Count)
			delete(w.eventCache, n)
		}
	}
}

func (w *Watcher) deleteEvents(stop, done chan bool) {
	loop, err := strconv.Atoi(os.Getenv("EVENT_CHECK_SECS"))
	if err != nil || loop == 0 {
		loop = 60
	}
	retain, err := strconv.Atoi(os.Getenv("EVENT_RETAIN_MINS"))
	if err != nil || retain == 0 {
		retain = 60
	}

	ticker := time.NewTicker(time.Second * time.Duration(loop))
	for {
		select {
		case <-ticker.C:
			w.deleteEvent(retain)
		case <-stop:
			done <- true
			return
		}
	}
}
