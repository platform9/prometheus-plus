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
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type kpod struct {
	Pod   v1.Pod     `json:"pod"`
	Event []v1.Event `json:"events"`
}

//Describe all pods
func (w *Watcher) Describe(resp http.ResponseWriter, req *http.Request) error {

	var options metav1.ListOptions
	list, err := w.client.CoreV1().Pods(metav1.NamespaceAll).List(options)
	if err != nil {
		log.Error(err, "listing pods")
		return err
	}

	klist := []kpod{}
	for _, pod := range list.Items {
		//log.Infof("Pod Name: %s", pod.ObjectMeta.Name)

		k := kpod{
			Pod:   pod,
			Event: []v1.Event{},
		}

		eventListOptions := metav1.ListOptions{FieldSelector: fmt.Sprintf("involvedObject.name=%s", pod.ObjectMeta.Name)}
		evlist, err := w.client.CoreV1().Events(pod.ObjectMeta.Namespace).List(eventListOptions)
		if err != nil {
			log.Error(err, "listing events")
			return err
		}

		for _, e := range evlist.Items {
			//log.Infof("Event: %s", e.ObjectMeta.Name)
			k.Event = append(k.Event, e)
		}

		klist = append(klist, k)
	}

	byteData, err := json.Marshal(klist)
	if err != nil {
		log.Error(err)
	}

	resp.Header().Add("Content-Type", "application/json")
	resp.Write(byteData)
	return nil
}
