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
	"flag"
	"reflect"
	"testing"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var w *Watcher

func TestMain(m *testing.M) {
	w = &Watcher{}
}
func init() {
	viper.Set("mode", flag.String("mode", "standalone", "kubernetes configuration mode"))
}

func TestGetByKubeCfg(t *testing.T) {
	assert.Equal(t, reflect.TypeOf(w), reflect.TypeOf(&Watcher{}))
}

func TestGetFormatter(t *testing.T) {
	var f format
	f, err := w.getFormatter("slack")
	assert.Equal(t, nil, err)
	assert.Equal(t, reflect.TypeOf(f), reflect.TypeOf(slackconfig{}))

	f, err = w.getFormatter("email")
	assert.Equal(t, nil, err)
	assert.Equal(t, reflect.TypeOf(f), reflect.TypeOf(emailconfig{}))
}

func TestSlackFormat(t *testing.T) {
	URL := "https://hooks.slack.com/services/xxx/yyy"
	channel := "#alertmgr"

	amc := monitoringv1.AlertmanagerConfig{
		Spec: monitoringv1.AlertmanagerConfigSpec{
			Type: "slack",
			Params: []monitoringv1.Param{
				monitoringv1.Param{
					Name:  "url",
					Value: URL,
				},
				monitoringv1.Param{
					Name:  "channel",
					Value: channel,
				},
			},
		},
	}

	acfg := alertConfig{
		Receivers: []receiver{
			receiver{
				Name: "webhook",
			},
		},
	}
	err := w.formatReceiver(&amc, &acfg)
	assert.Equal(t, nil, err)

	assert.Equal(t, acfg.Receivers[0].SlackConfigs[0].ApiURL, URL)
	assert.Equal(t, acfg.Receivers[0].SlackConfigs[0].Channel, channel)
}

func TestEmailFormat(t *testing.T) {
	to := "to@p9.com"
	from := "from@p9.com"
	smarthost := "p9.local:8887"

	amc := monitoringv1.AlertmanagerConfig{
		Spec: monitoringv1.AlertmanagerConfigSpec{
			Type: "email",
			Params: []monitoringv1.Param{
				monitoringv1.Param{
					Name:  "to",
					Value: to,
				},
				monitoringv1.Param{
					Name:  "from",
					Value: from,
				},
				monitoringv1.Param{
					Name:  "smarthost",
					Value: smarthost,
				},
			},
		},
	}

	acfg := alertConfig{
		Receivers: []receiver{
			receiver{
				Name: "webhook",
			},
		},
	}

	err := w.formatReceiver(&amc, &acfg)
	assert.Equal(t, nil, err)

	assert.Equal(t, acfg.Receivers[0].EmailConfigs[0].To, to)
	assert.Equal(t, acfg.Receivers[0].EmailConfigs[0].From, from)
	assert.Equal(t, acfg.Receivers[0].EmailConfigs[0].SmartHost, smarthost)
}
