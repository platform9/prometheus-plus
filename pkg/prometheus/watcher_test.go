package prometheus

import (
	"flag"
	"reflect"
	"testing"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func init() {
	viper.Set("mode", flag.String("mode", "standalone", "kubernetes configuration mode"))
}

func TestGetByKubeCfg(t *testing.T) {
	w := getConfig(t)
	assert.Equal(t, reflect.TypeOf(w), reflect.TypeOf(&Watcher{}))
}

func TestGetFormater(t *testing.T) {
	var f format
	w := getConfig(t)
	f, err := w.getFormater("slack")
	assert.Equal(t, nil, err)
	assert.Equal(t, reflect.TypeOf(f), reflect.TypeOf(slackconfig{}))

	f, err = w.getFormater("email")
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
	w := getConfig(t)
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

	w := getConfig(t)
	err := w.formatReceiver(&amc, &acfg)
	assert.Equal(t, nil, err)

	assert.Equal(t, acfg.Receivers[0].EmailConfigs[0].To, to)
	assert.Equal(t, acfg.Receivers[0].EmailConfigs[0].From, from)
	assert.Equal(t, acfg.Receivers[0].EmailConfigs[0].SmartHost, smarthost)
}

func getConfig(t *testing.T) *Watcher {
	w, err := New()
	if err != nil {
		t.Fatalf("Error occured while getting kubernetes config. Error is: %s", err.Error())
	}
	return w
}
