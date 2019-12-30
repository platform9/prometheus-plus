package sysprom

import (
	"os"
	"testing"

	monitoringclient "github.com/coreos/prometheus-operator/pkg/client/versioned/fake"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

func init() {
	os.Setenv("CONFIG_DIR", "../../promplus")
}

func getNewConfig() *InitConfig {
	cfg := &rest.Config{
		APIPath: "/apis",
		ContentConfig: rest.ContentConfig{
			NegotiatedSerializer: scheme.Codecs,
			GroupVersion:         &appsv1.SchemeGroupVersion,
		},
	}

	client := fake.NewSimpleClientset()
	mclient := monitoringclient.NewSimpleClientset()

	return &InitConfig{
		cfg:     cfg,
		client:  client,
		mClient: mclient,
		sysCfg:  getSystemPrometheusEnv(),
	}
}

func TestPrometheus(t *testing.T) {
	syspc := getNewConfig()
	err := syspc.createPrometheus()
	assert.Equal(t, nil, err)
}

func TestPrometheusRules(t *testing.T) {
	syspc := getNewConfig()
	err := syspc.createPrometheusRules()
	assert.Equal(t, nil, err)
}

func TestServiceMonitor(t *testing.T) {
	syspc := getNewConfig()
	err := syspc.createServiceMonitor()
	assert.Equal(t, nil, err)
}

func TestAlertManager(t *testing.T) {
	syspc := getNewConfig()
	err := syspc.createAlertManager()
	assert.Equal(t, nil, err)
}

func TestGrafana(t *testing.T) {
	syspc := getNewConfig()
	err := syspc.createGrafana()
	assert.Equal(t, nil, err)
}
