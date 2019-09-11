package sysprom

import (
	"flag"
	"reflect"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func init() {
	viper.Set("mode", flag.String("mode", "standalone", "kubernetes configuration mode"))
}

func TestNewConfig(t *testing.T) {
	config := getConfig(t)
	assert.Equal(t, reflect.TypeOf(config), reflect.TypeOf(&InitConfig{}))
}

func TestPrometheus(t *testing.T) {
	config := getConfig(t)
	err := createPrometheus(config)
	assert.Equal(t, nil, err)
}

func TestPrometheusRules(t *testing.T) {
	config := getConfig(t)
	err := createPrometheusRules(config)
	assert.Equal(t, nil, err)
}

func TestServiceMonitor(t *testing.T) {
	config := getConfig(t)
	err := createServiceMonitor(config)
	assert.Equal(t, nil, err)
}

func TestAlertManager(t *testing.T) {
	config := getConfig(t)
	err := createAlertManager(config)
	assert.Equal(t, nil, err)
}

func TestGrafana(t *testing.T) {
	config := getConfig(t)
	err := createGrafana(config)
	assert.Equal(t, nil, err)
}

func getConfig(t *testing.T) *InitConfig {
	config, err := new()
	if err != nil {
		t.Fatalf("Error occured while getting kubernetes config. Error is: %s", err.Error())
	}
	return config
}
