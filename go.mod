module github.com/platform9/prometheus-plus

go 1.13

require (
	github.com/coreos/prometheus-operator v0.40.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.6.0
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.0
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	k8s.io/api v0.18.6
	k8s.io/apiextensions-apiserver v0.18.6
	k8s.io/apimachinery v0.18.6
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
)
