# monhelper
Helper service to enhance prometheus-operator

Currently, monhelper runs alongside prometheus-operator and watches changes to Prometheus and AlertManager objects.
For new instances, it creates service objects to front prometheus/alertmanager pods. These services can be located by
inspecting annotations for corresponding prometheus objects and locating *service_path* key.

```yaml
 k get prometheus/prometheus -o yaml
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"monitoring.coreos.com/v1","kind":"Prometheus","metadata":{"annotations":{},"name":"prometheus","namespace":"default"},"spec":{"enableAdminAPI":false,"resources":{"requests":{"memory":"400Mi"}},"serviceAccountName":"prometheus","serviceMonitorSelector":{"matchLabels":{"team":"frontend"}}}}
    service: prometheus-0jq3ofdu
    service_path: /api/v1/namespaces/default/services/prometheus-0jq3ofdu:web/proxy
  creationTimestamp: 2019-05-02T00:40:37Z
  generation: 2
  name: prometheus
  namespace: default
  resourceVersion: "4693"
  selfLink: /apis/monitoring.coreos.com/v1/namespaces/default/prometheuses/prometheus
  uid: e7205dce-6c72-11e9-bfd3-0a190cacc41f
spec:
  resources:
    requests:
      memory: 400Mi
  rules:
    alert: {}
  serviceAccountName: prometheus
  serviceMonitorSelector:
    matchLabels:
      team: frontend
```

The services are named as ```<prometheus_custom_resource_name>-<random_suffix>```. The lifecycle of service object is tied to the
corresponding prometheus custom resource. It is cleaned up after parent object is deleted.
