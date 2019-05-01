# monhelper
Helper service to enhance prometheus-operator

Currently, monhelper runs alongside prometheus-operator and watches changes to Prometheus and AlertManager objects.
For new instances, it creates service objects to front prometheus/alertmanager pods. These services can be located by
inspecting annotations for corresponding prometheus objects and locating *service* key.

```yaml
k get prometheus/prometheus -o yaml
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"monitoring.coreos.com/v1","kind":"Prometheus","metadata":{"annotations":{},"name":"prometheus","namespace":"default"},"spec":{"enableAdminAPI":false,"resources":{"requests":{"memory":"400Mi"}},"serviceAccountName":"prometheus","serviceMonitorSelector":{"matchLabels":{"team":"frontend"}}}}
    service: prometheus-c2vnnfa7
  creationTimestamp: 2019-04-30T13:53:55Z
  generation: 2
  name: prometheus
  namespace: default
  resourceVersion: "67438"
  selfLink: /apis/monitoring.coreos.com/v1/namespaces/default/prometheuses/prometheus
  uid: 64e54969-6b4f-11e9-a54b-b230d89ff249
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
