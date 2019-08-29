package sysprom

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkDeploymentReady checks if kubernetes deployment resource is ready
func checkDeploymentReady(w *InitConfig, name, namespace string) (bool, error) {
	list, err := w.client.AppsV1().Deployments(namespace).List(metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, d := range list.Items {
		if d.Name == name {
			if d.Status.ReadyReplicas == 0 {
				return false, nil
			}
			return true, nil
		}
	}
	return false, fmt.Errorf("Deployment %s not created yet", name)
}

// checkDaemonSetReady checks if kubernetes daemonset resource is ready
func checkDaemonSetReady(w *InitConfig, name, namespace string) (bool, error) {
	list, err := w.client.AppsV1().DaemonSets(namespace).List(metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, d := range list.Items {
		if d.Name == name {
			if d.Status.NumberReady == 0 {
				return false, nil
			}
			return true, nil
		}
	}
	return false, fmt.Errorf("Daemonset %s not created yet", name)
}
