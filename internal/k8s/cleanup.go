package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PodInfo contains basic pod information
type PodInfo struct {
	Name      string
	Namespace string
	CreatedAt time.Time
	Labels    map[string]string
}

// GetBrowserSandboxPods returns all pods in the browser-sandbox namespace
func GetBrowserSandboxPods(clientset *kubernetes.Clientset, namespace string) ([]PodInfo, error) {
	ctx := context.Background()

	// List pods with label selector for browser sandbox pods (both browser and office)
	labelSelector := "app in (browser-sandbox-test, office-sandbox-test)"
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("error listing pods: %v", err)
	}

	var podInfos []PodInfo
	for _, pod := range pods.Items {
		// Only include running or pending pods
		if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending {
			podInfo := PodInfo{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				CreatedAt: pod.CreationTimestamp.Time,
				Labels:    pod.Labels,
			}
			podInfos = append(podInfos, podInfo)
		}
	}

	return podInfos, nil
}

// DeletePodGrace deletes a specific pod with a grace period
func DeletePodGrace(clientset *kubernetes.Clientset, namespace, podName string) error {
	ctx := context.Background()

	logrus.Infof("Deleting pod %s in namespace %s", podName, namespace)

	err := clientset.CoreV1().Pods(namespace).Delete(ctx, podName, metav1.DeleteOptions{
		GracePeriodSeconds: &[]int64{30}[0], // 30 second grace period
	})
	if err != nil {
		return fmt.Errorf("error deleting pod %s: %v", podName, err)
	}

	logrus.Infof("Successfully deleted pod %s", podName)
	return nil
}

// IsOrphanedPod checks if a pod should be considered orphaned
func IsOrphanedPod(pod PodInfo, gracePeriod time.Duration) bool {
	// Consider a pod orphaned if it's been running for longer than the grace period
	// This gives time for sessions to be established
	return time.Since(pod.CreatedAt) > gracePeriod
}

// FilterBrowserSandboxPods filters pods that match browser or office sandbox pattern
func FilterBrowserSandboxPods(pods []PodInfo) []PodInfo {
	var sandboxPods []PodInfo
	for _, pod := range pods {
		// Check if pod name matches browser or office sandbox pattern
		if strings.HasPrefix(pod.Name, "browser-sandbox-") || strings.HasPrefix(pod.Name, "office-sandbox-") {
			sandboxPods = append(sandboxPods, pod)
		}
	}
	return sandboxPods
}
