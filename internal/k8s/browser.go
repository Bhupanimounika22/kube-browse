package k8s

// Core Go packages for Kubernetes API interaction
import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	// "k8s.io/client-go/rest"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
)

// CreateSandboxPod creates a new pod with the rdp container
func CreateBrowserSandboxPod(clientset *kubernetes.Clientset, namespace, userID string) (*corev1.Pod, error) {
	podName := fmt.Sprintf("browser-sandbox-%s-%s", userID, time.Now().Format("20060102150405"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
			Labels: map[string]string{
				"app":  "browser-sandbox-test",
				"user": userID,
			},
		},

		Spec: corev1.PodSpec{
			Hostname:  podName,
			Subdomain: "sandbox-instances",
			Volumes: []corev1.Volume{
				{
					Name: "log-volume",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Name:  "init-log-dirs",
					Image: "busybox:1.36",
					Command: []string{
						"sh",
						"-c",
						"mkdir -p /var/log/supervisor && chmod 755 /var/log/supervisor && chown -R 1000:1000 /var/log/supervisor",
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "log-volume",
							MountPath: "/var/log",
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:  "rdp-chromium",
					Image: "ghcr.io/browsersec/rdp-chromium:sha-64ed77a",
					Ports: []corev1.ContainerPort{
						{
							Name:          "rdp",
							ContainerPort: 3389,
						},
					},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("1000m"),
							corev1.ResourceMemory: resource.MustParse("1000Mi"),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("250m"),
							corev1.ResourceMemory: resource.MustParse("256Mi"),
						},
					},
					// SecurityContext: &corev1.SecurityContext{
					// 	// RunAsNonRoot: ptr.To(true),
					// 	// RunAsUser:    ptr.To(int64(1000)),
					// 	Capabilities: &corev1.Capabilities{
					// 		Drop: []corev1.Capability{"ALL"},
					// 	},
					// },
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "log-volume",
							MountPath: "/var/log",
						},
					},
				},
			},
			TerminationGracePeriodSeconds: ptr.To(int64(30)),
		},
	}

	result, err := clientset.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		logrus.Errorf("Error creating pod: %v", err)
		return nil, err
	}
	return result, nil
}
