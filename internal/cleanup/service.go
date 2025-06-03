package cleanup

import (
	"context"
	"fmt"
	"time"

	"github.com/browsersec/KubeBrowse/internal/k8s"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// CleanupService handles cleaning up orphaned resources
type CleanupService struct {
	k8sClient   *kubernetes.Clientset
	redisClient *redis.Client
	namespace   string
	gracePeriod time.Duration
}

// NewCleanupService creates a new cleanup service
func NewCleanupService(k8sClient *kubernetes.Clientset, redisClient *redis.Client, namespace string, gracePeriod time.Duration) *CleanupService {
	return &CleanupService{
		k8sClient:   k8sClient,
		redisClient: redisClient,
		namespace:   namespace,
		gracePeriod: gracePeriod,
	}
}

// CleanupOrphanedPods removes pods that have no active session
func (s *CleanupService) CleanupOrphanedPods() error {
	logrus.Info("Starting cleanup of orphaned pods")

	// Get all browser sandbox pods
	pods, err := k8s.GetBrowserSandboxPods(s.k8sClient, s.namespace)
	if err != nil {
		return fmt.Errorf("failed to get browser sandbox pods: %v", err)
	}

	logrus.Infof("Found %d browser sandbox pods for cleanup evaluation", len(pods))

	ctx := context.Background()

	// Check each pod against Redis sessions
	for _, pod := range pods {
		// Skip pods that are too new (within grace period)
		if !k8s.IsOrphanedPod(pod, s.gracePeriod) {
			logrus.Debugf("Pod %s is within grace period, skipping", pod.Name)
			continue
		}

		// Check if pod has an active session in Redis
		sessionExists := false
		podName := pod.Name

		// Scan for sessions that reference this pod
		var cursor uint64
		for {
			var keys []string
			var err error
			keys, cursor, err = s.redisClient.Scan(ctx, cursor, "session:*", 100).Result()
			if err != nil {
				logrus.Errorf("Error scanning Redis for sessions: %v", err)
				break
			}

			// Check each session to see if it references this pod
			for _, key := range keys {
				podNameFromRedis, err := s.redisClient.HGet(ctx, key, "pod_name").Result()
				if err == nil && podNameFromRedis == podName {
					sessionExists = true
					break
				}
			}

			if sessionExists || cursor == 0 {
				break
			}
		}

		// Also check reconnection windows
		if !sessionExists {
			var cursor uint64
			for {
				var keys []string
				var err error
				keys, cursor, err = s.redisClient.Scan(ctx, cursor, "reconnect:*", 100).Result()
				if err != nil {
					logrus.Errorf("Error scanning Redis for reconnect windows: %v", err)
					break
				}

				// Check each reconnect window
				for _, key := range keys {
					podNameFromRedis, err := s.redisClient.Get(ctx, key).Result()
					if err == nil && podNameFromRedis == podName {
						sessionExists = true
						break
					}
				}

				if sessionExists || cursor == 0 {
					break
				}
			}
		}

		// If no active session found, delete the pod
		if !sessionExists {
			logrus.Infof("No active session for pod %s, terminating", podName)
			err = k8s.DeletePodGrace(s.k8sClient, s.namespace, podName)
			if err != nil {
				logrus.Errorf("Failed to delete orphaned pod %s: %v", podName, err)
			}
		} else {
			logrus.Debugf("Pod %s has an active session, skipping", podName)
		}
	}

	logrus.Info("Completed cleanup of orphaned pods")
	return nil
}
