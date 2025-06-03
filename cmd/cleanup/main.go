package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/browsersec/KubeBrowse/internal/cleanup"
	redisClient "github.com/browsersec/KubeBrowse/internal/redis"
)

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.Info("Starting Browser Sandbox Cleanup Service")

	// Initialize Kubernetes client
	k8sClient, err := initKubernetesClient()
	if err != nil {
		logrus.Fatalf("Error initializing Kubernetes client: %v", err)
	}

	// Validate Kubernetes connection
	if err := validateKubernetesConnection(k8sClient); err != nil {
		logrus.Fatalf("Failed to validate Kubernetes connection: %v", err)
	}

	// Initialize Redis client
	redisConn := redisClient.InitRedis()

	// Get configuration from environment variables
	namespace := getEnvOrDefault("CLEANUP_NAMESPACE", "browser-sandbox")
	gracePeriodStr := getEnvOrDefault("CLEANUP_GRACE_PERIOD", "5m")
	cronSchedule := getEnvOrDefault("CLEANUP_CRON_SCHEDULE", "*/5 * * * *") // Every 5 minutes

	gracePeriod, err := time.ParseDuration(gracePeriodStr)
	if err != nil {
		logrus.Fatalf("Invalid grace period format: %v", err)
	}

	// Create cleanup service
	cleanupService := cleanup.NewCleanupService(k8sClient, redisConn, namespace, gracePeriod)

	// Setup cron job
	c := cron.New()
	_, err = c.AddFunc(cronSchedule, func() {
		err := cleanupService.CleanupOrphanedPods()
		if err != nil {
			logrus.Errorf("Cleanup job failed: %v", err)
		}
	})
	if err != nil {
		logrus.Fatalf("Error setting up cron job: %v", err)
	}

	logrus.Infof("Cleanup service configured:")
	logrus.Infof("  Namespace: %s", namespace)
	logrus.Infof("  Grace Period: %s", gracePeriod)
	logrus.Infof("  Cron Schedule: %s", cronSchedule)

	// Start the cron scheduler
	c.Start()
	logrus.Info("Cleanup service started")

	// Run an initial cleanup
	logrus.Info("Running initial cleanup")
	err = cleanupService.CleanupOrphanedPods()
	if err != nil {
		logrus.Errorf("Initial cleanup failed: %v", err)
	}

	// Keep the service running
	select {}
}

func initKubernetesClient() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	// Check if we're running in a Kubernetes cluster
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		logrus.Info("Detected in-cluster environment, attempting in-cluster config")
		config, err = rest.InClusterConfig()
		if err != nil {
			logrus.Warnf("Failed to load in-cluster config: %v", err)
		} else {
			logrus.Info("Successfully loaded in-cluster config")
		}
	} else {
		logrus.Info("Not running in-cluster, skipping in-cluster config")
	}

	// If in-cluster config failed or we're not in cluster, try kubeconfig
	if config == nil {
		logrus.Info("Attempting to load kubeconfig")

		// Try multiple kubeconfig locations
		kubeconfigPaths := []string{
			os.Getenv("KUBECONFIG"),
			filepath.Join(homedir.HomeDir(), ".kube", "config"),
			"/etc/kubernetes/admin.conf", // Common location for cluster admin config
		}

		var kubeconfigPath string
		for _, path := range kubeconfigPaths {
			if path != "" {
				if _, err := os.Stat(path); err == nil {
					kubeconfigPath = path
					logrus.Infof("Found kubeconfig at: %s", path)
					break
				}
			}
		}

		if kubeconfigPath == "" {
			return nil, fmt.Errorf("no valid kubeconfig found in standard locations")
		}

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to build config from kubeconfig %s: %v", kubeconfigPath, err)
		}
		logrus.Infof("Successfully loaded kubeconfig from: %s", kubeconfigPath)
	}

	// Set reasonable timeouts
	config.Timeout = 30 * time.Second

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	logrus.Info("Kubernetes client initialized successfully")
	return clientset, nil
}

func validateKubernetesConnection(client *kubernetes.Clientset) error {
	logrus.Info("Validating Kubernetes connection...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to get server version
	version, err := client.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("failed to get server version: %v", err)
	}

	logrus.Infof("Connected to Kubernetes cluster version: %s", version.String())

	// Try to list namespaces to verify we have basic permissions
	_, err = client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		logrus.Warnf("Cannot list namespaces (may be due to RBAC restrictions): %v", err)
	} else {
		logrus.Info("Successfully validated cluster access")
	}

	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
