package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	guac2 "github.com/browsersec/KubeBrowse/internal/guac"
	"github.com/browsersec/KubeBrowse/internal/k8s"

	"github.com/browsersec/KubeBrowse/api"
	"github.com/browsersec/KubeBrowse/docs"
	"github.com/browsersec/KubeBrowse/internal/minio"
	redis2 "github.com/browsersec/KubeBrowse/internal/redis"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// @BasePath /test

var (
	certPath     string
	certKeyPath  string
	guacdAddr    = "0.0.0.0:4822"
	k8sClient    *kubernetes.Clientset
	k8sNamespace = "browser-sandbox"
	clamavAddr   = "http://clamd-api.browser-sandbox.svc.cluster.local:3000"
	minioAddr    = "minio.browser-sandbox.svc.cluster.local:9000"
)

var activeTunnels *guac2.ActiveTunnelStore
var redisClient *redis.Client

type MinioConfig struct {
	bucketName string
	minioAddr  string
	accessKey  string
	secretKey  string
}

// GinHandlerAdapter adapts http.Handler to gin.HandlerFunc
func GinHandlerAdapter(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func main() {
	redisClient = redis2.InitRedis()

	minioConfig := &MinioConfig{
		bucketName: os.Getenv("MINIO_BUCKET"),
		minioAddr:  minioAddr,
		accessKey:  os.Getenv("MINIO_ACCESS_KEY"),
		secretKey:  os.Getenv("MINIO_SECRET_KEY"),
	}

	// Use default bucket name if not set in environment
	if minioConfig.bucketName == "" {
		minioConfig.bucketName = "kubebrowse-files"
		logrus.Info("Using default bucket name: kubebrowse-files")
	}

	if minioConfig.accessKey == "" || minioConfig.secretKey == "" {
		logrus.Warn("MINIO_ACCESS_KEY and/or MINIO_SECRET_KEY environment variables not set, MinIO uploads will fail")
	}

	// Check if MinIO endpoint is overridden in environment
	if os.Getenv("MINIO_ENDPOINT") != "" {
		minioConfig.minioAddr = os.Getenv("MINIO_ENDPOINT")
		logrus.Infof("Using MINIO_ENDPOINT from environment: %s", minioConfig.minioAddr)
	}

	// Initialize MinIO client with more robust error handling
	var minioClient *minio.MinioClient
	if minioConfig.accessKey != "" && minioConfig.secretKey != "" {
		var err error
		minioClient, err = minio.NewMinioClient(minioConfig.minioAddr, minioConfig.accessKey, minioConfig.secretKey, false)
		if err != nil {
			logrus.Warnf("Failed to create MinIO client: %v", err)
			logrus.Warn("File uploads to MinIO storage will not work")
		} else {
			// Check if MinIO bucket exists
			err = minioClient.CreateBucket(context.Background(), minioConfig.bucketName, "us-east-1")
			if err != nil {
				logrus.Warnf("Failed to create MinIO bucket: %v", err)
				logrus.Warn("Continuing without MinIO bucket creation")
			} else {
				logrus.Infof("Successfully connected to MinIO with bucket: %s", minioConfig.bucketName)
			}
		}
	}

	// ClamAV configuration
	if os.Getenv("CLAMAV_ADDRESS") != "" {
		clamavAddr = os.Getenv("CLAMAV_ADDRESS")
		logrus.Infof("Using ClamAV address from environment: %s", clamavAddr)
	}

	// Parse command line flags
	helpFlag := flag.Bool("h", false, "Display help information")
	flag.Parse()

	// Check if help flag was provided
	if *helpFlag {
		displayHelp()
		return
	}

	logrus.SetLevel(logrus.TraceLevel)

	// Get environment variables
	if os.Getenv("CERT_PATH") != "" {
		certPath = os.Getenv("CERT_PATH")
		// Check if certificate file exists
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			logrus.Warnf("Certificate file %s does not exist", certPath)
		}
	}

	if os.Getenv("CERT_KEY_PATH") != "" {
		certKeyPath = os.Getenv("CERT_KEY_PATH")
		// Check if key file exists
		if _, err := os.Stat(certKeyPath); os.IsNotExist(err) {
			logrus.Warnf("Certificate key file %s does not exist", certKeyPath)
		}
	}

	if certPath != "" && certKeyPath == "" {
		logrus.Fatal("You must set the CERT_KEY_PATH environment variable to specify the full path to the certificate keyfile")
	}

	if certPath == "" && certKeyPath != "" {
		logrus.Fatal("You must set the CERT_PATH environment variable to specify the full path to the certificate file")
	}

	if os.Getenv("GUACD_ADDRESS") != "" {
		guacdAddr = os.Getenv("GUACD_ADDRESS")
	}

	if os.Getenv("KUBERNETES_NAMESPACE") != "" {
		k8sNamespace = os.Getenv("KUBERNETES_NAMESPACE")
	}

	activeTunnels = guac2.NewActiveTunnelStore()

	// Initialize Kubernetes client with fallback for local development
	config, err := rest.InClusterConfig()
	if err != nil {
		logrus.Warnf("Failed to create in-cluster config: %v", err)
		logrus.Info("Attempting to use local kubeconfig file")

		// Try to use the kubeconfig file instead
		kubeconfigPath := os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			// Default kubeconfig location if not specified
			homeDir, err := os.UserHomeDir()
			if err == nil {
				kubeconfigPath = filepath.Join(homeDir, ".kube", "config")
			}
		}

		if kubeconfigPath != "" {
			// Import clientcmd at the top of the file
			config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
			if err != nil {
				logrus.Errorf("Failed to create kubernetes client config from kubeconfig: %v", err)
				logrus.Warn("Continuing without Kubernetes client - pod creation functions will not work")
			} else {
				logrus.Infof("Using kubeconfig from: %s", kubeconfigPath)
			}
		} else {
			logrus.Warn("No kubeconfig file found. Continuing without Kubernetes client")
		}
	}

	if config != nil {
		k8sClient, err = kubernetes.NewForConfig(config)
		if err != nil {
			logrus.Errorf("Failed to create Kubernetes client: %v", err)
			logrus.Warn("Continuing without Kubernetes client - pod creation functions will not work")
		} else {
			logrus.Info("Successfully connected to Kubernetes")
		}
	}

	// Initialize Gin
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Configure Swagger
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Title = "KubeBrowse API"
	docs.SwaggerInfo.Description = "KubeBrowse API for managing browser and office sandbox pods"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = "localhost:4567"
	docs.SwaggerInfo.Schemes = []string{"http", "https"}
	coors := cors.DefaultConfig()
	coors.AllowAllOrigins = true
	coors.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	coors.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	coors.AllowCredentials = true
	router.Use(cors.New(coors))
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// Initialize Guacamole handlers
	// servlet := guac.NewServer(DemoDoConnect) // We'll adjust this if DemoDoConnect's signature changes, or use a wrapper
	// wsServer := guac.NewWebsocketServer(DemoDoConnect) // Same here

	// Pass activeTunnels to DemoDoConnect by wrapping it
	doConnectWrapper := func(request *http.Request) (guac2.Tunnel, error) {
		return api.DemoDoConnect(request, activeTunnels, redisClient, guacdAddr)
	}

	servlet := guac2.NewServer(doConnectWrapper)
	wsServer := guac2.NewWebsocketServer(doConnectWrapper)

	// sessions := guac.NewMemorySessionStore() // Old store
	// wsServer.OnConnect = sessions.Add // Old OnConnect
	// wsServer.OnDisconnect = sessions.Delete // Old OnDisconnect

	// OnConnect is implicitly handled by DemoDoConnect now adding to activeTunnels.
	// We still need OnDisconnect to remove from the store when a tunnel closes for any reason.
	wsServer.OnDisconnect = func(connectionID string, req *http.Request, tunnel guac2.Tunnel) {
		logrus.Debugf("Websocket disconnected, removing tunnel: %s", connectionID)
		activeTunnels.Delete(connectionID, req, tunnel)

		// Extract connection UUID from request parameters
		uuidParam := req.URL.Query().Get("uuid")
		if uuidParam == "" {
			logrus.Debugf("No UUID found in request for connection: %s", connectionID)
			return
		}

		// Check if this session exists in Redis
		ctx := context.Background()
		sessionKey := fmt.Sprintf("session:%s", uuidParam)

		// // First, check what type the key is in Redis
		// keyType, err := redisClient.Type(ctx, sessionKey).Result()
		// if err != nil {
		// 	logrus.Errorf("Failed to check Redis key type for session %s: %v", uuidParam, err)
		// 	return
		// }

		// var podName string

		// // Extract pod name based on the key type
		// switch keyType {
		// case "hash":
		// 	// If it's a hash, use HGET
		// 	podName, err = redisClient.HGet(ctx, sessionKey, "pod_name").Result()
		// 	if err != nil {
		// 		logrus.Warnf("Failed to get pod_name from hash for session %s: %v", uuidParam, err)
		// 		// Try getting PodName field as well
		// 		podName, err = redisClient.HGet(ctx, sessionKey, "PodName").Result()
		// 	}
		// case "string":
		// 	// If it's a string, try to decode it as JSON or extract pod name from the log pattern
		// 	sessionData, err := redisClient.Get(ctx, sessionKey).Result()
		// 	if err == nil {
		// 		// Try to extract pod name from the session data string
		// 		// Based on the log, it looks like: "PodName:browser-sandbox-browser-7acfd4ab-20250601101159"
		// 		if strings.Contains(sessionData, "PodName:") {
		// 			parts := strings.Split(sessionData, "PodName:")
		// 			if len(parts) > 1 {
		// 				podNamePart := strings.Split(parts[1], " ")[0]
		// 				podName = strings.TrimSpace(podNamePart)
		// 			}
		// 		}
		// 	}
		// default:
		// 	logrus.Warnf("Unexpected Redis key type '%s' for session %s", keyType, uuidParam)
		// 	return
		// }

		sessiondata, err := redis2.GetSessionData(redisClient, uuidParam)
		if err != nil {
			logrus.Warnf("Failed to get session data for %s: %v", uuidParam, err)
			return
		}
		podName := sessiondata.PodName

		if podName == "" {
			logrus.Warnf("No pod name found for session %s ,  %v", uuidParam, err)
			return
		}

		logrus.Infof("Found pod name %s for disconnected session %s", podName, uuidParam)

		// Set a reconnection window in Redis with expiration
		reconnectKey := fmt.Sprintf("reconnect:%s", uuidParam)
		sessionJSON, err := json.Marshal(sessiondata)
		if err != nil {
			logrus.Errorf("Failed to marshal session data for %s: %v", uuidParam, err)
			return
		}
		err = redisClient.Set(ctx, reconnectKey, sessionJSON, 2*time.Minute).Err()
		if err != nil {
			logrus.Errorf("Failed to set reconnection window for session %s: %v", uuidParam, err)
		} else {
			logrus.Infof("Set 2-minute reconnection window for session %s", uuidParam)
		}

		// Schedule pod termination after grace period if no reconnection
		go func() {
			// Wait for reconnection window (30 Seconds)
			time.Sleep(30 * time.Second)

			// Check if pod still exists in reconnect window
			// exists, err := redisClient.Exists(ctx, reconnectKey).Result()
			// if err != nil {
			// 	logrus.Errorf("Failed to check reconnection status for %s: %v", uuidParam, err)
			// 	return
			// }
			exists, err := k8s.CheckPodName(k8sClient, k8sNamespace, podName)
			if err != nil {
				logrus.Errorf("Failed to check if pod %s exists: %v", podName, err)
				return
			}

			if exists {
				// No reconnection happened, delete the pod
				logrus.Infof("No reconnection for session %s after grace period, terminating pod %s", uuidParam, podName)
				if k8sClient != nil {
					err = k8s.DeletePodGrace(k8sClient, k8sNamespace, podName)
					if err != nil {
						logrus.Errorf("Failed to delete pod %s: %v", podName, err)
					} else {
						logrus.Infof("Successfully scheduled pod %s for deletion", podName)
					}
				}

				// Clean up Redis keys
				redisClient.Del(ctx, sessionKey, reconnectKey)
				logrus.Infof("Cleaned up Redis keys for session %s", uuidParam)
			} else {
				logrus.Infof("Session %s reconnected, pod %s will not be terminated", uuidParam, podName)
			}
		}()
	}

	// Setup routes using Gin
	router.Any("/tunnel", GinHandlerAdapter(servlet))
	router.Any("/tunnel/*path", GinHandlerAdapter(servlet))
	router.Any("/websocket-tunnel", GinHandlerAdapter(wsServer))

	// Session management handler
	router.GET("/sessions/", func(c *gin.Context) {
		api.HandlerSession(c, activeTunnels)

	})

	// Add test routes for pod creation
	testRoutes := router.Group("/test")
	{
		// New route for deploying and connecting to office pod with RDP credentials
		testRoutes.POST("/deploy-office", func(c *gin.Context) {
			api.DeployOffice(c, k8sClient, k8sNamespace, redisClient, activeTunnels)
		})

		// New route for deploying and connecting to browser pod with RDP credentials
		testRoutes.POST("/deploy-browser", func(c *gin.Context) {
			api.DeployBrowser(c, k8sClient, k8sNamespace, redisClient, activeTunnels)
		})

		// New endpoint to handle websocket connections using stored parameters
		testRoutes.GET("/connect/:connectionID", func(c *gin.Context) {
			api.HandlerConnectionID(c, activeTunnels, redisClient)
		})

		// Share session route
		testRoutes.GET("/share/:connectionID", func(c *gin.Context) {
			api.HandlerShareSession(c, activeTunnels, redisClient)
		})

		// Test route to create a browser sandbox pod
		testRoutes.POST("/browser-pod", func(c *gin.Context) {
			api.HandlerBrowserPod(c, activeTunnels, k8sClient, k8sNamespace)
		})

		// Test route to create an office sandbox pod
		testRoutes.POST("/office-pod", func(c *gin.Context) {
			api.HandlerOfficePod(c, activeTunnels, k8sClient, k8sNamespace)
		})
	}

	sessionRoutes := router.Group("/sessions")
	{

		// Endpoint to stop a specific WebSocket session
		sessionRoutes.DELETE("/:connectionID/stop", func(c *gin.Context) {
			api.HandlerStopWSSession(c, redisClient, k8sClient)
		})

		// Tunnel a Pod Rest API to Upload a file to a pod
		sessionRoutes.POST("/:connectionID/upload", func(c *gin.Context) {
			// Check if minioClient is nil before passing it to the handler
			if minioClient == nil {
				api.HandlerUploadFileWithoutMinio(c, redisClient, k8sClient, clamavAddr, 10)
			} else {
				api.HandlerUploadFile(c, redisClient, k8sClient, minioClient.Client, minioConfig.bucketName, clamavAddr, 10)
			}
		})
	}

	// Add Swagger documentation route
	router.GET("/swagger/*any", ginSwagger.WrapHandler(
		swaggerfiles.Handler))

	// Start server with appropriate TLS configuration
	addr := "0.0.0.0:4567"
	if certPath != "" {
		logrus.Println("Serving on https://", addr)
		err := router.RunTLS(addr, certPath, certKeyPath)
		if err != nil {
			logrus.Fatal(err)
		}
	} else {
		logrus.Println("Serving on http://", addr)
		err := router.Run(addr)
		if err != nil {
			logrus.Fatal(err)
		}
	}
}

// Add a help command to display CLI usage information
func displayHelp() {
	fmt.Println("Usage: guac [command] [options]")
	fmt.Println("Commands:")
	fmt.Println("  run             Start the GUAC server")
	fmt.Println("  generate        Generate self-signed certificates")
	fmt.Println("  generate_prod   Generate Let's Encrypt certificates")
	fmt.Println("  test            Run tests")
	fmt.Println("  build           Build the project")
	fmt.Println("  help            Display this help message")
}

func GuacdTest(address string) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to connect to guacd at %s: %v\n", address, err)
		return err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "Failed to close connection: %v\n", cerr)
		}
	}()

	fmt.Printf("✅ Successfully connected to guacd at %s\n", address)
	return nil
}
