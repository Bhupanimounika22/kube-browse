package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type SessionData struct {
	PodName          string            `json:"podName"`
	PodIP            string            `json:"podIP"`
	FQDN             string            `json:"fqdn"`
	ConnectionID     string            `json:"connection_id"`
	ConnectionParams map[string]string `json:"connection_params"`
	Share            bool              `json:"share"`
}

// InitRedis initializes and returns a new Redis client
func InitRedis() *redis.Client {
	// Retrieve Redis connection details from environment variables or use defaults
	redisHost := "localhost"
	redisPort := "6379"
	if os.Getenv("REDIS_HOST") != "" {
		redisHost = os.Getenv("REDIS_HOST")
	}
	if os.Getenv("REDIS_PORT") != "" {
		redisPort = os.Getenv("REDIS_PORT")
	}
	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

	// Create a new Redis client
	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Ping the Redis server to check the connection
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		logrus.Errorf("Could not connect to Redis: %v", err)
		// Depending on your application's requirements, you might want to panic here
		// panic(err)
	}

	logrus.Infof("Connected to Redis at %s", redisAddr)

	return client
}

// CheckSessionExists checks if a session exists for a given pod
func CheckSessionExists(client *redis.Client, podName string) (bool, error) {
	ctx := context.Background()

	// Check if session key exists
	exists, err := client.Exists(ctx, fmt.Sprintf("session:%s", podName)).Result()
	if err != nil {
		return false, fmt.Errorf("error checking session existence: %v", err)
	}

	return exists > 0, nil
}

// GetSessionData retrieves session data for a given pod
func GetSessionData(client *redis.Client, podName string) (*SessionData, error) {
	ctx := context.Background()

	sessionKey := fmt.Sprintf("session:%s", podName)
	sessionJSON, err := client.Get(ctx, sessionKey).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("session not found for pod: %s", podName)
	} else if err != nil {
		return nil, fmt.Errorf("error retrieving session: %v", err)
	}

	var sessionData SessionData
	err = json.Unmarshal([]byte(sessionJSON), &sessionData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling session data: %v", err)
	}

	return &sessionData, nil
}

// SetSessionData stores session data for a given pod with TTL
func SetSessionData(client *redis.Client, podName string, sessionData *SessionData, ttl time.Duration) error {
	ctx := context.Background()

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("error marshaling session data: %v", err)
	}

	sessionKey := fmt.Sprintf("session:%s", podName)
	err = client.Set(ctx, sessionKey, sessionJSON, ttl).Err()
	if err != nil {
		return fmt.Errorf("error setting session data: %v", err)
	}

	return nil
}

// DeleteSession removes a session for a given pod
func DeleteSession(client *redis.Client, podName string) error {
	ctx := context.Background()

	sessionKey := fmt.Sprintf("session:%s", podName)
	err := client.Del(ctx, sessionKey).Err()
	if err != nil {
		return fmt.Errorf("error deleting session: %v", err)
	}

	return nil
}

// GetAllActiveSessions returns all active session pod names
func GetAllActiveSessions(client *redis.Client) ([]string, error) {
	ctx := context.Background()

	keys, err := client.Keys(ctx, "session:*").Result()
	if err != nil {
		return nil, fmt.Errorf("error retrieving session keys: %v", err)
	}

	var podNames []string
	for _, key := range keys {
		// Extract pod name from session key (remove "session:" prefix)
		podName := key[8:] // len("session:") = 8
		podNames = append(podNames, podName)
	}
	logrus.Infof("Found %d active sessions in Redis: %v", len(podNames), podNames)

	return podNames, nil
}
