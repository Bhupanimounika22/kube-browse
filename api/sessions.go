package api

import (
	"context"
	"github.com/browsersec/KubeBrowse/internal/guac"

	"encoding/json"
	"net/http"

	"fmt"

	"github.com/browsersec/KubeBrowse/internal/k8s"
	redis2 "github.com/browsersec/KubeBrowse/internal/redis"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// Endpoint to stop a specific WebSocket session
func HandlerStopWSSession(c *gin.Context, redisClient *redis.Client, k8sClient *kubernetes.Clientset) {

	connectionID := c.Param("connectionID")
	if connectionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Connection ID is required"})
		return
	}
	val, err := redisClient.Get(context.Background(), "session:"+connectionID).Result()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}
	var session redis2.SessionData
	err = json.Unmarshal([]byte(val), &session)
	if err != nil {
		logrus.Errorf("Failed to unmarshal session data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unmarshal session data"})
		return
	}
	err = k8s.DeletePod(k8sClient, session.PodName)
	if err != nil {
		logrus.Errorf("Failed to delete pod: %v", err)
	}
	redisClient.Del(context.Background(), "session:"+connectionID)
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Session %s stopped and pod deleted.", connectionID)})
}

// Session management handler
func HandlerSession(c *gin.Context, activeTunnels *guac.ActiveTunnelStore) {
	c.Header("Content-Type", "application/json")

	// sessions.RLock() // Old store lock
	// defer sessions.RUnlock() // Old store unlock

	type ConnInfo struct {
		Uuid string `json:"uuid"`
		// Num  int    `json:"num"` // We don't have a 'Num' equivalent directly, can show count if needed
	}

	// connIds := make([]*ConnIds, len(sessions.ConnIds)) // Old way
	allIDs := activeTunnels.GetAllIDs()
	connInfos := make([]*ConnInfo, len(allIDs))

	// i := 0 // Old way
	// for id, num := range sessions.ConnIds { // Old way
	// 	connIds[i] = &ConnIds{ // Old way
	// 		Uuid: id, // Old way
	// 		Num:  num, // Old way
	// 	}
	// 	i++ // Old way
	// }
	for i, id := range allIDs {
		connInfos[i] = &ConnInfo{Uuid: id}
	}

	// c.JSON(http.StatusOK, connIds) // Old way
	c.JSON(http.StatusOK, gin.H{
		"active_sessions": len(connInfos),
		"connection_ids":  connInfos,
	})

}
