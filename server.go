package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/authzed/authzed-go/v1"
	authzedv1 "github.com/authzed/authzed-go/v1"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/sirupsen/logrus"
)

var (
	keycloakIssuer   = "http://localhost:8080/auth/realms/vite-realm" // Your Keycloak Realm URL
	keycloakClientID = "kube-client"                                  // Your Keycloak client ID
	spiceDBEndpoint  = "spicedb.local:50051"                          // SpiceDB gRPC endpoint
)

type Deployment struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Namespace   string    `json:"namespace"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description"`
}

func main() {
	ctx := context.Background()

	// Initialize OIDC verifier for Keycloak
	provider, err := oidc.NewProvider(ctx, keycloakIssuer)
	if err != nil {
		logrus.Fatalf("Failed to get OIDC provider: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: keycloakClientID})

	// Connect to PostgreSQL (adjust connection string)
	db, err := sql.Open("pgx", "postgres://postgres:password@localhost:5432/kube_db?sslmode=disable")
	if err != nil {
		logrus.Fatalf("Failed to connect to Postgres: %v", err)
	}
	defer db.Close()

	// Connect to SpiceDB
	spiceClient, err := authzed.NewClient(ctx, spiceDBEndpoint, nil)
	if err != nil {
		logrus.Fatalf("Failed to connect to SpiceDB: %v", err)
	}

	// Initialize Gin router
	r := gin.Default()

	// Auth middleware: validate Keycloak JWT
	r.Use(func(c *gin.Context) {
		userID, err := validateKeycloakToken(c.Request, verifier)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: " + err.Error()})
			return
		}
		c.Set("userID", userID)
		c.Next()
	})

	// Deployments routes with RBAC
	r.POST("/deployments", func(c *gin.Context) {
		userID := c.GetString("userID")

		// Check SpiceDB permission for user on resource
		allowed, err := checkPermission(ctx, spiceClient, userID, "deploy", "kube_namespace", "default")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permissions"})
			return
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}

		var dep Deployment
		if err := c.ShouldBindJSON(&dep); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
			return
		}

		dep.CreatedBy = userID
		dep.CreatedAt = time.Now()

		// Insert into Postgres
		err = insertDeployment(ctx, db, &dep)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save deployment"})
			return
		}

		c.JSON(http.StatusOK, dep)
	})

	r.GET("/deployments", func(c *gin.Context) {
		userID := c.GetString("userID")

		// Check SpiceDB permission
		allowed, err := checkPermission(ctx, spiceClient, userID, "view", "kube_namespace", "default")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permissions"})
			return
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}

		deps, err := getDeployments(ctx, db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load deployments"})
			return
		}

		c.JSON(http.StatusOK, deps)
	})

	r.Run(":8081")
}

// Validate Keycloak JWT token from Authorization header
func validateKeycloakToken(r *http.Request, verifier *oidc.IDTokenVerifier) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("Authorization header missing")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}
	rawToken := parts[1]

	ctx := r.Context()
	idToken, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	// Extract subject from token claims (sub claim)
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return "", fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims.Sub, nil
}

// Check SpiceDB permission for user
func checkPermission(ctx context.Context, client *authzed.Client, userID, permission, resourceType, resourceID string) (bool, error) {
	resp, err := client.CheckPermission(ctx, &authzedv1.CheckPermissionRequest{
		Resource: &authzedv1.ObjectReference{
			ObjectType: resourceType,
			ObjectId:   resourceID,
		},
		Permission: permission,
		Subject: &authzedv1.SubjectReference{
			Object: &authzedv1.ObjectReference{
				ObjectType: "user",
				ObjectId:   userID,
			},
		},
	})
	if err != nil {
		return false, err
	}

	return resp.Permissionship == authzedv1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// Insert deployment data into Postgres
func insertDeployment(ctx context.Context, db *sql.DB, dep *Deployment) error {
	query := `INSERT INTO deployments(name, namespace, created_by, created_at, description)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`
	return db.QueryRowContext(ctx, query, dep.Name, dep.Namespace, dep.CreatedBy, dep.CreatedAt, dep.Description).Scan(&dep.ID)
}

// Get all deployments
func getDeployments(ctx context.Context, db *sql.DB) ([]Deployment, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, name, namespace, created_by, created_at, description FROM deployments")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deployments []Deployment
	for rows.Next() {
		var d Deployment
		if err := rows.Scan(&d.ID, &d.Name, &d.Namespace, &d.CreatedBy, &d.CreatedAt, &d.Description); err != nil {
			return nil, err
		}
		deployments = append(deployments, d)
	}

	return deployments, nil
}
