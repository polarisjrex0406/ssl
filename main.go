package main

import (
	"fmt"
	"time"

	"bitbucket.org/xoduxcrt/ssl/api/handlers"
	"bitbucket.org/xoduxcrt/ssl/api/middleware"
	"bitbucket.org/xoduxcrt/ssl/api/routes"
	"bitbucket.org/xoduxcrt/ssl/api/services"
	"bitbucket.org/xoduxcrt/ssl/internal/config"
	"bitbucket.org/xoduxcrt/ssl/internal/db"
	"bitbucket.org/xoduxcrt/ssl/pkg/utils"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ulule/limiter"
	"github.com/ulule/limiter/drivers/store/memory"
)

func main() {
	// Database close when exit
	defer db.Close()
	// Get configuration
	cfg, err := config.GetConfig()
	if err != nil {
		panic(err)
	}
	// Dependency injection across services, handlers
	app := setupDependencyInjections(db.Conn)
	// Rate limiter configuration
	rate := limiter.Rate{
		Period: cfg.Server.Rate.Period,
		Limit:  cfg.Server.Rate.Limit,
	}
	store := memory.NewStore()
	limit := limiter.New(store, rate)
	// Create auth middleware
	authMiddleware := middleware.HeaderAuth(cfg.Server.Auth.Header, cfg.Server.Auth.Token)
	// Initialize gin router
	router := gin.Default()
	// Whitelist
	allowedIps := utils.LoadIPs(cfg.Server.AllowedIPs)
	// CORS settings
	allowedOrigins := []string{
		"http://37.27.171.40:8080",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
	}
	for _, ip := range allowedIps {
		allowedOrigins = append(allowedOrigins, fmt.Sprintf("http://%s:*", ip))
	}
	router.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "OPTIONS", "HEAD"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "Accept", "Cache-Control", "X-XODUXCRT-AUTH-TOKEN"},
		ExposeHeaders:    []string{"Content-Length", "Content-Disposition"},
		MaxAge:           12 * time.Hour,
		AllowCredentials: true,
	}))
	// Add swagger UI routes
	router.GET("/swagger/index.html", SwaggerUIHandler)
	// Add documentation routes
	router.GET("/swagger/doc.json", func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "http://95.217.33.236:8080")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.File("./api/docs/swagger.json")
	})
	// Setup relative routes
	r := routes.SetupRouter(router, app.CTHandler, allowedIps, limit, authMiddleware)
	// Start server
	r.Run(fmt.Sprintf("0.0.0.0:%d", 8080))
}

type App struct {
	CTHandler handlers.CTHandler
}

func setupDependencyInjections(conn *pgx.Conn) (app *App) {
	ctService := services.NewCTService(conn)
	// DI to handlers
	ctHandler := handlers.NewCertHandler(ctService)

	return &App{
		CTHandler: ctHandler,
	}
}

func SwaggerUIHandler(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "http://95.217.33.236:8080")
	c.Header("Access-Control-Allow-Credentials", "true")
	c.Data(200, "text/html; charset=utf-8", []byte(`
		<!DOCTYPE html>
		<html>
		<head>
			<link rel="stylesheet" type="text/css" 
				href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
		</head>
		<body>
			<div id="swagger-ui"></div>
			<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
			<script>
				SwaggerUIBundle({
					url: '/swagger/doc.json',
					dom_id: '#swagger-ui',
					presets: [
						SwaggerUIBundle.presets.apis,
						SwaggerUIBundle.SwaggerUIStandalonePreset
					]
				})
			</script>
		</body>
		</html>
    `))
}
