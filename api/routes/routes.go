package routes

import (
	"bitbucket.org/xoduxcrt/ssl/api/handlers"
	"bitbucket.org/xoduxcrt/ssl/api/middleware"
	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter"
)

func SetupRouter(
	r *gin.Engine,
	ctHandler handlers.CTHandler,
	allowedIps []string,
	limit *limiter.Limiter,
	headerAuth gin.HandlerFunc,
) *gin.Engine {
	certsGroup := r.Group("/certs")
	{
		certsGroup.Use(middleware.Whitelist(allowedIps), middleware.RateLimit(limit), headerAuth)
		certsGroup.GET("/", ctHandler.List)
		certsGroup.GET("/:id/download", ctHandler.Download)
		certsGroup.GET("/:id", ctHandler.Query)
	}

	return r
}
