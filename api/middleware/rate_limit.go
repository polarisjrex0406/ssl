package middleware

import (
	"net/http"

	"bitbucket.org/xoduxcrt/ssl/api/dto"
	"bitbucket.org/xoduxcrt/ssl/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter"
)

func RateLimit(limit *limiter.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		context, err := limit.Get(c, "ct-log:"+c.ClientIP())
		if err == nil && context.Reached {
			utils.SendResponseFailure(c, http.StatusTooManyRequests, dto.MESSAGE_FAILED_TOO_MANY_REQUESTS, nil, dto.ErrTooManyRequests.Error())
			return
		}

		c.Next()
	}
}
