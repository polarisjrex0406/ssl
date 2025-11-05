package middleware

import (
	"net/http"

	"bitbucket.org/xoduxcrt/ssl/api/dto"
	"bitbucket.org/xoduxcrt/ssl/pkg/utils"
	"github.com/gin-gonic/gin"
)

func HeaderAuth(authHeader, expectedToken string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader(authHeader)
		if token != expectedToken {
			utils.SendResponseFailure(c, http.StatusUnauthorized, dto.MESSAGE_FAILED_TOKEN_NOT_VALID, nil, dto.ErrTokenNotValid.Error())
			return
		}
		c.Next()
	}
}
