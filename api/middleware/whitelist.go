package middleware

import (
	"net/http"

	"bitbucket.org/xoduxcrt/ssl/api/dto"
	"bitbucket.org/xoduxcrt/ssl/pkg/utils"
	"github.com/gin-gonic/gin"
)

func Whitelist(allowedIps []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		isAllowedIp := false
		for _, ip := range allowedIps {
			if ip == c.ClientIP() {
				isAllowedIp = true
				break
			}
		}

		if !isAllowedIp {
			utils.SendResponseFailure(c, http.StatusForbidden, dto.MESSAGE_FAILED_NOT_IN_WHITELIST, nil, dto.ErrNotInWhitelist.Error())
		}

		c.Next()
	}
}
