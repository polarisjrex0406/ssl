package utils

import (
	"github.com/gin-gonic/gin"
)

type Response struct {
	Success bool   `json:"success" example:"true"`
	Message string `json:"message" example:"success"`
	Data    any    `json:"data,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code" example:"500"`
	Message string `json:"message" example:"server_error"`
}

type EmptyObj struct{}

func SendResponseSuccess(c *gin.Context, httpStatus int, message string, data any) {
	res := Response{
		Success: true,
		Message: message,
		Data:    data,
		Error:   nil,
	}
	c.JSON(httpStatus, res)
}

func SendResponseFailure(c *gin.Context, httpStatus int, message string, data any, err string) {
	res := Response{
		Success: false,
		Message: message,
		Data:    data,
		Error: &Error{
			Code:    httpStatus,
			Message: err,
		},
	}
	c.AbortWithStatusJSON(httpStatus, res)
}
