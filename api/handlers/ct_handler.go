package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"bitbucket.org/xoduxcrt/ssl/api/dto"
	"bitbucket.org/xoduxcrt/ssl/api/services"
	"bitbucket.org/xoduxcrt/ssl/pkg/utils"
	"github.com/gin-gonic/gin"
)

type (
	CTHandler interface {
		List(c *gin.Context)
		Download(c *gin.Context)
		Query(c *gin.Context)
	}

	ctHandler struct {
		ctService services.CTService
	}
)

func NewCertHandler(cs services.CTService) CTHandler {
	return &ctHandler{
		ctService: cs,
	}
}

func (h *ctHandler) List(c *gin.Context) {
	// Get query
	queries := c.Request.URL.Query()
	searchBy, searchFor := h.extractQuery(queries)
	// Validate query
	if len(searchBy) == 0 || len(searchFor) == 0 {
		// Get pageNum and pageSize from query parameters
		pageNum, err := strconv.ParseInt(c.Query("pagenum"), 10, 64)
		if err != nil {
			utils.SendResponseFailure(c, http.StatusBadRequest, dto.MESSAGE_FAILED, nil, dto.ErrGetQueryParam.Error())
			return
		}
		pageSize, err := strconv.ParseInt(c.Query("pagesize"), 10, 64)
		if err != nil {
			utils.SendResponseFailure(c, http.StatusBadRequest, dto.MESSAGE_FAILED, nil, dto.ErrGetQueryParam.Error())
			return
		}

		resp, err := h.ctService.List(c.Request.Context(), pageNum, pageSize)
		if err != nil {
			utils.SendResponseFailure(c, http.StatusInternalServerError, dto.MESSAGE_FAILED, nil, dto.ErrServer.Error())
			return
		}

		utils.SendResponseSuccess(c, http.StatusOK, dto.MESSAGE_SUCCESS, resp)
	} else {
		searchBy = append(searchBy, "output")
		searchFor = append(searchFor, "json")
		// Search
		resp, err := h.ctService.Search(c.Request.Context(), searchBy, searchFor)
		if errors.Is(err, dto.ErrSearchResultNotFound) ||
			errors.Is(err, dto.ErrUnmarshalSearchResult) {
			utils.SendResponseFailure(c, http.StatusBadRequest, dto.MESSAGE_FAILED, nil, dto.ErrParamNotValid.Error())
			return
		} else if err != nil {
			utils.SendResponseFailure(c, http.StatusInternalServerError, dto.MESSAGE_FAILED, nil, dto.ErrServer.Error())
			return
		}

		utils.SendResponseSuccess(c, http.StatusOK, dto.MESSAGE_SUCCESS, resp)
	}
}

func (h *ctHandler) Download(c *gin.Context) {
	id := c.Param("id")
	resp, err := h.ctService.Download(c.Request.Context(), id)
	if errors.Is(err, dto.ErrCertificateNotFound) {
		utils.SendResponseFailure(c, http.StatusBadRequest, dto.MESSAGE_FAILED, nil, dto.ErrParamNotValid.Error())
		return
	} else if err != nil {
		utils.SendResponseFailure(c, http.StatusInternalServerError, dto.MESSAGE_FAILED, nil, dto.ErrServer.Error())
		return
	}
	// Set headers for CRT download
	c.Header("Content-Type", "text/plain")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.crt", id))
	// Send CRT content
	c.Data(http.StatusOK, "application/pkix-cert", resp.PEMContent)
}

func (h *ctHandler) Query(c *gin.Context) {
	// Get query
	id := c.Param("id")
	// Validate query
	if id == "" {
		utils.SendResponseFailure(c, http.StatusBadRequest, dto.MESSAGE_FAILED, nil, dto.ErrGetQueryParam.Error())
		return
	}
	// Search
	resp, err := h.ctService.Search(c.Request.Context(), []string{"id", "output"}, []string{id, "json"})
	if errors.Is(err, dto.ErrSearchResultNotFound) ||
		errors.Is(err, dto.ErrUnmarshalSearchResult) {
		utils.SendResponseFailure(c, http.StatusBadRequest, dto.MESSAGE_FAILED, nil, dto.ErrParamNotValid.Error())
		return
	} else if err != nil {
		utils.SendResponseFailure(c, http.StatusInternalServerError, dto.MESSAGE_FAILED, nil, dto.ErrServer.Error())
		return
	}

	utils.SendResponseSuccess(c, http.StatusOK, dto.MESSAGE_SUCCESS, resp)
}

func (h *ctHandler) extractQuery(queries url.Values) ([]string, []string) {
	keys, values := []string{}, []string{}
	for k, val := range queries {
		for _, f := range dto.CTSearchFields {
			if f == k {
				for _, v := range val {
					if v != "" {
						keys = append(keys, k)
						values = append(values, v)
					}
				}
			}
		}
	}

	return keys, values
}
