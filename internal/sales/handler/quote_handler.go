package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"auth-service/internal/sales/service"
)

type QuoteServiceHandler struct {
	service service.QuoteService
}

func NewQuoteServiceHandler(service service.QuoteService) *QuoteServiceHandler {
	return &QuoteServiceHandler{
		service: service,
	}
}

func (h *QuoteServiceHandler) RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/quote")

	group.GET("/:id", h.GetByID)
	group.POST("/", h.Create)
	group.PUT("/:id", h.Update)
	group.DELETE("/:id", h.Delete)
}

func (h *QuoteServiceHandler) GetByID(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetByID not implemented",
	})
}

func (h *QuoteServiceHandler) Create(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Create not implemented",
	})
}

func (h *QuoteServiceHandler) Update(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Update not implemented",
	})
}

func (h *QuoteServiceHandler) Delete(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Delete not implemented",
	})
}
