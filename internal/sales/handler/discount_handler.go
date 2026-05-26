package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"auth-service/internal/sales/service"
)

type DiscountEngineServiceHandler struct {
	service service.DiscountEngineService
}

func NewDiscountEngineServiceHandler(service service.DiscountEngineService) *DiscountEngineServiceHandler {
	return &DiscountEngineServiceHandler{
		service: service,
	}
}

func (h *DiscountEngineServiceHandler) RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/discount")

	group.GET("/:id", h.GetByID)
	group.POST("/", h.Create)
	group.PUT("/:id", h.Update)
	group.DELETE("/:id", h.Delete)
}

func (h *DiscountEngineServiceHandler) GetByID(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetByID not implemented",
	})
}

func (h *DiscountEngineServiceHandler) Create(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Create not implemented",
	})
}

func (h *DiscountEngineServiceHandler) Update(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Update not implemented",
	})
}

func (h *DiscountEngineServiceHandler) Delete(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Delete not implemented",
	})
}
