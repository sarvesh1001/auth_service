package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"auth-service/internal/sales/service"
)

type PricingServiceHandler struct {
	service service.PricingService
}

func NewPricingServiceHandler(service service.PricingService) *PricingServiceHandler {
	return &PricingServiceHandler{
		service: service,
	}
}

func (h *PricingServiceHandler) RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/pricing")

	group.GET("/:id", h.GetByID)
	group.POST("/", h.Create)
	group.PUT("/:id", h.Update)
	group.DELETE("/:id", h.Delete)
}

func (h *PricingServiceHandler) GetByID(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetByID not implemented",
	})
}

func (h *PricingServiceHandler) Create(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Create not implemented",
	})
}

func (h *PricingServiceHandler) Update(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Update not implemented",
	})
}

func (h *PricingServiceHandler) Delete(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Delete not implemented",
	})
}
