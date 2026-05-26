package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"auth-service/internal/sales/service"
)

type TaxIntegrationServiceHandler struct {
	service service.TaxIntegrationService
}

func NewTaxIntegrationServiceHandler(service service.TaxIntegrationService) *TaxIntegrationServiceHandler {
	return &TaxIntegrationServiceHandler{
		service: service,
	}
}

func (h *TaxIntegrationServiceHandler) RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/tax")

	group.GET("/:id", h.GetByID)
	group.POST("/", h.Create)
	group.PUT("/:id", h.Update)
	group.DELETE("/:id", h.Delete)
}

func (h *TaxIntegrationServiceHandler) GetByID(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetByID not implemented",
	})
}

func (h *TaxIntegrationServiceHandler) Create(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Create not implemented",
	})
}

func (h *TaxIntegrationServiceHandler) Update(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Update not implemented",
	})
}

func (h *TaxIntegrationServiceHandler) Delete(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Delete not implemented",
	})
}
