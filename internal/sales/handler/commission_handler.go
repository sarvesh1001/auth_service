package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"auth-service/internal/sales/service"
)

type SalesRepCommissionServiceHandler struct {
	service service.SalesRepCommissionService
}

func NewSalesRepCommissionServiceHandler(service service.SalesRepCommissionService) *SalesRepCommissionServiceHandler {
	return &SalesRepCommissionServiceHandler{
		service: service,
	}
}

func (h *SalesRepCommissionServiceHandler) RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/commission")

	group.GET("/:id", h.GetByID)
	group.POST("/", h.Create)
	group.PUT("/:id", h.Update)
	group.DELETE("/:id", h.Delete)
}

func (h *SalesRepCommissionServiceHandler) GetByID(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetByID not implemented",
	})
}

func (h *SalesRepCommissionServiceHandler) Create(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Create not implemented",
	})
}

func (h *SalesRepCommissionServiceHandler) Update(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Update not implemented",
	})
}

func (h *SalesRepCommissionServiceHandler) Delete(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Delete not implemented",
	})
}
