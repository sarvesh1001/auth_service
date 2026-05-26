package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"auth-service/internal/sales/service"
)

type SalesRepServiceHandler struct {
	service service.SalesRepService
}

func NewSalesRepServiceHandler(service service.SalesRepService) *SalesRepServiceHandler {
	return &SalesRepServiceHandler{
		service: service,
	}
}

func (h *SalesRepServiceHandler) RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/sales_rep")

	group.GET("/:id", h.GetByID)
	group.POST("/", h.Create)
	group.PUT("/:id", h.Update)
	group.DELETE("/:id", h.Delete)
}

func (h *SalesRepServiceHandler) GetByID(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetByID not implemented",
	})
}

func (h *SalesRepServiceHandler) Create(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Create not implemented",
	})
}

func (h *SalesRepServiceHandler) Update(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Update not implemented",
	})
}

func (h *SalesRepServiceHandler) Delete(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Delete not implemented",
	})
}
