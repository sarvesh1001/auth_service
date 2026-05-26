package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"auth-service/internal/sales/service"
)

type CreditCheckServiceHandler struct {
	service service.CreditCheckService
}

func NewCreditCheckServiceHandler(service service.CreditCheckService) *CreditCheckServiceHandler {
	return &CreditCheckServiceHandler{
		service: service,
	}
}

func (h *CreditCheckServiceHandler) RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/credit_check")

	group.GET("/:id", h.GetByID)
	group.POST("/", h.Create)
	group.PUT("/:id", h.Update)
	group.DELETE("/:id", h.Delete)
}

func (h *CreditCheckServiceHandler) GetByID(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetByID not implemented",
	})
}

func (h *CreditCheckServiceHandler) Create(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Create not implemented",
	})
}

func (h *CreditCheckServiceHandler) Update(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Update not implemented",
	})
}

func (h *CreditCheckServiceHandler) Delete(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Delete not implemented",
	})
}
