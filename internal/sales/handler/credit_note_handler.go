package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"auth-service/internal/sales/service"
)

type CreditNoteServiceHandler struct {
	service service.CreditNoteService
}

func NewCreditNoteServiceHandler(service service.CreditNoteService) *CreditNoteServiceHandler {
	return &CreditNoteServiceHandler{
		service: service,
	}
}

func (h *CreditNoteServiceHandler) RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/credit_note")

	group.GET("/:id", h.GetByID)
	group.POST("/", h.Create)
	group.PUT("/:id", h.Update)
	group.DELETE("/:id", h.Delete)
}

func (h *CreditNoteServiceHandler) GetByID(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetByID not implemented",
	})
}

func (h *CreditNoteServiceHandler) Create(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Create not implemented",
	})
}

func (h *CreditNoteServiceHandler) Update(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Update not implemented",
	})
}

func (h *CreditNoteServiceHandler) Delete(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Delete not implemented",
	})
}
