package controllers

import (
	"idp/model"
	"net/http"
)

type HookController struct {
	hydraService *model.HydraService
}

func NewHookController(hydraService *model.HydraService) *HookController {
	return &HookController{
		hydraService: hydraService,
	}
}

func (c *HookController) TokenHook(w http.ResponseWriter, r *http.Request) {
	c.hydraService.HandleTokenHook(w, r)
}
