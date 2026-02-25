package view

import (
	"html/template"
	"net/http"
	"rp/httputil"
)

type TemplateService struct {
	templatesDir string
}

func NewTemplateService(templatesDir string) *TemplateService {
	return &TemplateService{
		templatesDir: templatesDir,
	}
}

func (s *TemplateService) RenderTemplate(w http.ResponseWriter, id string, data interface{}) bool {
	t, err := template.New(id).ParseFiles(s.templatesDir + "/" + id)
	if err != nil {
		httputil.HandleError(w, "could not render template", http.StatusInternalServerError, err)
		return false
	}

	if err := t.Execute(w, data); err != nil {
		httputil.HandleError(w, "could not render template", http.StatusInternalServerError, err)
		return false
	}

	return true
}
