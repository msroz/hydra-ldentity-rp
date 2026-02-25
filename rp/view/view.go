package view

import (
	"html/template"
	"net/http"

	"github.com/pkg/errors"
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
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	}

	if err := t.Execute(w, data); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	}

	return true
}
