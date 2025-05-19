package validator

import (
	"github.com/go-playground/validator/v10"
)

type Validator interface {
	Validate(out any) error
}

type service struct {
	v *validator.Validate
}

func NewValidator() Validator {
	v := validator.New()
	return &service{v: v}
}

func (s *service) Validate(out any) error {
	return s.v.Struct(out)
}
