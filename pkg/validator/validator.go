package validator

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"net"
	"net/smtp"
	"reflect"
	"regexp"
	"strings"
)

var (
	emailRegex = regexp.MustCompile(`^((([0-9A-Za-z][-0-9A-z.]{0,30}[0-9A-Za-z]?)|([0-9А-Яа-я][-0-9А-я.]{0,30}[0-9А-Яа-я]?))@([-A-Za-z]+\.)+[-A-Za-z]{2,})$`)
)

type Validator interface {
	Validate(i interface{}) error
}

type valid struct {
	v *validator.Validate
}

func NewValidator() (Validator, error) {
	v := validator.New()
	if err := v.RegisterValidation("email", emailValidate); err != nil {
		return nil, err
	}
	return &valid{v: v}, nil
}

func (v *valid) Validate(i interface{}) error {
	if err := v.v.Struct(i); err != nil {
		return validateError(err.(validator.ValidationErrors)[0])
	}
	return nil
}

func validateError(err validator.FieldError) error {
	switch err.Tag() {
	case "email":
		return errors.New("field email is incorrect. Make sure that you entered the email correctly and it exists")
	default:
		return fmt.Errorf("field %s is required", err.Field())
	}
}

// Проверяем почту сначала через регулярку (похожа на настоящую), потом ее реальное существование через smtp
func emailValidate(fl validator.FieldLevel) bool {
	if fl.Field().Kind() != reflect.String {
		return false
	}
	email := fl.Field().String()

	if !emailRegex.MatchString(email) {
		return false
	}

	domain := email[strings.LastIndex(email, "@")+1:]
	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		return false
	}
	smtpServer := mxRecords[0].Host + ":25"
	client, err := smtp.Dial(smtpServer)
	if err != nil {
		return false
	}
	defer func() { _ = client.Close() }()
	if err = client.Hello("example.com"); err != nil {
		return false
	}
	if err = client.Mail("test@example.com"); err != nil {
		return false
	}
	if err = client.Rcpt(email); err != nil {
		return false
	}
	return true
}
