package exception

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type ErrorWebResonse struct {
	Message string `json:"message"`
}

func CustomErrorHandler(err error, c echo.Context) {
	// Default response for error
	res := ErrorWebResonse{
		Message: err.Error(),
	}
	code := http.StatusInternalServerError

	if _, ok := err.(*BadRequestError); ok {
		code = http.StatusBadRequest
	}

	c.JSON(code, res)
}
