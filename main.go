package main

import (
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/naomigrain/coba-go-cookie/exception"
	"github.com/naomigrain/coba-go-cookie/handler"
)

func main() {
	godotenv.Load()

	e := echo.New()
	e.GET("/get", handler.Get)
	e.GET("/protected", handler.Protected)
	e.HTTPErrorHandler = exception.CustomErrorHandler

	e.Logger.Fatal(e.Start(":5000"))
}
