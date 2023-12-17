package handler

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/naomigrain/coba-go-cookie/helper"
)

type Token struct {
	AccessToken  string
	RefreshToken string
}

type AuthRequest struct {
	AccessToken string `validate:"required"`
}

func Get(c echo.Context) error {
	accessToken, _, err := helper.GenerateAccessToken()
	if err != nil {
		return err
	}

	refreshToken, expiredAtRefresh, err := helper.GenerateRefreshToken()
	if err != nil {
		return err
	}

	// Store refresh token to HttpOnly Cookie
	cookie := new(http.Cookie)
	cookie.Name = "refreshToken"
	cookie.Value = refreshToken
	cookie.Expires = time.Unix(expiredAtRefresh, 0)
	cookie.HttpOnly = true
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, Token{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	})
}

type TokenResult struct {
	AccessTokenName       string
	AccessTokenExpiredAt  time.Time
	RefreshTokenExpiredAt time.Time
}

func Protected(c echo.Context) error {
	var data TokenResult

	token := new(AuthRequest)
	if err := c.Bind(token); err != nil {
		return err
	}

	// Parse access token
	accessData, err := helper.ParseAccessToken(token.AccessToken)
	if err != nil {
		return err
	}

	// Validate if acesss token expired
	if time.Now().Unix() > accessData.ExpiredAt {
		return c.JSON(http.StatusBadRequest, "Access token expired")
	}
	data.AccessTokenName = accessData.Name
	data.AccessTokenExpiredAt = time.Unix(accessData.ExpiredAt, 0)

	// Get refresh token
	cookie, err := c.Cookie("refreshToken")
	if err != nil {
		return c.JSON(http.StatusBadRequest, "Can't read Refresh Token!")
	}

	// Parse refresh token
	refreshData, err := helper.ParseRefreshToken(cookie.Value)
	if err != nil {
		return err
	}

	// Validate if refresh token expired
	if time.Now().Unix() > refreshData.Unix() {
		return c.JSON(http.StatusBadRequest, "refresh token expired")
	}
	data.RefreshTokenExpiredAt = refreshData

	return c.JSON(http.StatusOK, data)
}
