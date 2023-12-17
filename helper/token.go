package helper

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/naomigrain/coba-go-cookie/exception"
)

func GenerateRefreshToken() (string, int64, error) {
	var refreshToken string
	var expiresAt int64

	// Get refresh expire time from env or set as default
	expMinutes, err := strconv.Atoi(
		os.Getenv("JWT_REFRESH_KEY_EXPIRE_MINUTES"))
	if err != nil {
		expMinutes = 10
	}
	expDuration := time.Duration(expMinutes) * time.Minute

	// Key from env
	key := os.Getenv("JWT_REFRESH_KEY_SIGNATURE")

	// Create Claim
	expiresAt = time.Now().Add(expDuration).Unix()

	t := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"exp": expiresAt,
		})

	// Sign the string with claim and key
	s, err := t.SignedString([]byte(key))
	if err != nil {
		return refreshToken, 0, &exception.BadRequestError{Message: err.Error()}
	}

	return s, expiresAt, nil
}

type AccessData struct {
	Name      string
	ExpiredAt int64
}

func GenerateAccessToken() (string, int64, error) {
	var accessToken string
	var expiresAt int64

	// Get access expire time from env or set as default
	expMinutes, err := strconv.Atoi(os.Getenv("JWT_ACCESS_KEY_EXPIRE_MINUTES"))
	if err != nil {
		expMinutes = 10
	}
	expDuration := time.Duration(expMinutes) * time.Minute

	// Key from env
	key := os.Getenv("JWT_ACCESS_KEY_SIGNATURE")

	// Create claim
	expiresAt = time.Now().Add(expDuration).Unix()

	t := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"exp": expiresAt,
			"data": AccessData{
				Name: "thisIsDefaulName",
			},
		})

	// Sign with key
	s, err := t.SignedString([]byte(key))
	if err != nil {
		return accessToken, 0, &exception.BadRequestError{Message: err.Error()}
	}

	return s, expiresAt, nil
}

func ParseRefreshToken(refreshToken string) (time.Time, error) {
	var expiresAt *jwt.NumericDate

	key := os.Getenv("JWT_REFRESH_KEY_SIGNATURE")

	// Immidiately parse the token
	token, err := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return expiresAt.Time, &exception.BadRequestError{Message: err.Error()}
	}

	// Convert claim for token into mapclaim
	claims := token.Claims.(jwt.MapClaims)
	expiresAt, err = claims.GetExpirationTime()
	if err != nil {
		return expiresAt.Time, &exception.BadRequestError{Message: err.Error()}
	}

	return expiresAt.Time, nil
}

func ParseAccessToken(accessToken string) (AccessData, error) {
	var data AccessData

	key := os.Getenv("JWT_ACCESS_KEY_SIGNATURE")

	// Immidiately parse the token
	token, err := jwt.Parse(accessToken, func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return data, &exception.BadRequestError{Message: err.Error()}
	}

	// Convert claim for token into mapclain
	claims := token.Claims.(jwt.MapClaims)
	dataInt := claims["data"].(map[string]interface{})
	data.Name = dataInt["Name"].(string)

	// Get expiration time
	expiredAt, err := claims.GetExpirationTime()
	if err != nil {
		return data, &exception.BadRequestError{Message: err.Error()}
	}
	data.ExpiredAt = expiredAt.Time.Unix()

	return data, nil
}
