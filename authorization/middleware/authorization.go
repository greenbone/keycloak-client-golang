package middleware

import (
	"fmt"
	"github.com/gin-gonic/gin"
	ks "github.com/greenbone/user-management-api/authorization/jwtTokenService"
	"net/http"
)

func CheckAuthorization(ctx *gin.Context, adapter interface {
	EvaluateJwtToken(token string) (ks.UserData, error)
},
) {
	var header struct {
		Authorization string `header:"Authorization"`
	}

	if err := ctx.ShouldBindHeader(&header); err != nil {
		_ = ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("could not bind header: %w", err))
		return
	}

	token := header.Authorization

	userData, err := adapter.EvaluateJwtToken(token)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("authorization failed: %w", err))
		return
	}

	ctx.Set("userData", userData)

	ctx.Next()
}
