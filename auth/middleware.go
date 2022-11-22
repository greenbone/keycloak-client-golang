package auth

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func NewGinAuthMiddleware(parseHeaderFunc func(authHeader string) (*UserContext, error)) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var header struct {
			Authorization string `header:"Authorization"`
		}

		if err := ctx.ShouldBindHeader(&header); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("could not bind header: %w", err))
			return
		}

		userContext, err := parseHeaderFunc(header.Authorization)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("authorization failed: %w", err))
			return
		}

		setUserContext(ctx, *userContext)

		ctx.Next()
	}
}
