// SPDX-FileCopyrightText: 2023-2024 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
)

// NewGinAuthMiddleware creates a new Gin middleware to authorize each request via Authorization header in format "BEARER JWT_TOKEN" where JWT_TOKEN is the keycloak auth token.
// NOTE: Origin header is optional and if not present it will not be tested against the ones in token.
// It sets the UserContext with extracted token claims in gin context. Use GetUserContext on gin.Context to extract this data.
func NewGinAuthMiddleware(parseRequestFunc func(ctx context.Context, authorizationHeader string, originHeader string) (UserContext, error)) (gin.HandlerFunc, error) {
	if parseRequestFunc == nil {
		return nil, errors.New("parseHeaderFunc cannot be nil")
	}

	return func(ctx *gin.Context) {
		var header struct {
			Authorization string `header:"Authorization" binding:"required"`
			Origin        string `header:"Origin"`
		}

		if err := ctx.ShouldBindHeader(&header); err != nil {
			AbortWithError(ctx, fmt.Errorf("could not bind header: %w", err))
			return
		}

		userContext, err := parseRequestFunc(ctx, header.Authorization, header.Origin)
		if err != nil {
			AbortWithError(ctx, fmt.Errorf("authorization failed: %w", err))
			return
		}

		SetUserContext(ctx, userContext)

		ctx.Next()
	}, nil
}

func AbortWithError(ctx *gin.Context, err error) {
	_ = ctx.Error(err)
	ctx.Abort()
}
