// SPDX-FileCopyrightText: 2023-2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGinAuthMiddleware(t *testing.T) {
	t.Run("Nil func", func(t *testing.T) {
		auth, err := NewGinAuthMiddleware(nil)

		require.EqualError(t, err, "parseHeaderFunc cannot be nil")
		require.Nil(t, auth)
	})
}

func TestGinAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("No header", func(t *testing.T) {
		parseRequestFunc := func(ctx context.Context, auth string, origin string) (UserContext, error) {
			return UserContext{}, nil
		}

		auth, err := NewGinAuthMiddleware(parseRequestFunc)
		require.NoError(t, err)
		require.NotNil(t, auth)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request, _ = http.NewRequest("GET", "/", nil)
		auth(ctx)

		require.Len(t, ctx.Errors, 1)
		assert.ErrorContains(t, ctx.Errors[0], "could not bind header")
		assert.ErrorContains(t, ctx.Errors[0], "Authorization")
	})

	t.Run("Failed auth", func(t *testing.T) {
		parseRequestFunc := func(ctx context.Context, auth string, origin string) (UserContext, error) {
			return UserContext{}, errors.New("test error")
		}

		auth, err := NewGinAuthMiddleware(parseRequestFunc)
		require.NoError(t, err)
		require.NotNil(t, auth)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request, _ = http.NewRequest("GET", "/", nil)
		ctx.Request.Header.Add("Authorization", "bearer token")
		ctx.Request.Header.Add("Origin", "origin")
		auth(ctx)

		require.Len(t, ctx.Errors, 1)
		assert.ErrorContains(t, ctx.Errors[0], "authorization failed")
		assert.ErrorContains(t, ctx.Errors[0], "test error")
	})

	t.Run("OK", func(t *testing.T) {
		parseRequestFunc := func(ctx context.Context, auth string, origin string) (UserContext, error) {
			return UserContext{
				Realm:        "user-management",
				UserID:       "12345",
				EmailAddress: "some@email.com",
				UserName:     "some_user",
				Roles:        []string{"some_role"},
				Groups:       []string{"some_group"},
			}, nil
		}

		auth, err := NewGinAuthMiddleware(parseRequestFunc)
		require.NoError(t, err)
		require.NotNil(t, auth)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request, _ = http.NewRequest("GET", "/", nil)
		ctx.Request.Header.Add("Authorization", fmt.Sprintf("bearer %s", validToken))
		ctx.Request.Header.Add("Origin", validOrigin)
		auth(ctx)

		require.Equal(t, http.StatusOK, w.Code)
		require.Empty(t, ctx.Errors)

		userContext, err := GetUserContext(ctx)
		require.NoError(t, err)
		require.NotZero(t, userContext)

		assert.Equal(t, "12345", userContext.UserID)
		assert.Equal(t, "some@email.com", userContext.EmailAddress)
		assert.Equal(t, "some_user", userContext.UserName)
		assert.Equal(t, []string{"some_role"}, userContext.Roles)
		assert.Equal(t, []string{"some_group"}, userContext.Groups)
	})
}
