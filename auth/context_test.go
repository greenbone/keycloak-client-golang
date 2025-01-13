// SPDX-FileCopyrightText: 2023-2025 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserContext(t *testing.T) {
	t.Run("No user context", func(t *testing.T) {
		userContext, err := GetUserContext(&gin.Context{})

		require.ErrorContains(t, err, "user context data not found")
		require.Zero(t, userContext)
	})

	t.Run("With user context", func(t *testing.T) {
		ctx := &gin.Context{}
		SetUserContext(ctx, UserContext{UserName: "user1"})

		userContext, err := GetUserContext(ctx)

		require.NoError(t, err)
		require.NotZero(t, userContext)
		assert.Equal(t, "user1", userContext.UserName)
	})

	t.Run("Wrong user context type", func(t *testing.T) {
		ctx := &gin.Context{}
		ctx.Set(userContextKey, int(42))

		userContext, err := GetUserContext(ctx)

		require.ErrorContains(t, err, "user context data has incorrect type")
		require.Zero(t, userContext)
	})

	t.Run("User context immutable", func(t *testing.T) {
		ctx := &gin.Context{}
		originalContext := UserContext{UserName: "user1"}
		SetUserContext(ctx, originalContext)

		userContext, err := GetUserContext(ctx)

		require.NoError(t, err)
		require.NotZero(t, userContext)

		userContext.UserName = "user2"
		assert.Equal(t, "user2", userContext.UserName)
		assert.Equal(t, "user1", originalContext.UserName)
	})
}
