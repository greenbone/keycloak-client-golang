package auth

import (
	"errors"

	"github.com/gin-gonic/gin"
)

const userContextKey = "USER_CONTEXT_DATA"

// UserContext contains parsed claims from a keycloak JWT token
type UserContext struct {
	Realm          string
	UserID         string
	UserName       string
	EmailAddress   string
	Roles          []string
	Groups         []string
	allowedOrigins []string
}

func setUserContext(ctx *gin.Context, userCtx UserContext) {
	ctx.Set(userContextKey, userCtx)
}

// GetUserContext extract UserContext from gin.Context. NOTE: it is immutable, you cannot change the existing context
func GetUserContext(ctx *gin.Context) (*UserContext, error) {
	v, ok := ctx.Get(userContextKey)
	if !ok {
		return nil, errors.New("user context data not found")
	}

	userData, ok := v.(UserContext)
	if !ok {
		return nil, errors.New("user context data has incorrect type")
	}

	return &userData, nil
}
