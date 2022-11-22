package auth

import (
	"errors"

	"github.com/gin-gonic/gin"
)

const userContextKey = "USER_CONTEXT_DATA"

type UserContext struct {
	UserName       string
	EmailAddress   string
	KeycloakUserID string
	Roles          []string
	Groups         []string
}

func setUserContext(ctx *gin.Context, userCtx UserContext) {
	ctx.Set(userContextKey, userCtx)
}

// todo: return pointer?
func GetUserContext(ctx *gin.Context) (UserContext, error) {
	v, ok := ctx.Get(userContextKey)
	if !ok {
		return UserContext{}, errors.New("user context data not found")
	}

	userData, ok := v.(UserContext)
	if !ok {
		return UserContext{}, errors.New("user context data has incorect type")
	}

	return userData, nil
}
