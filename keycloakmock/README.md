# Keycloak authentication mock

This app mocks keycloak openid connect api call and get keycloak certificates api call.

To run:

```sh
make run
```

See `make help` for more scripts and details.

## Configuration

Configuration is done via env vars:

- `PORT` - port on which server starts, default: `8080`
- `KEYCLOAK_PUBLIC_URL` - public url of keycloak to mock (used as token issuer), default: `http://localhost:28080/auth`
- `FRONTEND_URL` - url of frontend (used as allowed origins in token), default: `http://localhost:3000`
- `USER_EMAIL_DOMAIN` - appended domain for user email to user name (inside token), default: `host.local`

## Sample openid connect call

```sh
USER=initial REALM=opensight-asset CLIENT_ID=local-web; \
curl -s \
    -d "client_id=$CLIENT_ID" \
    -d "grant_type=password" \
    -d "username=$USER" \
    -d "password=password" \
    "http://localhost:8080/auth/realms/$REALM/protocol/openid-connect/token"
```

NOTE: whatever value you will put in `USER`, `REALM` and `CLIENT_ID` those will be used in token.
