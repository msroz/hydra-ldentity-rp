# hydra-ldentity-rp

hydra + self-hosted identity server + sample rp

# Requirements

- Docker
- Docker Compose
- `jq`

# Get it started

- Run containers

```bash
$ docker compose up
```

- Register client in Hydra

```bash
$ code_client=$(docker-compose exec hydra \
    hydra create client \
    --endpoint http://127.0.0.1:4445 \
    --grant-type authorization_code,refresh_token \
    --response-type code,id_token \
    --format json \
    --scope openid --scope offline \
    --subject-type pairwise  \
    --token-endpoint-auth-method private_key_jwt \
    --jwks-uri http://127.0.0.1:5555/.well-known/jwks.json \
    --redirect-uri http://127.0.0.1:5555/callback)

$ echo $code_client
{"client_id":"0ca2fd2b-0df7-467c-a97f-90b8494cb388","client_name":"","client_secret":"zqIWWi3MApnwQGxztXhJSxz7Qm","client_secret_expires_at":0,"client_uri":"","created_at":"2024-09-18T06:52:42Z","grant_types":["authorization_code","refresh_token"],"jwks":{},"jwks_uri":"http://rp:5555/.well-known/jwks.json","logo_uri":"","metadata":{},"owner":"","policy_uri":"","redirect_uris":["http://127.0.0.1:5555/callback"],"registration_access_token":"ory_at_WSjU3FpnzIc4w_aY8wEjP97b_lBd_aMNXJGiFiINDJk.P83WqokRN0nf7dF6Z_ooWlTcwEqOhxlXmy_nBUjoXFw","registration_client_uri":"http://127.0.0.1:4444/oauth2/register/","request_object_signing_alg":"RS256","response_types":["code","id_token"],"scope":"openid offline","skip_consent":false,"skip_logout_consent":false,"subject_type":"pairwise","token_endpoint_auth_method":"private_key_jwt","tos_uri":"","updated_at":"2024-09-18T06:52:42.139092Z","userinfo_signed_response_alg":"none"}

$ code_client_id=$(echo $code_client | jq -r '.client_id')
$ code_client_secret=$(echo $code_client | jq -r '.client_secret')

$ echo "code_client_id:$code_client_id\ncode_client_secret:$code_client_secret"
code_client_id:8d14540d-55b7-4d55-8eaf-cf1392dbbcd9
code_client_secret:YpSNt87xkAYzOzkuU3Qphuu8as
```

- Set Client ID ans Secret into RP

```
# in .env
DEFAULT_CLIENT_ID=0ca2fd2b-0df7-467c-a97f-90b8494cb388
DEFAULT_CLIENT_SECRET=zqIWWi3MApnwQGxztXhJSxz7Qm
```

Or, you can save cleint id and secret via form in http://127.0.0.1:5555/


# References

- [5 minute tutorial | Ory](https://www.ory.sh/docs/hydra/5min-tutorial)
