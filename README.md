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
    --id hydra-sample-id \
    --secret hydra-sample-secret \
    --endpoint http://127.0.0.1:9999\
    --grant-type authorization_code,refresh_token \
    --response-type code,id_token \
    --format json \
    --scope openid --scope offline \
    --subject-type pairwise  \
    --token-endpoint-auth-method private_key_jwt \
    --jwks-uri http://rp:7777/.well-known/jwks.json \
    --redirect-uri http://127.0.0.1:7777/callback)

$ echo $code_client | jq .
{
  "client_id": "hydra-sample-id",
  "client_name": "",
  "client_secret": "hydra-sample-secret",
  "client_secret_expires_at": 0,
  "client_uri": "",
  "created_at": "2025-03-13T01:12:17Z",
  "grant_types": [
    "authorization_code",
    "refresh_token"
  ],
  "jwks": {},
  "jwks_uri": "http://rp:7777/.well-known/jwks.json",
  "logo_uri": "",
  "metadata": {},
  "owner": "",
  "policy_uri": "",
  "redirect_uris": [
    "http://127.0.0.1:7777/callback"
  ],
  "registration_access_token": "ory_at_3jX2Mv5ps_9PKm7AaoIBXlIX-ICOvX3fiepvZJFeMfA.rlp6Yp--nXeCuI9W0og9Tu0MZbNPT6Zlpt18_yBqi-g",
  "registration_client_uri": "http://127.0.0.1:4444/oauth2/register/hydra-sample-id",
  "request_object_signing_alg": "RS256",
  "response_types": [
    "code",
    "id_token"
  ],
  "scope": "openid offline",
  "skip_consent": false,
  "skip_logout_consent": false,
  "subject_type": "pairwise",
  "token_endpoint_auth_method": "private_key_jwt",
  "tos_uri": "",
  "updated_at": "2025-03-13T01:12:16.789976Z",
  "userinfo_signed_response_alg": "none"
}
```

Or, you can save cleint id and secret via form in http://127.0.0.1:7777/


# References

- [5 minute tutorial | Ory](https://www.ory.sh/docs/hydra/5min-tutorial)
