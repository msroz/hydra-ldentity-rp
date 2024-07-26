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
    --redirect-uri http://127.0.0.1:5555/callback)

$ echo $code_client
{"client_id":"8d14540d-55b7-4d55-8eaf-cf1392dbbcd9","client_name":"","client_secret":"YpSNt87xkAYzOzkuU3Qphuu8as","client_secret_expires_at":0,"client_uri":"","created_at":"2024-07-30T00:51:11Z","grant_types":["authorization_code","refresh_token"],"jwks":{},"logo_uri":"","metadata":{},"owner":"","policy_uri":"","redirect_uris":["http://127.0.0.1:5555/callback"],"registration_access_token":"ory_at_M5gMHHOoSF69jn3b0I4uT96_THXae5uAc7ABK15G4UM.PAgzt23bxY08qbF2GRQA2ZHAruZFPMqL8yDsjWAfInw","registration_client_uri":"http://127.0.0.1:4444/oauth2/register/8d14540d-55b7-4d55-8eaf-cf1392dbbcd9","request_object_signing_alg":"RS256","response_types":["code","id_token"],"scope":"openid offline","skip_consent":false,"subject_type":"pairwise","token_endpoint_auth_method":"client_secret_basic","tos_uri":"","updated_at":"2024-07-30T00:51:11.411531Z","userinfo_signed_response_alg":"none"}

$ code_client_id=$(echo $code_client | jq -r '.client_id')
$ code_client_secret=$(echo $code_client | jq -r '.client_secret')

$ echo "code_client_id:$code_client_id\ncode_client_secret:$code_client_secret"
code_client_id:8d14540d-55b7-4d55-8eaf-cf1392dbbcd9
code_client_secret:YpSNt87xkAYzOzkuU3Qphuu8as
```

- Set Client ID ans Secret into RP

```yml
# in docker-compose.yml
    environment:
      - CLIENT_ID=8d14540d-55b7-4d55-8eaf-cf1392dbbcd9
      - CLIENT_SECRET=YpSNt87xkAYzOzkuU3Qphuu8as # This is a secret, do not expose it in production
```


# References

- [5 minute tutorial | Ory](https://www.ory.sh/docs/hydra/5min-tutorial)
