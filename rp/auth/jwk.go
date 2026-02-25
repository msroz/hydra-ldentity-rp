package auth

import (
	"context"
	"rp/config"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// FetchHydraJWKs fetches the JWKS from Hydra for token verification
func FetchHydraJWKs(ctx context.Context) (jwk.Set, error) {
	return jwk.Fetch(ctx, config.GetHydraJWKSetURL())
}
