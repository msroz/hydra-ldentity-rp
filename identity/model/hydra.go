package model

import (
	"context"
	"fmt"
	"io"
	"net/http"

	hydra "github.com/ory/client-go"
)

type HydraService struct {
	adminURL string
}

func NewHydraService(adminURL string) *HydraService {
	return &HydraService{
		adminURL: adminURL,
	}
}

func (s *HydraService) client() *hydra.APIClient {
	client := hydra.NewConfiguration()
	client.Servers = hydra.ServerConfigurations{{URL: s.adminURL}}
	return hydra.NewAPIClient(client)
}

func (s *HydraService) GetLoginRequest(ctx context.Context, challenge string) (*hydra.OAuth2LoginRequest, error) {
	client := s.client()
	resp, _, err := client.OAuth2API.GetOAuth2LoginRequest(ctx).LoginChallenge(challenge).Execute()
	return resp, err
}

func (s *HydraService) AcceptLogin(ctx context.Context, challenge string, subject string) (string, error) {
	client := s.client()
	hydraReq := hydra.NewAcceptOAuth2LoginRequest(subject)
	resp, _, err := client.OAuth2API.AcceptOAuth2LoginRequest(ctx).LoginChallenge(challenge).AcceptOAuth2LoginRequest(*hydraReq).Execute()
	if err != nil {
		return "", err
	}
	return resp.RedirectTo, nil
}

func (s *HydraService) RejectLogin(ctx context.Context, challenge string) (string, error) {
	client := s.client()
	hydraReq := hydra.NewRejectOAuth2Request()
	resp, _, err := client.OAuth2API.RejectOAuth2LoginRequest(ctx).LoginChallenge(challenge).RejectOAuth2Request(*hydraReq).Execute()
	if err != nil {
		return "", err
	}
	return resp.RedirectTo, nil
}

func (s *HydraService) AcceptLoginWithSession(ctx context.Context, challenge string, subject string, sessionID string) (string, error) {
	client := s.client()
	hydraReq := hydra.NewAcceptOAuth2LoginRequest(subject)
	hydraReq.IdentityProviderSessionId = pointer(sessionID)
	hydraReq.Remember = pointer(true)
	rememberFor := int64(3600)
	hydraReq.RememberFor = &rememberFor
	hydraReq.Acr = pointer("fake_acr")
	hydraReq.Context = map[string]interface{}{
		"accept_login_request_context": "hello",
	}

	resp, _, err := client.OAuth2API.AcceptOAuth2LoginRequest(ctx).LoginChallenge(challenge).AcceptOAuth2LoginRequest(*hydraReq).Execute()
	if err != nil {
		return "", err
	}
	return resp.RedirectTo, nil
}

func (s *HydraService) GetConsentRequest(ctx context.Context, challenge string) (*hydra.OAuth2ConsentRequest, error) {
	client := s.client()
	resp, _, err := client.OAuth2API.GetOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).Execute()
	return resp, err
}

func (s *HydraService) AcceptConsent(ctx context.Context, challenge string, grantScope []string, audience []string) (string, error) {
	client := s.client()
	rememberFor := int64(3600)
	resp, _, err := client.OAuth2API.AcceptOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).AcceptOAuth2ConsentRequest(hydra.AcceptOAuth2ConsentRequest{
		GrantScope:               grantScope,
		GrantAccessTokenAudience: audience,
		Remember:                 pointer(true),
		RememberFor:              &rememberFor,
		Context:                  map[string]interface{}{"accept_consent_request_context": "hello"},
	}).Execute()
	if err != nil {
		return "", err
	}
	return resp.RedirectTo, nil
}

func (s *HydraService) RejectConsent(ctx context.Context, challenge string) (string, error) {
	client := s.client()
	hydraReq := hydra.NewRejectOAuth2Request()
	hydraReq.Error = pointer("access_denied")
	hydraReq.ErrorDescription = pointer("The resource owner denied the request")
	resp, _, err := client.OAuth2API.RejectOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).RejectOAuth2Request(*hydraReq).Execute()
	if err != nil {
		return "", err
	}
	return resp.RedirectTo, nil
}

func (s *HydraService) CreateConsentSession(includeRawUserID bool) *hydra.AcceptOAuth2ConsentRequestSession {
	idToken := map[string]interface{}{
		"baz":                   "bar",
		"phone_number":          "08012345678",
		"phone_number_verified": true,
		"family_name":           "Doe",
		"given_name":            "John",
		"ext": map[string]interface{}{
			"hoge": "fuga",
			"piyo": []string{"a", "b", "c"},
		},
	}

	if includeRawUserID {
		idToken["raw_user_id"] = "1234567890"
	}

	session := &hydra.AcceptOAuth2ConsentRequestSession{
		AccessToken: map[string]interface{}{
			"foo": "bar",
		},
		IdToken: idToken,
	}

	return session
}

func (s *HydraService) AcceptConsentWithSession(ctx context.Context, challenge string, grantScope []string, audience []string, session *hydra.AcceptOAuth2ConsentRequestSession, remember bool) (string, error) {
	client := s.client()
	rememberFor := int64(3600)
	resp, _, err := client.OAuth2API.AcceptOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).AcceptOAuth2ConsentRequest(hydra.AcceptOAuth2ConsentRequest{
		// Context:                  map[string]interface{}{"accept_consent_request_context": "hello"},
		GrantScope:               grantScope,
		Session:                  session,
		GrantAccessTokenAudience: audience,
		Remember:                 pointer(remember),
		RememberFor:              &rememberFor,
	}).Execute()
	if err != nil {
		return "", err
	}
	return resp.RedirectTo, nil
}

func (s *HydraService) GetLogoutRequest(ctx context.Context, challenge string) (*hydra.OAuth2LogoutRequest, error) {
	client := s.client()
	resp, _, err := client.OAuth2API.GetOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
	return resp, err
}

func (s *HydraService) AcceptLogout(ctx context.Context, challenge string) (string, error) {
	client := s.client()
	resp, _, err := client.OAuth2API.AcceptOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
	if err != nil {
		return "", err
	}
	return resp.RedirectTo, nil
}

func (s *HydraService) RejectLogout(ctx context.Context, challenge string) error {
	client := s.client()
	_, err := client.OAuth2API.RejectOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
	return err
}

func (s *HydraService) HandleTokenHook(w http.ResponseWriter, r *http.Request) {
	fmt.Print("[Identity]==========================> tokenHook called \n")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	path := r.URL.Path
	fmt.Printf("[IdP / Token Hook / %s] ======> Received JSON: %s\n", path, string(body))
	w.WriteHeader(http.StatusNoContent)
}

func pointer[T any](v T) *T { return &v }
