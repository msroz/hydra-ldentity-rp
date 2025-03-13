package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"
)

// config, codeを受け取ってID Tokenを返す
func TokenRequestWithPrivateKeyJwt(config oauth2.Config, code string, codeVerifier string) (*oauth2.Token, error) {
	// configの値を渡すとhttp://hydra:4444/oauth2/tokenになってエラーになっちゃう
	tokenUrl := "http://127.0.0.1:8888/oauth2/token"

	clientAssertion, err := generateClientAssertion(config.ClientID, tokenUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client assertion: %w", err)
	}
	log.Printf("client assertion jwt: %s", clientAssertion)

	client := &http.Client{}
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", config.ClientID)
	data.Set("code", code)
	data.Set("redirect_uri", config.RedirectURL)
	data.Set("code_verifier", codeVerifier)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", clientAssertion)

	log.Printf("token request body: %s", data.Encode())

	req, err := http.NewRequest("POST", config.Endpoint.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed: %s", body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	var tokens oauth2.Token
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	return tokens.WithExtra(raw), nil
}

func generateClientAssertion(clientId string, tokenEndpoint string) (string, error) {
	// プライベートキーの読み込み
	keyData, err := os.ReadFile("./keys/private_key.jwk")
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}

	// JWK のパース
	key, err := jwk.ParseKey(keyData)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// jti の生成
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}

	// JWT の生成
	token := jwt.New()
	now := time.Now()
	token.Set(jwt.IssuerKey, clientId)
	token.Set(jwt.SubjectKey, clientId)
	token.Set(jwt.AudienceKey, tokenEndpoint)
	token.Set(jwt.JwtIDKey, jti)
	token.Set(jwt.ExpirationKey, now.Add(time.Hour).Unix())
	token.Set(jwt.IssuedAtKey, now.Unix())

	// JWT の署名
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return string(signed), nil
}

func generateJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
