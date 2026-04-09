package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"rp/config"
)

func IntrospectAccessToken(accessToken string) (map[string]interface{}, error) {
	endpoint := config.GetHydraAdminIntrospectURL()

	resp, err := http.PostForm(endpoint, url.Values{
		"token": {accessToken},
	})
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read introspection response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	return result, nil
}
