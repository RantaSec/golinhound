package configure

import (
	"bytes"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

//go:embed custom-nodes.json
var customNodesJSON []byte

const configureHTTPTimeout = 30 * time.Second

type loginRequest struct {
	LoginMethod string `json:"login_method"`
	Username    string `json:"username"`
	Secret      string `json:"secret"`
}

type loginResponse struct {
	Data struct {
		SessionToken string `json:"session_token"`
	} `json:"data"`
}

// Run logs into BloodHound at baseURL with the given credentials and
// uploads the embedded custom-nodes.json. If insecure is true, TLS verification
// is skipped (for self-signed BloodHound deployments).
func Run(baseURL, username, password string, insecure bool) error {
	baseURL = strings.TrimRight(baseURL, "/")

	client := &http.Client{
		Timeout: configureHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	token, err := bloodhoundLogin(client, baseURL, username, password)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := uploadCustomNodes(client, baseURL, token); err != nil {
		return err
	}
	return nil
}

// bloodhoundLogin authenticates against POST /api/v2/login and returns
// the JWT session token from the response.
func bloodhoundLogin(client *http.Client, baseURL, user, pass string) (string, error) {
	body, err := json.Marshal(loginRequest{LoginMethod: "secret", Username: user, Secret: pass})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", baseURL+"/api/v2/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}

	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return "", fmt.Errorf("invalid login response: %w", err)
	}
	if lr.Data.SessionToken == "" {
		return "", errors.New("login response missing session_token")
	}
	return lr.Data.SessionToken, nil
}

// uploadCustomNodes POSTs the embedded custom-nodes.json to
// /api/v2/custom-nodes using the given JWT for bearer authentication.
func uploadCustomNodes(client *http.Client, baseURL, token string) error {
	req, err := http.NewRequest("POST", baseURL+"/api/v2/custom-nodes", bytes.NewReader(customNodesJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Prefer", "wait=30")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("custom node icons are already configured in BloodHound: %s", resp.Status)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("upload failed: %s", resp.Status)
	}
	return nil
}
