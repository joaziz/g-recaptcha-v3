package recaptchav3

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type V3ReCaptchaConfiguration struct {
	Secret            string
	GoogleVeriferLink string
}

// V3Response is the response from Google's reCAPTCHA V3 API.
type GoogleResponse struct {
	APKPackageName string    `json:"apk_package_name"`
	Action         string    `json:"action"`
	ChallengeTS    time.Time `json:"challenge_ts"`
	ErrorCodes     []string  `json:"error-codes"`
	Hostname       string    `json:"hostname"`
	Score          float64   `json:"score"`
	Success        bool      `json:"success"`
}

type V3Verifier struct {
	configurations V3ReCaptchaConfiguration
}

func NewV3Verier(conf V3ReCaptchaConfiguration) *V3Verifier {

	if conf.GoogleVeriferLink == "" {
		conf.GoogleVeriferLink = "https://www.google.com/recaptcha/api/siteverify"
	}

	return &V3Verifier{
		configurations: conf,
	}
}

func (verifier *V3Verifier) Verify(ctx context.Context, response string, remoteIP string) (GoogleResponse, error) {
	if response == "" {
		return GoogleResponse{}, fmt.Errorf("missing reponse from the client-side")
	}

	form := url.Values{
		"secret":   {verifier.configurations.Secret},
		"response": {response},
	}

	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifier.configurations.GoogleVeriferLink, strings.NewReader(form.Encode()))
	if err != nil {
		return GoogleResponse{}, fmt.Errorf("Error in createing reCAPTCHA V3 request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return GoogleResponse{}, fmt.Errorf("error in perform reCAPTCHA V3 request: %w", err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	var res GoogleResponse
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return GoogleResponse{}, fmt.Errorf("error : can`t parse reCAPTCHA V3 JSON response: %w", err)
	}

	return res, nil
}
