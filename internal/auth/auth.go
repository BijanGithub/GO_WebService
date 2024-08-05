package auth

import (
	"errors"
	"net/http"
	"strings"
)

// GetAPIKey should extract the API key from the header of HTTP request
// Template of header message for authentication&authorization could be:
// Authorization: ApiKey {the API key}
func GetAPIKey(headers http.Header) (string, error) {
	val := headers.Get("Authorization")
	if val == "" {
		return "", errors.New("no authentication info found")
	}
	vals := strings.Split(val, " ")
	if len(vals) != 2 {
		return "", errors.New("malformed auth header")
	}
	if vals[0] != "ApiKey" {
		return "", errors.New("not found first part of the auth header")
	}
	return vals[1], nil
}
