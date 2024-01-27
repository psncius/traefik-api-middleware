package traefik_api_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

type Config struct {
	AuthenticationHeader     bool     `json:"authenticationHeader,omitempty"`
	AuthenticationHeaderName string   `json:"headerName,omitempty"`
	BearerHeader             bool     `json:"bearerHeader,omitempty"`
	BearerHeaderName         string   `json:"bearerHeaderName,omitempty"`
	Keys                     []string `json:"keys,omitempty"`
	RemoveHeadersOnSuccess   bool     `json:"removeHeadersOnSuccess,omitempty"`
}

type Response struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

func CreateConfig() *Config {
	return &Config{
		AuthenticationHeader:     true,
		AuthenticationHeaderName: "X-API-KEY",
		BearerHeader:             true,
		BearerHeaderName:         "Authorization",
		Keys:                     make([]string, 0),
		RemoveHeadersOnSuccess:   true,
	}
}

type KeyAuth struct {
	next                     http.Handler
	authenticationHeader     bool
	authenticationHeaderName string
	bearerHeader             bool
	bearerHeaderName         string
	keys                     []string
	removeHeadersOnSuccess   bool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("Creating plugin: %s instance: %+v, ctx: %+v\n", name, *config, ctx)

	if len(config.Keys) == 0 {
		return nil, fmt.Errorf("must specify at least one valid key")
	}

	if !config.AuthenticationHeader && !config.BearerHeader {
		return nil, fmt.Errorf("at least one header type must be true")
	}

	return &KeyAuth{
		next:                     next,
		authenticationHeader:     config.AuthenticationHeader,
		authenticationHeaderName: config.AuthenticationHeaderName,
		bearerHeader:             config.BearerHeader,
		bearerHeaderName:         config.BearerHeaderName,
		keys:                     config.Keys,
		removeHeadersOnSuccess:   config.RemoveHeadersOnSuccess,
	}, nil
}

func contains(key string, validKeys []string) bool {
	for _, a := range validKeys {
		if a == key {
			return true
		}
	}
	return false
}

func bearer(key string, validKeys []string) bool {
	re, _ := regexp.Compile(`Bearer\s(?P<key>[^$]+)`)
	matches := re.FindStringSubmatch(key)
	if matches == nil {
		return false
	}

	keyIndex := re.SubexpIndex("key")
	extractedKey := matches[keyIndex]
	return contains(extractedKey, validKeys)
}

type responseWriterWrapper struct {
	http.ResponseWriter
	modifiedHeader http.Header
	ignoreHeaders  []string
}

func newResponseWriterWrapper(rw http.ResponseWriter, ignoreHeaders []string) *responseWriterWrapper {
	modifiedHeader := make(http.Header)
	for k, vv := range rw.Header() {
		modifiedHeader[k] = vv
	}

	return &responseWriterWrapper{
		ResponseWriter: rw,
		modifiedHeader: modifiedHeader,
		ignoreHeaders:  ignoreHeaders,
	}
}

func (rw *responseWriterWrapper) Header() http.Header {
	for _, header := range rw.ignoreHeaders {
		delete(rw.modifiedHeader, header)
	}
	return rw.modifiedHeader
}

func (rw *responseWriterWrapper) WriteHeader(statusCode int) {
	for k, vv := range rw.modifiedHeader {
		rw.ResponseWriter.Header()[k] = vv
	}
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (ka *KeyAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ignoreHeaders := []string{}
	if ka.removeHeadersOnSuccess {
		if ka.authenticationHeader {
			ignoreHeaders = append(ignoreHeaders, ka.authenticationHeaderName)
		}
		if ka.bearerHeader {
			ignoreHeaders = append(ignoreHeaders, ka.bearerHeaderName)
		}
	}
	wrappedRW := newResponseWriterWrapper(rw, ignoreHeaders)

	if ka.authenticationHeader && contains(req.Header.Get(ka.authenticationHeaderName), ka.keys) {
		ka.next.ServeHTTP(wrappedRW, req)
		return
	}

	if ka.bearerHeader && bearer(req.Header.Get(ka.bearerHeaderName), ka.keys) {
		ka.next.ServeHTTP(wrappedRW, req)
		return
	}

	var response Response
	if ka.authenticationHeader && ka.bearerHeader {
		response = Response{
			Message:    fmt.Sprintf("Invalid API Key."),
			StatusCode: http.StatusForbidden,
		}
	} else if ka.authenticationHeader && !ka.bearerHeader {
		response = Response{
			Message:    fmt.Sprintf("Invalid API Key."),
			StatusCode: http.StatusForbidden,
		}
	} else if !ka.authenticationHeader && ka.bearerHeader {
		response = Response{
			Message:    fmt.Sprintf("Invalid API Key."),
			StatusCode: http.StatusForbidden,
		}
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(response.StatusCode)
	if err := json.NewEncoder(rw).Encode(response); err != nil {
		fmt.Printf("Error when sending response to an invalid key: %s", err.Error())
	}
}
