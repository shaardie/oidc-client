package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

func GenerateAuthCodeURL(oauth2Config oauth2.Config, state string, tokenClaims []string, userinfoClaims []string) (string, error) {
	claimsParam := struct {
		IDToken  map[string]*struct{} `json:"id_token,omitempty"`
		Userinfo map[string]*struct{} `json:"userinfo,omitempty"`
	}{
		IDToken:  map[string]*struct{}{},
		Userinfo: map[string]*struct{}{},
	}
	for _, tc := range tokenClaims {
		claimsParam.IDToken[tc] = nil
	}
	for _, uc := range userinfoClaims {
		claimsParam.Userinfo[uc] = nil
	}

	if len(claimsParam.IDToken) == 0 && len(claimsParam.Userinfo) == 0 {
		return oauth2Config.AuthCodeURL(state), nil
	}

	b, err := json.Marshal(claimsParam)
	if err != nil {
		return "", fmt.Errorf("unable to marshal claims parameter, %w", err)
	}
	return oauth2Config.AuthCodeURL(state, oauth2.SetAuthURLParam("claims", string(b))), nil
}

const (
	FailurePath = "/oidc-client/failure"
	SuccessPath = "/oidc-client/success"
)

func HandleRedirect(ctx context.Context, u *url.URL, state string) (string, error) {
	done := make(chan struct{}, 1)
	mux := http.NewServeMux()
	p := "/"
	if u.Path != "" {
		p = u.Path
	}

	var errHandleRedirect error
	var code string
	mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
		params, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			errHandleRedirect = err
			http.Redirect(w, r, FailurePath, http.StatusTemporaryRedirect)
			return
		}

		if params.Get("error") != "" {
			errHandleRedirect = fmt.Errorf("oidc flow failed, %v, %v", params.Get("error"), params.Get("error_description"))
			http.Redirect(w, r, FailurePath, http.StatusTemporaryRedirect)
			return
		}

		if params.Get("state") != state {
			errHandleRedirect = errors.New("state does not match")
			http.Redirect(w, r, FailurePath, http.StatusTemporaryRedirect)
			return
		}

		code = params.Get("code")
		if code == "" {
			errHandleRedirect = errors.New("code empty")
			return
		}

		http.Redirect(w, r, SuccessPath, http.StatusTemporaryRedirect)
	})

	mux.HandleFunc(FailurePath, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Failed to do oidc flow.", http.StatusBadGateway)
		done <- struct{}{}
	})

	mux.HandleFunc(SuccessPath, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Success. You can close this window now.")
		done <- struct{}{}
	})

	s := http.Server{
		Addr:    u.Host,
		Handler: mux,
	}

	var errListenAndServer error
	go func() {
		err := s.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errListenAndServer = err
		}
	}()

	<-done
	errShutdown := s.Shutdown(ctx)
	return code, errors.Join(errHandleRedirect, errListenAndServer, errShutdown)
}
