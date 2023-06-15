/*
Copyright © 2023 Sven Haardiek <sven@haardiek.de>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/shaardie/oidc-client/pkg/utils"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	issuer                 string
	oauth2Config           oauth2.Config
	tokenClaimsParameter   []string
	userinfoClaimsParamter []string
	showIDToken            bool
	insecureTLS            bool
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "OIDC Login Flow",
	Long: `Login using the OIDC Login flow.
This command is highly customizable via the command line parameter.`,
	Run: func(cmd *cobra.Command, args []string) {
		if insecureTLS {
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		provider, err := oidc.NewProvider(context.TODO(), issuer)
		if err != nil {
			fmt.Printf("unable to create oidc provider, %v\n", err)
			os.Exit(1)
		}
		oauth2Config.Endpoint = provider.Endpoint()

		randBytes := make([]byte, 8)
		_, err = rand.Read(randBytes)
		if err != nil {
			fmt.Printf("unable to get random bytes for state, %v\n", err)
			os.Exit(1)
		}
		state := base64.StdEncoding.EncodeToString(randBytes)
		authCodeURL, err := utils.GenerateAuthCodeURL(oauth2Config, state, tokenClaimsParameter, userinfoClaimsParamter)
		if err != nil {
			fmt.Printf("unable to get random bytes for state, %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Authenticate at %v\n", authCodeURL)

		u, err := url.Parse(oauth2Config.RedirectURL)
		if err != nil {
			fmt.Printf("return unable to parse redirect url, %v\n", err)
			os.Exit(1)
		}
		code, err := utils.HandleRedirect(context.Background(), u, state)
		if err != nil {
			fmt.Printf("return unable to parse redirect url, %v\n", err)
			os.Exit(1)
		}

		oauth2Token, err := oauth2Config.Exchange(context.TODO(), code)
		if err != nil {
			fmt.Printf("return unable to get token, %v\n", err)
			os.Exit(1)
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			fmt.Println("id token missing")
			os.Exit(1)
		}

		if showIDToken {
			fmt.Printf("id token:\n%v\n", rawIDToken)
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})
		idToken, err := verifier.Verify(context.TODO(), rawIDToken)
		if err != nil {
			fmt.Printf("unable to verify id token, %v", err)
			os.Exit(1)
		}
		idTokenClaims := map[string]interface{}{}
		if err := idToken.Claims(&idTokenClaims); err != nil {
			fmt.Printf("unable to extract id token claims, %v", err)
			os.Exit(1)
		}
		out, err := json.MarshalIndent(idTokenClaims, "", "  ")
		if err != nil {
			fmt.Printf("unable to marshal id token claims, %v", err)
			os.Exit(1)
		}
		fmt.Printf("id token claims:\n%v\n", string(out))

		userinfo, err := provider.UserInfo(context.TODO(), oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			fmt.Printf("unable to get userinfo, %v", err)
			os.Exit(1)
		}
		userinfoClaims := map[string]interface{}{}
		if err := userinfo.Claims(&userinfoClaims); err != nil {
			fmt.Printf("unable to extract userinfo claims, %v", err)
			os.Exit(1)
		}
		out, err = json.MarshalIndent(userinfoClaims, "", "  ")
		if err != nil {
			fmt.Printf("unable to marshal userinfo claims, %v", err)
			os.Exit(1)
		}
		fmt.Printf("userinfo claims:\n%v\n", string(out))
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVarP(&issuer, "issuer", "", "", "OIDC Issuer")
	loginCmd.MarkFlagRequired("issuer")
	loginCmd.Flags().StringVarP(&oauth2Config.ClientID, "id", "", "", "OIDC Client ID")
	loginCmd.MarkFlagRequired("id")
	loginCmd.Flags().StringVarP(&oauth2Config.ClientSecret, "secret", "", "", "OIDC Client Secret")
	loginCmd.MarkFlagRequired("secret")
	loginCmd.Flags().StringVarP(&oauth2Config.RedirectURL, "redirect-url", "", "http://localhost:4242/", "OIDC Client Secret")
	loginCmd.Flags().StringArrayVarP(&oauth2Config.Scopes, "scopes", "", []string{oidc.ScopeOpenID, "profile", "email"}, "OIDC Scope")
	loginCmd.Flags().StringArrayVarP(&tokenClaimsParameter, "token-claim", "", nil, "Additional token claims")
	loginCmd.Flags().StringArrayVarP(&userinfoClaimsParamter, "userinfo-claim", "", nil, "Additional userinfo claims")
	loginCmd.Flags().BoolVarP(&showIDToken, "show-id-token", "", false, "Show the id token")
	loginCmd.Flags().BoolVarP(&insecureTLS, "insecure-tls", "", false, "Disable tls checks")
}
