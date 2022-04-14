package sac

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"gogs.io/gogs/internal/auth"
	"gogs.io/gogs/internal/conf"
	"gogs.io/gogs/internal/httplib"
)

// Provider contains configuration of an sac authentication provider.
type Provider struct {
	config *Config
}

type SacUserResult struct {
	Authenticated      bool `json:authenticated`
	UserAuthentication struct {
		Principal struct {
			Said     int64  `json:said`
			Username string `json:username`
			Nickname string `json:nickname`
		}
	} `json:userAuthentication`
}

// NewProvider creates a new sac authentication provider.
func NewProvider(cfg *Config) auth.Provider {
	return &Provider{
		config: cfg,
	}
}

// Authenticate queries if login/password is valid against the sac server,
// and returns queried information when succeeded.
func (p *Provider) Authenticate(login, password string) (*auth.ExternalAccount, error) {
	// 取token
	httpauth := []byte(fmt.Sprintf("%s:%s", p.config.ClientId, p.config.ClientSecret))
	req := httplib.Post(p.config.PrivateUrl+"/oauth/token").SetTimeout(4*time.Second, 4*time.Second).
		Header("Authorization", "Basic "+base64.StdEncoding.EncodeToString(httpauth)).
		Param("grant_type", "authorization_code").
		Param("code", password).
		Param("redirect_uri", p.config.CallbackUrl).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: conf.Webhook.SkipTLSVerify})
	resp, err := req.Response()
	if err != nil {
		return nil, err
	}
	// 反序列化
	dec := json.NewDecoder(resp.Body)
	var r map[string]interface{}
	err = dec.Decode(&r)
	if err != nil {
		return nil, err
	}
	// 找token
	accessToken := r["access_token"]
	if accessToken == nil {
		return nil, auth.ErrBadCredentials{}
	}
	// 查用户
	req = httplib.Get(p.config.PrivateUrl+"/api/userinfo").SetTimeout(4*time.Second, 4*time.Second).
		Header("Authorization", "Bearer "+accessToken.(string)).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: conf.Webhook.SkipTLSVerify})
	resp, err = req.Response()
	if err != nil {
		return nil, err
	}
	// 反序列化
	user := &SacUserResult{}
	dec = json.NewDecoder(resp.Body)
	err = dec.Decode(user)
	if err != nil {
		return nil, err
	}
	// 看用户
	if !user.Authenticated {
		return nil, auth.ErrBadCredentials{}
	}
	return &auth.ExternalAccount{
		Login:    user.UserAuthentication.Principal.Username,
		Name:     user.UserAuthentication.Principal.Username,
		FullName: user.UserAuthentication.Principal.Nickname,
		Email:    user.UserAuthentication.Principal.Username + "@scraft.top",
	}, nil
}

func (p *Provider) Config() interface{} {
	return p.config
}

func (p *Provider) HasTLS() bool {
	return false
}

func (p *Provider) UseTLS() bool {
	return false
}

func (p *Provider) SkipTLSVerify() bool {
	return false
}
