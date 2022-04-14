package sac

import (
	"fmt"
)

// Config contains configuration for sac authentication.
//
// ⚠️ WARNING: Change to the field name must preserve the INI key name for backward compatibility.
type Config struct {
	PublicUrl    string
	PrivateUrl   string
	ClientId     string
	ClientSecret string
	CallbackUrl  string
}

// CreateLoginUrl 用户认证地址
func (c *Config) CreateLoginUrl() string {
	return fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s", c.PublicUrl, c.ClientId, c.CallbackUrl)
}
