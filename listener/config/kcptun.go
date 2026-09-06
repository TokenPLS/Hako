package config

import "github.com/TokenPLS/Hako/transport/kcptun"

type KcpTun struct {
	Enable        bool `json:"enable"`
	kcptun.Config `json:",inline"`
}
