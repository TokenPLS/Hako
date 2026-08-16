package config

import "encoding/json"

type ResTLS struct {
	Enable       bool
	Dest         string
	Password     string
	RestlsScript string
	MinRecordLen int
	Proxy        string
}

func (r ResTLS) String() string {
	b, _ := json.Marshal(r)
	return string(b)
}
