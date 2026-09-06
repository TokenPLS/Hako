package profile

import (
	"github.com/TokenPLS/Hako/common/atomic"
)

// StoreSelected is a global switch for storing selected proxy to cache
var StoreSelected = atomic.NewBool(true)
