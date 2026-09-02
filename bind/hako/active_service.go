package hako

import "sync"

var activeCoreService struct {
	sync.RWMutex
	service *BoxService
}

func publishCoreService(service *BoxService) {
	activeCoreService.Lock()
	activeCoreService.service = service
	activeCoreService.Unlock()
}

func unpublishCoreService(service *BoxService) {
	activeCoreService.Lock()
	if activeCoreService.service == service {
		activeCoreService.service = nil
	}
	activeCoreService.Unlock()
}

func currentCoreService() *BoxService {
	activeCoreService.RLock()
	defer activeCoreService.RUnlock()
	return activeCoreService.service
}
