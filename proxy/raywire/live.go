package raywire

import "sync"

// maxLivePerClient counts authenticated TCP connections, including connections
// carrying UDP or mux. It is independent of the pre-auth and replay quotas.
const maxLivePerClient = 32

// liveSessions belongs to one inbound. Its zero value is ready for use. Only
// authenticated public keys enter the map; labels and source IPs are not identities.
type liveSessions struct {
	mu        sync.Mutex
	perClient map[string]int
}

func (s *liveSessions) TryAcquire(publicKey []byte) (release func(), ok bool) {
	key := string(publicKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perClient[key] >= maxLivePerClient {
		return nil, false
	}
	if s.perClient == nil {
		s.perClient = make(map[string]int)
	}
	s.perClient[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.perClient[key]--
			if s.perClient[key] == 0 {
				delete(s.perClient, key)
			}
		})
	}, true
}
