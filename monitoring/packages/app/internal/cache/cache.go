package cache

import (
	"sync"
	"time"
)

type entry struct {
	val []byte
	exp time.Time
}

type Cache struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]entry
}

func New(ttl time.Duration) *Cache { return &Cache{ttl: ttl, m: map[string]entry{}} }

func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	e, ok := c.m[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.val, true
}

func (c *Cache) Set(key string, val []byte) {
	c.mu.Lock()
	c.m[key] = entry{val: val, exp: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}
