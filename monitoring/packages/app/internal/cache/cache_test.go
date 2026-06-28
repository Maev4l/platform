package cache

import (
	"testing"
	"time"
)

func TestSetGet(t *testing.T) {
	c := New(time.Minute)
	c.Set("k", []byte("v"))
	if got, ok := c.Get("k"); !ok || string(got) != "v" {
		t.Fatalf("want v, got %q ok=%v", got, ok)
	}
}

func TestExpiry(t *testing.T) {
	c := New(10 * time.Millisecond)
	c.Set("k", []byte("v"))
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected expiry")
	}
}
