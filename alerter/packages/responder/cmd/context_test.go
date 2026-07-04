package main

import "testing"

func TestDecodeButtonValue(t *testing.T) {
	c, err := decodeButtonValue(`{"s":"idp","c":"req-1","p":"tok"}`)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c.Source != "idp" || c.CallbackID != "req-1" || c.Payload != "tok" {
		t.Fatalf("bad decode: %+v", c)
	}
}

func TestDecodeButtonValue_Invalid(t *testing.T) {
	if _, err := decodeButtonValue("not-json"); err == nil {
		t.Fatal("expected error for invalid value")
	}
}
