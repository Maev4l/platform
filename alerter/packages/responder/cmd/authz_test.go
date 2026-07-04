package main

import "testing"

func TestParseOperatorsAndAllow(t *testing.T) {
	allow := parseOperators(" U1 , U2 ,, U3 ") // tolerate spaces + empty entries
	if len(allow) != 3 {
		t.Fatalf("expected 3 operators, got %d", len(allow))
	}
	if !isAllowed(allow, "U2") {
		t.Fatal("U2 should be allowed")
	}
	if isAllowed(allow, "U9") {
		t.Fatal("U9 should NOT be allowed")
	}
}

func TestIsAllowed_EmptyListDeniesAll(t *testing.T) {
	if isAllowed(parseOperators(""), "U1") {
		t.Fatal("empty allow-list must deny everyone")
	}
}
