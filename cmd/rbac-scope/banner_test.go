package main

import "strings"
import "testing"

func TestGetBanner(t *testing.T) {
	b := GetBanner()
	if b == "" {
		t.Fatal("empty banner")
	}
	if !strings.Contains(b, "██") {
		t.Error("banner content unexpected")
	}
}
