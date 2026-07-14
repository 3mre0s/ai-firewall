package main

import "testing"

func TestLoopbackAddr(t *testing.T) {
	if got, want := loopbackAddr(8080), "127.0.0.1:8080"; got != want {
		t.Fatalf("loopbackAddr() = %q, want %q", got, want)
	}
}
