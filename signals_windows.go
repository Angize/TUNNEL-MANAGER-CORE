//go:build windows

package main

// wireRotateSignals is a no-op on Windows: the rotate/probe controls are delivered as SIGUSR1,
// SIGUSR2 and SIGHUP, none of which exist there. The core only ever RUNS on linux; this file exists
// so the tree type-checks for GOOS=windows, which is the cheapest whole-tree check available on the
// box this repo is developed from.
func wireRotateSignals(b any) {}
