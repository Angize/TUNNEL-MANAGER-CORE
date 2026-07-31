//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// wireRotateSignals installs the live "rotate now" / "probe now" controls the node drives with
// `systemctl kill`. It lives in its own !windows file because SIGUSR1/SIGUSR2 do not exist on
// Windows, which kept `GOOS=windows go build ./...` — the cheapest full-tree type check on the box
// this repo is developed from — from ever completing. Nothing on the fleet changes: every node runs
// linux, and this is the same code that was inline in main.
func wireRotateSignals(b any) {
	// SIGUSR1 rotates the edge IP, SIGUSR2 rotates the SNI — one dimension, no rebuild,
	// the TUN stays up while the carrier re-dials on the new edge.
	if r, ok := b.(interface {
		RotateIP()
		RotateSNI()
		ProbeAllNow()
	}); ok {
		rsig := make(chan os.Signal, 3)
		signal.Notify(rsig, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)
		go func() {
			for s := range rsig {
				switch s {
				case syscall.SIGUSR1:
					log.Print("tnl-core: rotate-now (edge IP)")
					r.RotateIP()
				case syscall.SIGUSR2:
					log.Print("tnl-core: rotate-now (SNI)")
					r.RotateSNI()
				case syscall.SIGHUP:
					log.Print("tnl-core: probe-now (retest all suspect/dead edges)")
					r.ProbeAllNow()
				}
			}
		}()
	} else if r, ok := b.(interface{ ProbeAllNow() }); ok {
		// Direct-transport peer/source pool (udp/tcp/raw/flux): SIGHUP retests every suspect/dead
		// endpoint immediately (the "probe now" control). These carriers have no ws edge dimensions to
		// rotate, so only SIGHUP is wired; the else-if avoids double-registering it for the ws path.
		rsig := make(chan os.Signal, 1)
		signal.Notify(rsig, syscall.SIGHUP)
		go func() {
			for range rsig {
				log.Print("tnl-core: probe-now (retest all suspect/dead peer/source endpoints)")
				r.ProbeAllNow()
			}
		}()
	}
}
