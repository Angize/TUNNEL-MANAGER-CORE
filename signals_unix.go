//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func wireRotateSignals(b any) {

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
