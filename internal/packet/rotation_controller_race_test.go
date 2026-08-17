package packet

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestRotationControllerIsRaceFree hammers the controller from the two goroutines that really touch it —
// the carrier's client loop (success/proactive) and the pin-poll loop (fail) — because nothing else in
// the package makes them collide reliably. It found nothing for a long time only because the collision
// window is narrow; under -race with both loops spinning it is immediate.
//
// The counters are the odometer: a lost update means a lap counted twice or not at all, which convicts
// the SOURCE early or late. Not a crash — a wrong verdict, which is worse because nothing reports it.
func TestRotationControllerIsRaceFree(t *testing.T) {
	dir := t.TempDir()
	dst := NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "d.json"))
	src := NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json"))
	rc := newRotationController(dst, src)
	rc.rotate = time.Millisecond
	rc.rotateAt = time.Now()

	rot := func(bool) {}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the client loop
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				rc.success()
				rc.proactive(rot, rot, time.Now())
			}
		}
	}()
	go func() { // the pin-poll loop
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				rc.fail(rot, rot)
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
