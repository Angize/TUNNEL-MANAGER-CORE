package packet

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

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
	go func() {
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
	go func() {
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
