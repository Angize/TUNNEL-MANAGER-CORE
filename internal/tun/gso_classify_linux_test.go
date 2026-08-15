package tun

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// The other half of the gso fallback lives here: main's retry is only correct if
// Open marks the gso-specific ioctls AND NOTHING ELSE. A kernel that supports gso
// perfectly well (every box we have) can never reach those branches, so the two
// ioctls are driven through the setIff/setOffload seams instead.
func TestOnlyTheGSOSpecificIoctlsAreMarkedGSOUnsupported(t *testing.T) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no usable /dev/net/tun here: %v", err)
	}
	f.Close()

	origIff, origOffload := setIff, setOffload
	t.Cleanup(func() { setIff, setOffload = origIff, origOffload })

	cases := []struct {
		name     string
		failIff  bool
		failOffl bool
		gso      bool
		want     bool // must errors.Is(err, ErrGSOUnsupported)
	}{
		{"TUNSETIFF carrying IFF_VNET_HDR", true, false, true, true},
		{"TUNSETOFFLOAD", false, true, true, true},
		// The same ioctl with no gso asked for: there is nothing to fall back to, so
		// marking it would send main into a second open that must fail the same way.
		{"TUNSETIFF without gso", true, false, false, false},
		// Everything after the two ioctls — the `ip` calls — has to stay a hard error
		// even when gso is on, or a bad address would silently drop gso instead of
		// failing. Here both ioctls "succeed" and no device exists, so `ip` fails.
		{"the ip commands after the ioctls", false, false, true, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setIff = func(*os.File, *[ifReqSize]byte) syscall.Errno {
				if c.failIff {
					return syscall.EINVAL
				}
				return 0
			}
			setOffload = func(*os.File, uintptr) syscall.Errno {
				if c.failOffl {
					return syscall.EINVAL
				}
				return 0
			}

			_, err := OpenN("tnlgsoclassify", 1380, "10.201.0.1/24", c.gso, 1)
			if err == nil {
				t.Fatal("want an error")
			}
			if got := errors.Is(err, ErrGSOUnsupported); got != c.want {
				t.Fatalf("errors.Is(err, ErrGSOUnsupported) = %v, want %v (err = %v)", got, c.want, err)
			}
		})
	}
}
