package tun

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

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
		want     bool
	}{
		{"TUNSETIFF carrying IFF_VNET_HDR", true, false, true, true},
		{"TUNSETOFFLOAD", false, true, true, true},

		{"TUNSETIFF without gso", true, false, false, false},

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
