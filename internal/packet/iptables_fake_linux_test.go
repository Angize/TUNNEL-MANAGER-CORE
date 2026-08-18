//go:build linux

package packet

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

func verbOf(args []string) (string, int) {
	for i, a := range args {
		switch a {
		case "-I", "-A", "-D", "-C":
			return a, i
		}
	}
	return "", -1
}

type fakeIptables struct {
	mu        sync.Mutex
	rules     []string
	failDel   bool
	noComment bool
}

func (f *fakeIptables) install() func() {
	prev := iptablesRun
	iptablesRun = f.run
	return func() { iptablesRun = prev }
}

func (f *fakeIptables) run(args []string) ([]byte, error) {
	verb, i := verbOf(args)
	if verb == "" || i+1 >= len(args) {
		return nil, fmt.Errorf("fake iptables: no verb in %v", args)
	}

	spec := append([]string{}, args[:i]...)
	spec = append(spec, args[i+1])
	spec = append(spec, args[i+2:]...)
	key := strings.Join(spec, " ")

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noComment && strings.Contains(key, "-m comment") {
		return []byte("iptables: No chain/target/match by that name"), errors.New("exit status 2")
	}
	switch verb {
	case "-I":
		f.rules = append([]string{key}, f.rules...)
	case "-A":
		f.rules = append(f.rules, key)
	case "-C":
		if f.countLocked(key) == 0 {
			return []byte("iptables: Bad rule (does a matching rule exist in that chain?)"), errors.New("exit status 1")
		}
	case "-D":
		if f.failDel {
			return []byte("Another app is currently holding the xtables lock"), errors.New("exit status 4")
		}
		for k, r := range f.rules {
			if r == key {
				f.rules = append(f.rules[:k:k], f.rules[k+1:]...)
				return nil, nil
			}
		}
		return []byte("iptables: Bad rule (does a matching rule exist in that chain?)"), errors.New("exit status 1")
	}
	return nil, nil
}

func (f *fakeIptables) countLocked(key string) int {
	n := 0
	for _, r := range f.rules {
		if r == key {
			n++
		}
	}
	return n
}

func (f *fakeIptables) setFailDel(v bool) {
	f.mu.Lock()
	f.failDel = v
	f.mu.Unlock()
}

func (f *fakeIptables) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rules)
}

func (f *fakeIptables) dups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen, n := map[string]bool{}, 0
	for _, r := range f.rules {
		if seen[r] {
			n++
		}
		seen[r] = true
	}
	return n
}

func (f *fakeIptables) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.rules...)
}
