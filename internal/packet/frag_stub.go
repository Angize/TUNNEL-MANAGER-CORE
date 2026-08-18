//go:build !linux

package packet

func (f *fragConn) writeDisorder(p []byte, at int) (int, error) {
	return f.writeSplit(p, at)
}

func (f *fragConn) writeFake(p []byte, at int) (int, error) {
	return f.writeSplit(p, at)
}
