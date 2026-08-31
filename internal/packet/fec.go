package packet

import "errors"

var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gmul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gdiv(a, b byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])-int(gfLog[b])+255]
}

type fecCodec struct {
	n, k   int
	parity [][]byte
}

func newFECCodec(n, k int) (*fecCodec, error) {
	if n < 1 || k < 1 || n+k > 256 {
		return nil, errors.New("fec: bad (n,k)")
	}

	p := make([][]byte, k)
	for i := 0; i < k; i++ {
		p[i] = make([]byte, n)
		xi := byte(n + i)
		for j := 0; j < n; j++ {
			p[i][j] = gdiv(1, xi^byte(j))
		}
	}
	return &fecCodec{n: n, k: k, parity: p}, nil
}

func (c *fecCodec) Encode(data [][]byte) ([][]byte, error) {
	if len(data) != c.n {
		return nil, errors.New("fec: need exactly n data shards")
	}
	sz := len(data[0])
	for _, d := range data {
		if len(d) != sz {
			return nil, errors.New("fec: data shards must be equal length")
		}
	}
	out := make([][]byte, c.k)
	for i := 0; i < c.k; i++ {
		row := make([]byte, sz)
		for j := 0; j < c.n; j++ {
			coef := c.parity[i][j]
			if coef == 0 {
				continue
			}
			gfMulAddRow(row, data[j], coef)
		}
		out[i] = row
	}
	return out, nil
}

func (c *fecCodec) Reconstruct(shards [][]byte) ([][]byte, error) {
	if len(shards) != c.n+c.k {
		return nil, errors.New("fec: shards must be length n+k")
	}

	haveAllData := true
	sz := 0
	for i := 0; i < c.n+c.k; i++ {
		if shards[i] != nil {
			if sz != 0 && len(shards[i]) != sz {
				return nil, errors.New("fec: mixed shard lengths")
			}
			sz = len(shards[i])
		}
		if i < c.n && shards[i] == nil {
			haveAllData = false
		}
	}
	if haveAllData {
		return shards[:c.n], nil
	}

	rows := make([][]byte, 0, c.n)
	vals := make([][]byte, 0, c.n)
	for i := 0; i < c.n+c.k && len(rows) < c.n; i++ {
		if shards[i] == nil {
			continue
		}
		row := make([]byte, c.n)
		if i < c.n {
			row[i] = 1
		} else {
			copy(row, c.parity[i-c.n])
		}
		rows = append(rows, row)
		vals = append(vals, shards[i])
	}
	if len(rows) < c.n {
		return nil, errors.New("fec: not enough shards to reconstruct")
	}
	inv, err := gfInvert(rows)
	if err != nil {
		return nil, err
	}

	data := make([][]byte, c.n)
	for r := 0; r < c.n; r++ {
		if shards[r] != nil {
			data[r] = shards[r]
			continue
		}
		out := make([]byte, sz)
		for cc := 0; cc < c.n; cc++ {
			coef := inv[r][cc]
			if coef == 0 {
				continue
			}
			gfMulAddRow(out, vals[cc], coef)
		}
		data[r] = out
	}
	return data, nil
}

func gfMulAddRow(dst, src []byte, coef byte) {
	for i := range dst {
		dst[i] ^= gmul(coef, src[i])
	}
}

func gfInvert(m [][]byte) ([][]byte, error) {
	n := len(m)
	a := make([][]byte, n)
	for i := range m {
		a[i] = make([]byte, 2*n)
		copy(a[i], m[i])
		a[i][n+i] = 1
	}
	for col := 0; col < n; col++ {
		if a[col][col] == 0 {
			sw := -1
			for r := col + 1; r < n; r++ {
				if a[r][col] != 0 {
					sw = r
					break
				}
			}
			if sw < 0 {
				return nil, errors.New("fec: singular matrix")
			}
			a[col], a[sw] = a[sw], a[col]
		}

		pv := a[col][col]
		for x := 0; x < 2*n; x++ {
			a[col][x] = gdiv(a[col][x], pv)
		}

		for r := 0; r < n; r++ {
			if r == col || a[r][col] == 0 {
				continue
			}
			gfMulAddRow(a[r], a[col], a[r][col])
		}
	}
	inv := make([][]byte, n)
	for i := 0; i < n; i++ {
		inv[i] = a[i][n:]
	}
	return inv, nil
}
