package packet

// What the FEC codec costs per byte. Measured on DE02 (go1.25.12, EPYC-Rome, 2 cores),
// -benchtime 2s x3, so nobody re-derives it.
//
//                        before      after the 256x256 table
//   Encode 10/3       146-160     288-322 MB/s
//   Encode 20/4       115-125     236-271 MB/s
//   Reconstruct 10/3   98-105     224-253 MB/s
//   gfMulAddRow      802-989     1159-1171 MB/s
//
// The old inner loop called gmul() per byte: two branches, gfLog twice, an add and gfExp. The table
// makes it one indexed load from a 256-byte row that stays in L1, which is where the 2x comes from.
//
// End to end in a netns lab (raw:udp, 70ms RTT, 1% loss each way, one cpu pinned per end, iperf3 -P 8):
//
//   no FEC                     691 Mbit
//   FEC 10/3, before           257
//   FEC 10/3, table only       320   (+24%)
//   FEC 10/3, table + block    397   (+54%)
//
// The second half of that is the block leaving in ONE emit so the carrier can sendmmsg it, instead of
// thirteen separate sendto calls. The remaining gap to 691 is mostly the parity itself: a 10/3 block
// puts 13 packets on the wire for every 10 the tunnel carries.

import "testing"

func fecBenchShards(n, sz int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = make([]byte, sz)
		for j := range out[i] {
			out[i][j] = byte(i*31 + j)
		}
	}
	return out
}

func BenchmarkFECEncode10x3(b *testing.B) {
	c, err := newFECCodec(10, 3)
	if err != nil {
		b.Fatal(err)
	}
	d := fecBenchShards(10, 1400)
	b.SetBytes(10 * 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Encode(d); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFECEncode20x4(b *testing.B) {
	c, err := newFECCodec(20, 4)
	if err != nil {
		b.Fatal(err)
	}
	d := fecBenchShards(20, 1400)
	b.SetBytes(20 * 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Encode(d); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFECReconstruct10x3(b *testing.B) {
	c, err := newFECCodec(10, 3)
	if err != nil {
		b.Fatal(err)
	}
	d := fecBenchShards(10, 1400)
	p, err := c.Encode(d)
	if err != nil {
		b.Fatal(err)
	}
	all := append(append([][]byte{}, d...), p...)
	b.SetBytes(10 * 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sh := append([][]byte{}, all...)
		sh[0], sh[3], sh[7] = nil, nil, nil
		if _, err := c.Reconstruct(sh); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGfMulAddRow(b *testing.B) {
	dst := make([]byte, 1400)
	src := make([]byte, 1400)
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gfMulAddRow(dst, src, 0x53)
	}
}
