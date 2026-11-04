// Command constmap_vectors prints the serialized size and trailing FNV-1a
// checksum of maps built by github.com/lemire/constmap (Go), the reference
// implementation that the Java ConstMap, VerifiedConstMap and
// PairedVerifiedConstMap must match byte for byte. The checksum covers every
// byte before it, so equal checksums mean equal files.
//
// Run (from this directory):
//   go run . > ../../src/test/resources/constmap_vectors.txt
//
// For each size n and key set, the keys are fmt.Sprintf(prefix+"%d", i) for i
// in [0, n), and the value of key i is i * 0x9E3779B97F4A7C15 (mod 2^64).
// Output lines:
//   <kind> <prefix> <n> <size> <checksum hex>
// where kind is C (ConstMap), V (VerifiedConstMap) or P (PairedVerifiedConstMap).
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/lemire/constmap"
)

func emit(kind, prefix string, n int, w io.WriterTo) {
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		panic(err)
	}
	raw := b.Bytes()
	sum := binary.LittleEndian.Uint64(raw[len(raw)-8:])
	fmt.Printf("%s %s %d %d %016x\n", kind, prefix, n, len(raw), sum)
}

func main() {
	sizes := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 31, 32, 33, 100, 200, 255,
		256, 1000, 1023, 4096, 10000, 65537, 100000, 999999, 1000000, 1234567}
	for _, prefix := range []string{"key-", "clé-日本-"} {
		for _, n := range sizes {
			if prefix != "key-" && n > 100000 {
				continue
			}
			keys := make([]string, n)
			values := make([]uint64, n)
			for i := range keys {
				keys[i] = fmt.Sprintf(prefix+"%d", i)
				values[i] = uint64(i) * 0x9E3779B97F4A7C15
			}
			cm, err := constmap.New(keys, values)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			vm, err := constmap.NewVerified(keys, values)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			emit("C", prefix, n, cm)
			emit("V", prefix, n, vm)
			if n > 0 {
				emit("P", prefix, n, vm.Paired())
			}
		}
	}
}
