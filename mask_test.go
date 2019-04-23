// Copyright 2016 The Gorilla WebSocket Authors. All rights reserved.  Use of
// this source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// !appengine

package websocket

import (
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"
)

func maskBytesByByte(key [4]byte, pos int, b []byte) int {
	for i := range b {
		b[i] ^= key[pos&3]
		pos++
	}
	return pos & 3
}

func notzero(b []byte) int {
	for i := range b {
		if b[i] != 0 {
			return i
		}
	}
	return -1
}

func TestMaskBytes(t *testing.T) {
	key := [4]byte{1, 2, 3, 4}
	for size := 1; size <= 1024; size++ {
		for align := 0; align < wordSize; align++ {
			for pos := 0; pos < 4; pos++ {
				b := make([]byte, size+align)[align:]
				maskBytes(key, pos, b)
				maskBytesByByte(key, pos, b)
				if i := notzero(b); i >= 0 {
					t.Errorf("size:%d, align:%d, pos:%d, offset:%d", size, align, pos, i)
				}
			}
		}
	}
}

// xor applies the WebSocket masking algorithm to p
// with the given key where the first 3 bits of pos
// are the starting position in the key.
// See https://tools.ietf.org/html/rfc6455#section-5.3
//
// The returned value is the position of the next byte
// to be used for masking in the key. This is so that
// unmasking can be performed without the entire frame.
func nhooyr(key [4]byte, keyPos int, b []byte) int {
	// If the payload is greater than 16 bytes, then it's worth
	// masking 8 bytes at a time.
	// Optimization from https://github.com/golang/go/issues/31586#issuecomment-485530859
	if len(b) > 16 {
		// We first create a key that is 8 bytes long
		// and is aligned on the keyPos correctly.
		var alignedKey [8]byte
		for i := range alignedKey {
			alignedKey[i] = key[(i+keyPos)&3]
		}
		k := binary.LittleEndian.Uint64(alignedKey[:])

		// Then we xor until b is less than 8 bytes.
		for len(b) >= 8 {
			v := binary.LittleEndian.Uint64(b)
			binary.LittleEndian.PutUint64(b, v^k)
			b = b[8:]
		}
	}

	// xor remaining bytes.
	for i := range b {
		b[i] ^= key[keyPos&3]
		keyPos++
	}
	return keyPos & 3
}

// remain maps position in masking key [0,4) to number
// of bytes that need to be processed manually inside Cipher().
var remain = [4]int{0, 3, 2, 1}

func gobwas(mask [4]byte, offset int, payload []byte) int {
	n := len(payload)
	if n < 8 {
		for i := 0; i < n; i++ {
			payload[i] ^= mask[(offset+i)%4]
		}
		return 0
	}

	// Calculate position in mask due to previously processed bytes number.
	mpos := offset % 4
	// Count number of bytes will processed one by one from the beginning of payload.
	ln := remain[mpos]
	// Count number of bytes will processed one by one from the end of payload.
	// This is done to process payload by 8 bytes in each iteration of main loop.
	rn := (n - ln) % 8

	for i := 0; i < ln; i++ {
		payload[i] ^= mask[(mpos+i)%4]
	}
	for i := n - rn; i < n; i++ {
		payload[i] ^= mask[(mpos+i)%4]
	}

	// We should cast mask to uint32 with unsafe instead of encoding.BigEndian
	// to avoid care of os dependent byte order. That is, on any endianess mask
	// and payload will be presented with the same order. In other words, we
	// could not use encoding.BigEndian on xoring payload as uint64.
	m := *(*uint32)(unsafe.Pointer(&mask))
	m2 := uint64(m)<<32 | uint64(m)

	// Get pointer to payload at ln index to
	// skip manual processed bytes above.
	p := uintptr(unsafe.Pointer(&payload[ln]))
	// Also skip right part as the division by 8 remainder.
	// Divide it by 8 to get number of uint64 parts remaining to process.
	n = (n - rn) >> 3
	// Process the rest of bytes as uint64.
	for i := 0; i < n; i, p = i+1, p+8 {
		v := (*uint64)(unsafe.Pointer(p))
		*v = *v ^ m2
	}

	return 0
}

func BenchmarkMaskBytes(b *testing.B) {
	for _, size := range []int{2, 4, 16, 32, 512, 4096} {
		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			for _, align := range []int{wordSize / 2} {
				b.Run(fmt.Sprintf("align-%d", align), func(b *testing.B) {
					for _, fn := range []struct {
						name string
						fn   func(key [4]byte, pos int, b []byte) int
					}{
						{"byte", maskBytesByByte},
						{"gorilla", maskBytes},
						{"gobwas", gobwas},
						{"nhooyr", nhooyr},
						{"crypto/cipher", func(key [4]byte, pos int, b []byte) int {
							bigkey := make([]byte, 16)
							for i := range bigkey {
								bigkey[i] = key[i&3]
							}
							for len(b) > 0 {
								n := xorBytes(b, b, bigkey)
								b = b[n:]
							}
							return 0
						}},
					} {
						b.Run(fn.name, func(b *testing.B) {
							key := newMaskKey()
							data := make([]byte, size+align)[align:]
							for i := 0; i < b.N; i++ {
								fn.fn(key, 0, data)
							}
							b.SetBytes(int64(len(data)))
						})
					}
				})
			}
		})
	}
}
