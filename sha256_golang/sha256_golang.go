package sha256_golang

import "errors"

func PreProcess(msg []rune) []rune {
	proc := msg
	originalLengthBits := uint64(len(msg) * 8)

	// append 1 (1000 0000)
	proc = append(proc, 128)

	// pad with zeros such as msg length is a multiple of 512
	nbZeroBits := (512 + 448 - ((originalLengthBits)%512 + 1)) % 512
	nbZeroBytes := nbZeroBits / 8

	var i uint64
	for i = 0; i < nbZeroBytes; i++ {
		proc = append(proc, 0)
	}

	// pad original length as 64 bits
	mask := uint64(0xFF00000000000000)

	for i := 0; i < 8; i++ {
		val64 := originalLengthBits & mask
		val := uint8(val64 >> (56 - (8 * i)))
		proc = append(proc, rune(val))
		mask >>= 8
	}

	return proc
}

func ParseBlock(msg []rune, index int) ([]rune, error) {
	nbBlocks := len(msg) / 64

	if index > nbBlocks {
		return nil, errors.New("index is greater than the number of 512-bits blocks")
	}

	start := ((512 * index) / 8)
	end := (start + (512 / 8))

	return msg[start:end], nil
}

func InitHash() ([]uint32, []uint32) {
	// first thirty-two bits of the fractional parts of the square roots of the first eight prime numbers
	// set by the SHA-256 specification
	h_0 := []uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
		0x5be0cd19}

	//first thirty-two bits of the fractional parts of the cube roots of the first sixty-four prime numbers
	// set by the SHA-256 specification
	k := []uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
		0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
		0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
		0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
		0xc67178f2,
	}

	return h_0, k
}
