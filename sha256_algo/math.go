package sha256_algo

import "math/bits"

func sigma_0(x uint32) uint32 {
	return bits.RotateLeft32(x, -7) ^ bits.RotateLeft32(x, -18) ^ (x >> 3)
}

func sigma_1(x uint32) uint32 {
	return bits.RotateLeft32(x, -17) ^ bits.RotateLeft32(x, -19) ^ (x >> 10)
}

func bigSigma_0(x uint32) uint32 {
	return bits.RotateLeft32(x, -2) ^ bits.RotateLeft32(x, -13) ^ bits.RotateLeft32(x, -22)
}

func bigSigma_1(x uint32) uint32 {
	return bits.RotateLeft32(x, -6) ^ bits.RotateLeft32(x, -11) ^ bits.RotateLeft32(x, -25)
}

func choice(e, f, g uint32) uint32 {
	return (e & f) ^ (^e & g)
}

func majority(a, b, c uint32) uint32 {
	return (a & b) ^ (a & c) ^ (b & c)
}
