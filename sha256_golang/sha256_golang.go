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
