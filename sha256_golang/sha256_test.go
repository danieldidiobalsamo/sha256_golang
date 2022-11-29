package sha256_golang

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func getShortMessage() string {
	return "hi"
}

func getLongMessage() string {
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func getShortPreProcessed() []uint32 {
	rawMsg := getShortMessage()
	return PreProcess([]rune(rawMsg))
}

func getLongPreProcessed() []uint32 {
	rawMsg := getLongMessage()
	return PreProcess([]rune(rawMsg))
}

func getFirstBlockShort() []uint32 {
	msg := getShortPreProcessed()
	block, _ := ParseBlock(msg, 0)

	return block
}

func getFirstBlockLong() []uint32 {
	msg := getLongPreProcessed()
	block, _ := ParseBlock(msg, 0)

	return block
}

func TestPreProcessShort(t *testing.T) {

	rawMsg := getShortMessage()
	msg := PreProcess([]rune(rawMsg))

	pre_processed_bytes := []uint32{104, 105, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 16}

	assert.Equal(t, pre_processed_bytes, msg)
}

func TestPreProcessLong(t *testing.T) {

	rawMsg := getLongMessage()
	msg := PreProcess([]rune(rawMsg))

	pre_processed_bytes := []uint32{97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
		97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
		97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
		97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
		97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 128, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 88}

	assert.Equal(t, pre_processed_bytes, msg)
}

func TestParseBlockValid(t *testing.T) {

	msg := getShortPreProcessed()

	block, _ := ParseBlock(msg, 0)

	valid_block := []uint32{104, 105, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 16}

	assert.Equal(t, valid_block, block)
}

func TestParseBlockInvalid(t *testing.T) {

	msg := getShortPreProcessed()

	block, err := ParseBlock(msg, 65)

	assert.Equal(t, []uint32([]uint32(nil)), block)
	assert.EqualError(t, err, "index is greater than the number of 512-bits blocks")
}

func TestHashInit(t *testing.T) {
	h_0, k := InitHash()

	h0Good := []uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
		0x5be0cd19}

	kGood := []uint32{
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

	assert.Equal(t, h_0, h0Good)
	assert.Equal(t, k, kGood)
}

func TestMessageScheduleShort(t *testing.T) {
	block := getFirstBlockShort()
	schedule := MessageSchedule(block)

	goodSchedule := []uint32{
		0x68698000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10,
		0x68698000, 0xa0000, 0xf01a2359, 0x40000284, 0x55fbc086, 0x102a800, 0x98469ec2,
		0x6969c00b, 0x9ca90e8c, 0xc838a742, 0xe6b0fa06, 0x9d76f3b8, 0x637cabb0, 0x3fd29f6b,
		0x4a24a308, 0x26de146a, 0x769b20c2, 0xd4a1e662, 0x8216fabc, 0x6979e1e0, 0xe21a04f8,
		0x4986abe7, 0x6dfdd0d6, 0xa9b1620c, 0x78fd50cb, 0x175816cc, 0x3107dce8, 0xcf90ccf0,
		0x3947f012, 0x5eb8d9f8, 0x4f68069d, 0x59bebff1, 0x3827d60e, 0x65a47db8, 0x18f6702f,
		0xc0ed757b, 0xa4413c33, 0x8263307e, 0xd659ac97, 0xadc5d052, 0x62050d31, 0xa3cff18e,
		0xe46c7a47, 0x5a0f7f38, 0x3b11b357, 0xb854af2c, 0x33769263, 0x6d18e691,
	}

	assert.Equal(t, schedule, goodSchedule)
}

func TestMessageScheduleLong(t *testing.T) {
	block := getFirstBlockLong()
	schedule := MessageSchedule(block)

	goodSchedule := []uint32{
		0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
		0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
		0x61616161, 0x61616161, 0xf5fe3e3c, 0xf5fe3e3c, 0x325e1547, 0x325e1547, 0x21816259,
		0x21816259, 0xf6e94e20, 0x8b862afb, 0x7d00364d, 0xfa768297, 0x48667e8b, 0xaac11a45,
		0xa204f10, 0x9d4236b5, 0xb206cf59, 0x24e7cbf6, 0x97bb3687, 0x68705df9, 0xe854b988,
		0x50bd5067, 0x79787c0b, 0xe26c65b1, 0xba44d38d, 0x7a6111c9, 0x692a536e, 0xdcd178c,
		0xd5814de2, 0x8002d65e, 0x7144aacf, 0xa03e53ea, 0x6b2a892, 0x422c2043, 0x8f83ee50,
		0xf4e2f28d, 0x83c84b33, 0xf00b98ae, 0xad7b406a, 0xe17d306c, 0x9e4f1014, 0x8d153877,
		0x247dd0d2, 0x590f736c, 0x309f2fbc, 0x3fc5bb9f, 0x1aa4b3a7, 0x38409f61, 0xea3ab4f6,
		0xe77f61a,
	}

	assert.Equal(t, schedule, goodSchedule)
}
